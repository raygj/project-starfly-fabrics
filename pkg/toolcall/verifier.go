package toolcall

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// Sentinel errors for tool call verification. These are the same conceptual
// errors as pkg/mcp but live here so all adapters share a single error vocabulary.
var (
	ErrMissingToken        = errors.New("toolcall: missing authorization token")
	ErrInvalidToken        = errors.New("toolcall: invalid or expired token")
	ErrTokenRevoked        = errors.New("toolcall: token has been revoked")
	ErrToolNotRegistered   = errors.New("toolcall: tool not registered")
	ErrCapabilityDenied    = errors.New("toolcall: capability not granted")
	ErrBlastRadiusExceeded = errors.New("toolcall: blast radius exceeded")
	ErrAudienceMismatch    = errors.New("toolcall: token audience does not match tool resource URI")
	ErrPolicyDenied        = errors.New("toolcall: policy denied access")
	ErrProtocolDenied      = errors.New("toolcall: protocol not allowed for this tool")
	ErrExecOpMismatch      = errors.New("toolcall: operation not authorized for this tool")
	ErrExecPayloadMismatch = errors.New("toolcall: payload hash does not match request body")
	ErrExecPayloadMissing  = errors.New("toolcall: tool requires payload binding but token has no inp_hash")
	ErrExecTargetMismatch  = errors.New("toolcall: target resource not authorized for this tool")
	ErrExecBindingRequired = errors.New("toolcall: tool requires execution binding but token has none")
)

// VerifierConfig configures the DefaultVerifier.
type VerifierConfig struct {
	// JWKSResolver resolves public keys for JWT signature verification.
	// Required in production; may be nil in DevMode.
	JWKSResolver core.JWKSResolver
	// Registry is the universal tool registry for security constraint lookups.
	// When nil, audience/capability/execution checks are skipped.
	Registry *Registry
	// RevocationChecker checks whether a subject has been revoked.
	RevocationChecker core.RevocationIndex
	// Policy evaluates OPA authorization policy.
	Policy core.PolicyEngine
	// Auditor logs verification decisions.
	Auditor core.Auditor
	// UnitID is the Starfly unit identifier for audit events.
	UnitID string
	// DevMode skips JWT signature verification (development only).
	DevMode bool
}

// DefaultVerifier implements Verifier with the full five-phase WIMSE pipeline:
//
//  1. Identity  — JWT signature verification via JWKS resolver
//  2. Authorization — audience, capability, blast radius, OPA policy, protocol gate
//  3. Execution Binding — exec_act, inp_hash, target (ECT-aligned)
//  4. Revocation — O(1) revocation index lookup
//
// Phase 5 (ECT generation) is handled post-execution by the caller.
type DefaultVerifier struct {
	cfg VerifierConfig
}

// NewVerifier creates a DefaultVerifier with the given configuration.
func NewVerifier(cfg VerifierConfig) *DefaultVerifier {
	return &DefaultVerifier{cfg: cfg}
}

// Verify runs the verification pipeline for a ToolCallRequest.
func (v *DefaultVerifier) Verify(ctx context.Context, req *ToolCallRequest) (*VerifiedIdentity, error) {
	if req.Token == "" {
		return nil, ErrMissingToken
	}

	// ── Phase 1: Identity ────────────────────────────────────────────
	insecure, err := jwt.ParseInsecure([]byte(req.Token))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	issuer, _ := insecure.Issuer()
	if issuer == "" {
		return nil, fmt.Errorf("%w: missing issuer claim", ErrInvalidToken)
	}

	var verified jwt.Token
	if v.cfg.DevMode {
		verified = insecure
	} else {
		pubKey, err := v.cfg.JWKSResolver.ResolveKey(ctx, issuer, "")
		if err != nil {
			return nil, fmt.Errorf("%w: failed to resolve signing key: %v", ErrInvalidToken, err)
		}
		verified, err = jwt.Parse([]byte(req.Token),
			jwt.WithKey(inferAlg(pubKey), pubKey),
			jwt.WithValidate(true),
		)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
		}
	}

	identity, aud := extractIdentity(verified, req.Protocol)

	// ── Phase 2: Authorization ───────────────────────────────────────
	if req.ToolID != "" && v.cfg.Registry != nil {
		tool, ok := v.cfg.Registry.Get(req.ToolID)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrToolNotRegistered, req.ToolID)
		}

		// Protocol gate: tool must declare support for the caller's protocol.
		if !tool.SupportsProtocol(req.Protocol) {
			return nil, fmt.Errorf("%w: tool %q does not support protocol %q",
				ErrProtocolDenied, req.ToolID, req.Protocol)
		}

		resourceURI := tool.ResourceURI
		if resourceURI == "" {
			resourceURI = tool.ToolID
		}
		if aud != resourceURI {
			return nil, fmt.Errorf("%w: got %q, want %q", ErrAudienceMismatch, aud, resourceURI)
		}
		identity.ToolID = req.ToolID
		identity.Resource = resourceURI

		if err := checkCaps(identity.Capabilities, tool.RequiredCapabilities); err != nil {
			return nil, err
		}
		if tool.MaxBlastRadius != "" && identity.BlastRadius != "" {
			if !blastRadiusFits(identity.BlastRadius, tool.MaxBlastRadius) {
				return nil, fmt.Errorf("%w: token scope %q exceeds tool max %q",
					ErrBlastRadiusExceeded, identity.BlastRadius, tool.MaxBlastRadius)
			}
		}
	}

	// ── Phase 4: Revocation ──────────────────────────────────────────
	if v.cfg.RevocationChecker != nil {
		entry, err := v.cfg.RevocationChecker.IsRevoked(ctx, identity.Subject)
		if err != nil {
			slog.Warn("toolcall: revocation check error, failing open",
				"error", err, "subject", identity.Subject)
		}
		if entry != nil {
			return nil, fmt.Errorf("%w: %s", ErrTokenRevoked, entry.Reason)
		}
	}

	// OPA policy evaluation.
	if v.cfg.Policy != nil {
		decision, err := v.cfg.Policy.Evaluate(ctx, &core.PolicyInput{
			Action: "tool_call",
			Subject: &core.WorkloadIdentity{
				ID:          identity.Subject,
				TrustDomain: extractTrustDomain(identity.Subject),
				Attestation: &core.AttestationEvidence{
					Method:    core.AttestMethodMCP,
					Timestamp: time.Now(),
				},
			},
			Target: req.ToolID,
			Context: map[string]interface{}{
				"capabilities": identity.Capabilities,
				"blast_radius": identity.BlastRadius,
				"audience":     aud,
				"issuer":       identity.Issuer,
				"resource":     identity.Resource,
				"protocol":     string(req.Protocol),
			},
		})
		if err != nil {
			return nil, fmt.Errorf("toolcall: policy evaluation failed: %w", err)
		}
		if !decision.Allowed {
			return nil, fmt.Errorf("%w: %s", ErrPolicyDenied, decision.Reason)
		}
	}

	// ── Phase 3: Execution Binding ───────────────────────────────────
	if req.ToolID != "" && v.cfg.Registry != nil {
		if tool, ok := v.cfg.Registry.Get(req.ToolID); ok {
			if err := verifyExecBinding(identity, tool, req.RequestBody); err != nil {
				return nil, err
			}
		}
	}

	return identity, nil
}

// extractIdentity maps a verified JWT token to a VerifiedIdentity.
// The raw audience string is returned separately for the resource-URI comparison.
func extractIdentity(t jwt.Token, protocol Protocol) (*VerifiedIdentity, string) {
	sub, _ := t.Subject()
	iss, _ := t.Issuer()
	exp, _ := t.Expiration()

	identity := &VerifiedIdentity{
		Subject:   sub,
		Issuer:    iss,
		ExpiresAt: exp,
		Protocol:  protocol,
	}

	var aud string
	if auds, ok := t.Audience(); ok && len(auds) > 0 {
		aud = auds[0]
	}

	var capsRaw []interface{}
	if err := t.Get("caps", &capsRaw); err == nil {
		for _, c := range capsRaw {
			if s, ok := c.(string); ok {
				identity.Capabilities = append(identity.Capabilities, s)
			}
		}
	}

	var br string
	if err := t.Get("blast_radius", &br); err == nil {
		identity.BlastRadius = br
	}

	var obo string
	if err := t.Get("obo", &obo); err == nil {
		identity.Delegation = &Delegation{OnBehalfOf: obo}
	}
	var dd float64
	if err := t.Get("delegation_depth", &dd); err == nil {
		if identity.Delegation == nil {
			identity.Delegation = &Delegation{}
		}
		identity.Delegation.Depth = int(dd)
	}

	// Execution scope — ECT-aligned flat top-level claims.
	es := &core.ExecutionScope{}
	hasExec := false
	for claim, dst := range map[string]*string{
		"htm":      &es.Method,
		"htu":      &es.URI,
		"exec_act": &es.ExecAct,
		"inp_hash": &es.InputHash,
		"out_hash": &es.OutputHash,
		"target":   &es.Target,
		"wid":      &es.WorkflowID,
		"nonce":    &es.Nonce,
	} {
		var s string
		if err := t.Get(claim, &s); err == nil {
			*dst = s
			hasExec = true
		}
	}
	// Backward compat: payload_hash → inp_hash.
	if es.InputHash == "" {
		var ph string
		if err := t.Get("payload_hash", &ph); err == nil {
			es.InputHash = ph
			es.PayloadHash = ph
			hasExec = true
		}
	}
	if hasExec {
		identity.Execution = es
	}

	return identity, aud
}

func verifyExecBinding(identity *VerifiedIdentity, tool *ToolEntry, body []byte) error {
	if tool.RequiresExecution && identity.Execution == nil {
		return fmt.Errorf("%w: tool %q requires execution-scoped token",
			ErrExecBindingRequired, tool.ToolID)
	}
	if identity.Execution == nil {
		return nil
	}
	ex := identity.Execution

	if len(tool.AllowedOperations) > 0 && ex.ExecAct != "" {
		if !strIn(ex.ExecAct, tool.AllowedOperations) {
			return fmt.Errorf("%w: exec_act %q not in allowed set %v",
				ErrExecOpMismatch, ex.ExecAct, tool.AllowedOperations)
		}
	}
	if ex.InputHash != "" && body != nil {
		if computed := inputHash(body); computed != ex.InputHash {
			return fmt.Errorf("%w: computed %q, token declares %q",
				ErrExecPayloadMismatch, computed, ex.InputHash)
		}
	}
	if tool.RequiresExecution && ex.InputHash == "" {
		return ErrExecPayloadMissing
	}
	if len(tool.AllowedTargets) > 0 && ex.Target != "" {
		if !strIn(ex.Target, tool.AllowedTargets) {
			return fmt.Errorf("%w: target %q not in allowed set %v",
				ErrExecTargetMismatch, ex.Target, tool.AllowedTargets)
		}
	}
	return nil
}

func inputHash(data []byte) string {
	h := sha256.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func checkCaps(tokenCaps, required []string) error {
	if len(required) == 0 {
		return nil
	}
	have := make(map[string]bool, len(tokenCaps))
	for _, c := range tokenCaps {
		have[c] = true
	}
	var missing []string
	for _, req := range required {
		if !have[req] {
			missing = append(missing, req)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: missing %v", ErrCapabilityDenied, missing)
	}
	return nil
}

func blastRadiusFits(tokenBR, maxBR string) bool {
	if maxBR == "*" {
		return true
	}
	tp := strings.SplitN(tokenBR, ":", 2)
	mp := strings.SplitN(maxBR, ":", 2)
	if len(tp) < 2 || len(mp) < 2 {
		return tokenBR == maxBR
	}
	if tp[0] != mp[0] {
		return false
	}
	if mp[1] == "*" {
		return true
	}
	return tp[1] == mp[1]
}

func extractTrustDomain(uri string) string {
	for _, prefix := range []string{"wimse://", "spiffe://"} {
		if strings.HasPrefix(uri, prefix) {
			rest := strings.TrimPrefix(uri, prefix)
			if idx := strings.Index(rest, "/"); idx > 0 {
				return rest[:idx]
			}
			return rest
		}
	}
	return ""
}

func inferAlg(key crypto.PublicKey) jwa.SignatureAlgorithm {
	switch key.(type) {
	case *ecdsa.PublicKey:
		return jwa.ES256()
	case ed25519.PublicKey:
		return jwa.EdDSA()
	case *rsa.PublicKey:
		return jwa.RS256()
	default:
		return jwa.RS256()
	}
}

func strIn(s string, list []string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
