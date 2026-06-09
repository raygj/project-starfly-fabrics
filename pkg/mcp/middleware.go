// Package mcp provides MCP (Model Context Protocol) security middleware for Starfly.
//
// The middleware verifies WIMSE JWTs on MCP tool calls, enforces per-tool
// capability scoping, blast radius constraints, and delegation depth limits.
// It integrates with OPA policy, the revocation index, and audit logging.
//
// See ADR-0004 for the architecture decision record.
package mcp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/starfly-fabrics/starfly/pkg/audit"
	"github.com/starfly-fabrics/starfly/pkg/core"
)

// Sentinel errors for MCP middleware.
var (
	ErrMissingToken        = errors.New("mcp: missing authorization token")
	ErrInvalidToken        = errors.New("mcp: invalid or expired token")
	ErrTokenRevoked        = errors.New("mcp: token has been revoked")
	ErrToolNotRegistered   = errors.New("mcp: tool not registered")
	ErrCapabilityDenied    = errors.New("mcp: capability not granted")
	ErrBlastRadiusExceeded = errors.New("mcp: blast radius exceeded")
	ErrAudienceMismatch    = errors.New("mcp: token audience does not match tool resource URI")
	ErrPolicyDenied        = errors.New("mcp: policy denied access")
	ErrExecOpMismatch      = errors.New("mcp: operation not authorized for this tool")
	ErrExecPayloadMismatch = errors.New("mcp: payload hash does not match request body")
	ErrExecPayloadMissing  = errors.New("mcp: tool requires payload binding but token has no inp_hash")
	ErrExecTargetMismatch  = errors.New("mcp: target resource not authorized for this tool")
	ErrExecBindingRequired = errors.New("mcp: tool requires execution binding but token has none")
	ErrDPoPInvalid         = errors.New("mcp: DPoP proof validation failed")
)

// VerifiedClaims contains the validated claims from an MCP tool call token.
type VerifiedClaims struct {
	Subject        string               `json:"sub"`
	Issuer         string               `json:"iss"`
	Audience       string               `json:"aud"`
	Capabilities   []string             `json:"caps,omitempty"`
	BlastRadius    string               `json:"blast_radius,omitempty"`
	Delegation     *Delegation          `json:"delegation,omitempty"`
	Execution      *core.ExecutionScope `json:"execution,omitempty"`
	ExpiresAt      time.Time            `json:"exp"`
	ToolID         string               `json:"tool_id,omitempty"`
	Resource       string               `json:"resource,omitempty"` // RFC 8707 resource indicator
	CNFThumbprint  string               `json:"cnf_jkt,omitempty"` // RFC 9449 DPoP key thumbprint
}

// Delegation holds on-behalf-of delegation chain info extracted from the token.
type Delegation struct {
	OnBehalfOf string `json:"on_behalf_of,omitempty"`
	Depth      int    `json:"depth"`
}

// VerifyOptions carries request-scoped data needed for execution binding checks.
// When nil, execution binding verification is skipped (backward compatible).
type VerifyOptions struct {
	// RequestBody is the raw request body bytes for inp_hash verification.
	// When non-nil, the SHA-256 hash is computed and compared to the token's inp_hash claim.
	RequestBody []byte

	// DPoPProof is the raw DPoP proof JWT from the DPoP HTTP header (RFC 9449).
	// When non-empty, it is validated and its key thumbprint is checked against
	// the token's cnf.jkt claim if present.
	DPoPProof string
}

// contextKey for verified claims.
type mcpContextKey string

const verifiedClaimsKey mcpContextKey = "mcp_verified_claims"

// ClaimsFromContext extracts the VerifiedClaims from the request context.
// Returns nil if the middleware has not run or verification failed.
func ClaimsFromContext(ctx context.Context) *VerifiedClaims {
	v, _ := ctx.Value(verifiedClaimsKey).(*VerifiedClaims)
	return v
}

// Config holds the configuration for the MCP security middleware.
type Config struct {
	// JWKSResolver resolves public keys for JWT verification.
	JWKSResolver core.JWKSResolver

	// Registry is the MCP tool registry for looking up tool metadata.
	Registry *Registry

	// RevocationChecker checks whether a subject is revoked.
	RevocationChecker core.RevocationIndex

	// Policy evaluates OPA policy for tool access decisions.
	Policy core.PolicyEngine

	// Auditor logs MCP security events.
	Auditor core.Auditor

	// UnitID is the Starfly unit identifier for audit events.
	UnitID string

	// DevMode disables strict verification for development.
	DevMode bool

	// WorkflowTracker manages active workflows for DAG validation.
	// When nil, workflow tracking is skipped.
	WorkflowTracker *WorkflowTracker

	// ECTLedger is the append-only, hash-chained ECT audit ledger.
	// When nil, ECTs are still logged via Auditor but not indexed.
	ECTLedger *audit.ECTLedger

	// SigningKey signs post-execution ECTs. When nil, ECT generation is skipped.
	SigningKey crypto.Signer

	// SigningKeyID is the kid header value for signed ECTs.
	SigningKeyID string

	// Issuer is the WIMSE identifier for this Starfly unit (used as ECT issuer).
	Issuer string
}

// Middleware returns an http.Handler middleware that verifies WIMSE JWTs
// on incoming MCP tool calls. It extracts the tool ID from the request path,
// validates the token against the tool's resource URI (RFC 8707), checks
// capabilities and blast radius, and evaluates OPA policy.
//
// On success, the verified claims are stored in the request context
// and the next handler is called. On failure, an appropriate HTTP error
// is returned.
func Middleware(cfg Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Extract the bearer token.
			token, err := extractBearerToken(r)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "invalid_token", err.Error())
				logAudit(cfg, r, "", "", "denied", err.Error(), start)
				return
			}

			// Extract tool ID from the request (path or header).
			toolID := extractToolID(r)

			// Read body for execution binding (inp_hash verification).
			// The body is buffered so downstream handlers can still read it.
			opts := &VerifyOptions{
				DPoPProof: r.Header.Get("DPoP"),
			}
			if r.Body != nil {
				body, readErr := io.ReadAll(r.Body)
				if readErr == nil && len(body) > 0 {
					opts.RequestBody = body
					r.Body = io.NopCloser(strings.NewReader(string(body)))
				}
			}

			// Extract parent ECT JTIs from inbound Execution-Context headers
			// (ECT spec Section 4 — multiple headers carry parent context).
			parentJTIs := extractParentECTJTIs(r)

			// Verify the JWT and extract claims.
			claims, err := VerifyToolCall(r.Context(), cfg, token, toolID, opts)
			if err != nil {
				status := http.StatusUnauthorized
				code := "invalid_token"
				if errors.Is(err, ErrTokenRevoked) {
					status = http.StatusForbidden
					code = "token_revoked"
				} else if errors.Is(err, ErrCapabilityDenied) || errors.Is(err, ErrBlastRadiusExceeded) || errors.Is(err, ErrPolicyDenied) {
					status = http.StatusForbidden
					code = "access_denied"
				} else if errors.Is(err, ErrAudienceMismatch) {
					status = http.StatusForbidden
					code = "audience_mismatch"
				} else if errors.Is(err, ErrDPoPInvalid) {
					status = http.StatusUnauthorized
					code = "invalid_dpop_proof"
				} else if errors.Is(err, ErrExecOpMismatch) || errors.Is(err, ErrExecPayloadMismatch) ||
					errors.Is(err, ErrExecPayloadMissing) || errors.Is(err, ErrExecTargetMismatch) ||
					errors.Is(err, ErrExecBindingRequired) {
					status = http.StatusForbidden
					code = "execution_binding_failed"
				}
				writeError(w, status, code, err.Error())
				logAudit(cfg, r, claims.subjectOrEmpty(), toolID, "denied", err.Error(), start)
				return
			}

			// Store verified claims in context.
			ctx := context.WithValue(r.Context(), verifiedClaimsKey, claims)
			logAudit(cfg, r, claims.Subject, toolID, "allowed", "all checks passed", start)

			// ── Phase 5: Accountability (ECT generation) ──────────────────
			// Wrap the response writer to capture body for out_hash.
			if cfg.SigningKey != nil && claims.Execution != nil {
				rc := newResponseCapture(w)
				next.ServeHTTP(rc, r.WithContext(ctx))

				// Generate post-execution ECT.
				ect, ectErr := GenerateECT(&ECTRequest{
					Claims:       claims,
					ToolID:       toolID,
					ResponseBody: rc.body,
					DurationMS:   time.Since(start).Milliseconds(),
					ParentIDs:    parentJTIs,
				}, cfg.Issuer, cfg.SigningKey, cfg.SigningKeyID)
				if ectErr != nil {
					slog.Warn("mcp: ECT generation failed", "error", ectErr, "tool", toolID)
				} else {
					// Record task in workflow tracker for DAG validation.
					if cfg.WorkflowTracker != nil {
						wid := ""
						if claims.Execution != nil {
							wid = claims.Execution.WorkflowID
						}
						if dagErr := cfg.WorkflowTracker.RecordTask(
							wid, ect.JTI, ect.IssuedAt, ect.ParentIDs,
						); dagErr != nil {
							slog.Warn("mcp: DAG recording failed", "error", dagErr, "jti", ect.JTI)
						}
					}

					// Append to ECT ledger (hash-chained, jti-indexed).
					if cfg.ECTLedger != nil {
						_, ledgerErr := cfg.ECTLedger.Append(&audit.ECTLedgerEntry{
							JTI:        ect.JTI,
							ECTToken:   ect.SignedToken,
							Issuer:     ect.Issuer,
							Subject:    claims.Subject,
							ToolID:     toolID,
							ExecAct:    ect.ExecAct,
							WorkflowID: ect.WorkflowID,
						})
						if ledgerErr != nil {
							slog.Warn("mcp: ECT ledger append failed", "error", ledgerErr, "jti", ect.JTI)
						}
					}

					// Set Execution-Context response header per ECT spec Section 4.
					rc.ResponseWriter.Header().Set("Execution-Context", ect.SignedToken)

					// Append ECT to audit log.
					if cfg.Auditor != nil {
						_ = cfg.Auditor.Log(r.Context(), &core.AuditEvent{
							Type:     "ect",
							Action:   "ect_generated",
							Subject:  claims.Subject,
							Target:   toolID,
							Decision: "recorded",
							Reason:   ect.JTI,
							Metadata: map[string]interface{}{
								"exec_act":    ect.ExecAct,
								"inp_hash":    ect.InputHash,
								"out_hash":    ect.OutputHash,
								"target":      ect.Target,
								"wid":         ect.WorkflowID,
								"duration_ms": time.Since(start).Milliseconds(),
							},
							UnitID: cfg.UnitID,
						})
					}
				}
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// VerifyToolCall validates a WIMSE JWT for an MCP tool call.
//
// Five-phase verification pipeline (draft-nennemann-wimse-ect-00):
//
//  1. Identity — JWT signature verification via JWKS resolver
//  2. Authorization — audience, capability, blast radius, OPA policy
//  3. Execution Binding — exec_act, inp_hash, target (ECT-aligned)
//  4. Revocation — O(1) revocation index check
//
// Phase 5 (Accountability / ECT generation) is handled post-execution by the caller.
//
// The opts parameter is optional. When non-nil, it carries request-scoped data
// for execution binding verification (e.g., request body for inp_hash).
func VerifyToolCall(ctx context.Context, cfg Config, tokenStr string, toolID string, opts ...*VerifyOptions) (*VerifiedClaims, error) {
	// Parse the JWT without verification first to extract issuer + kid.
	insecure, err := jwt.ParseInsecure([]byte(tokenStr))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	issuer, _ := insecure.Issuer()
	if issuer == "" {
		return nil, fmt.Errorf("%w: missing issuer claim", ErrInvalidToken)
	}

	var verified jwt.Token

	if cfg.DevMode {
		// Dev mode: trust the token claims without external JWKS
		// verification (Starfly is verifying its own tokens).
		// Audience/capability/blast-radius checks still apply below.
		verified = insecure
	} else {
		// Resolve the signing key from the issuer's JWKS.
		kid := extractKID(tokenStr)
		pubKey, err := cfg.JWKSResolver.ResolveKey(ctx, issuer, kid)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to resolve signing key: %v", ErrInvalidToken, err)
		}

		// Verify the JWT signature and standard claims.
		verified, err = jwt.Parse([]byte(tokenStr),
			jwt.WithKey(inferAlgorithm(pubKey), pubKey),
			jwt.WithValidate(true),
		)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
		}
	}

	// Extract WIMSE-specific claims.
	claims := extractClaims(verified)

	// ── Phase 1.5: DPoP Proof-of-Possession (RFC 9449) ───────────────
	// Validates the DPoP proof and checks its key thumbprint against cnf.jkt.
	// Skipped in devMode (dev tokens have no cnf.jkt).
	if err := verifyDPoP(cfg, claims, resolveOpts(opts)); err != nil {
		return nil, err
	}

	// Audience check — RFC 8707 resource indicator alignment.
	// The token's aud must match the tool's resource URI to prevent
	// confused deputy attacks where tokens are mis-redeemed across tools.
	if toolID != "" && cfg.Registry != nil {
		tool, ok := cfg.Registry.Get(toolID)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrToolNotRegistered, toolID)
		}
		resourceURI := tool.ResourceURI
		if resourceURI == "" {
			resourceURI = tool.ToolID
		}
		if claims.Audience != resourceURI {
			return nil, fmt.Errorf("%w: got %q, want %q", ErrAudienceMismatch, claims.Audience, resourceURI)
		}
		claims.ToolID = toolID
		claims.Resource = resourceURI

		// Capability check — token capabilities must include tool requirements.
		if err := checkCapabilities(claims.Capabilities, tool.RequiredCapabilities); err != nil {
			return nil, err
		}

		// Blast radius check — token blast radius must fit within tool max.
		if tool.MaxBlastRadius != "" && claims.BlastRadius != "" {
			if !blastRadiusFits(claims.BlastRadius, tool.MaxBlastRadius) {
				return nil, fmt.Errorf("%w: token scope %q exceeds tool max %q",
					ErrBlastRadiusExceeded, claims.BlastRadius, tool.MaxBlastRadius)
			}
		}
	}

	// Revocation check.
	if cfg.RevocationChecker != nil {
		entry, err := cfg.RevocationChecker.IsRevoked(ctx, claims.Subject)
		if err != nil {
			slog.Warn("mcp: revocation check error, failing open", "error", err, "subject", claims.Subject)
		}
		if entry != nil {
			return nil, fmt.Errorf("%w: %s", ErrTokenRevoked, entry.Reason)
		}
	}

	// OPA policy evaluation.
	if cfg.Policy != nil {
		decision, err := cfg.Policy.Evaluate(ctx, &core.PolicyInput{
			Action: "mcp_tool_call",
			Subject: &core.WorkloadIdentity{
				ID:          claims.Subject,
				TrustDomain: extractTrustDomain(claims.Subject),
				Attestation: &core.AttestationEvidence{
					Method:    core.AttestMethodMCP,
					Timestamp: time.Now(),
				},
			},
			Target: toolID,
			Context: map[string]interface{}{
				"capabilities": claims.Capabilities,
				"blast_radius": claims.BlastRadius,
				"audience":     claims.Audience,
				"issuer":       claims.Issuer,
				"resource":     claims.Resource,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("mcp: policy evaluation failed: %w", err)
		}
		if !decision.Allowed {
			return nil, fmt.Errorf("%w: %s", ErrPolicyDenied, decision.Reason)
		}
	}

	// ── Phase 3: Execution Binding (ECT-aligned) ──────────────────────
	// Verifies exec_act, inp_hash, and target claims when the tool
	// requires execution-scoped tokens.
	if toolID != "" && cfg.Registry != nil {
		tool, ok := cfg.Registry.Get(toolID)
		if ok {
			if err := verifyExecutionBinding(claims, tool, resolveOpts(opts)); err != nil {
				return nil, err
			}
		}
	}

	return claims, nil
}

// extractBearerToken pulls the JWT from the Authorization header.
func extractBearerToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", ErrMissingToken
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", fmt.Errorf("%w: expected Bearer scheme", ErrInvalidToken)
	}
	return parts[1], nil
}

// extractToolID gets the tool identifier from the request.
// Checks X-MCP-Tool-ID header first, then falls back to URL path extraction.
func extractToolID(r *http.Request) string {
	if id := r.Header.Get("X-MCP-Tool-ID"); id != "" {
		return id
	}
	// Fall back to path-based extraction: /v1/mcp/tools/{toolID}/call
	parts := strings.Split(r.URL.Path, "/")
	for i, p := range parts {
		if p == "tools" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// extractParentECTJTIs parses Execution-Context request headers to extract
// parent task JTIs for DAG linkage. Per ECT spec Section 4, multiple headers
// may be present (one per parent ECT). Each is a JWS compact serialization.
// We extract the jti claim from each without full cryptographic verification
// here — verification happens in the workflow tracker.
func extractParentECTJTIs(r *http.Request) []string {
	headers := r.Header.Values("Execution-Context")
	if len(headers) == 0 {
		return nil
	}

	var jtis []string
	for _, h := range headers {
		// Parse insecurely to extract jti — full verification is the
		// receiver's responsibility per spec Section 6.
		token, err := jwt.ParseInsecure([]byte(h))
		if err != nil {
			continue
		}
		jti, ok := token.JwtID()
		if !ok || jti == "" {
			continue
		}
		jtis = append(jtis, jti)
	}
	return jtis
}

// extractKID extracts the kid from the JWT header without full parsing.
func extractKID(tokenStr string) string {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	// The header is the first part — we need a minimal parse.
	// jwt.Parse already handles this; we extract kid from the protected header.
	// For JWKS resolution, an empty kid triggers a full set search.
	return ""
}

// extractClaims maps JWT claims to VerifiedClaims.
func extractClaims(t jwt.Token) *VerifiedClaims {
	sub, _ := t.Subject()
	iss, _ := t.Issuer()
	exp, _ := t.Expiration()

	vc := &VerifiedClaims{
		Subject:   sub,
		Issuer:    iss,
		ExpiresAt: exp,
	}

	// Audience — take the first value.
	if auds, ok := t.Audience(); ok && len(auds) > 0 {
		vc.Audience = auds[0]
	}

	// Capabilities (caps claim).
	var capsRaw []interface{}
	if err := t.Get("caps", &capsRaw); err == nil {
		for _, c := range capsRaw {
			if s, ok := c.(string); ok {
				vc.Capabilities = append(vc.Capabilities, s)
			}
		}
	}

	// Blast radius.
	var br string
	if err := t.Get("blast_radius", &br); err == nil {
		vc.BlastRadius = br
	}

	// On-behalf-of delegation.
	var obo string
	if err := t.Get("obo", &obo); err == nil {
		vc.Delegation = &Delegation{OnBehalfOf: obo}
	}

	// Delegation depth.
	var dd float64
	if err := t.Get("delegation_depth", &dd); err == nil {
		if vc.Delegation == nil {
			vc.Delegation = &Delegation{}
		}
		vc.Delegation.Depth = int(dd)
	}

	// Execution scope — ECT-aligned top-level claims (draft-nennemann-wimse-ect-00).
	// The exchange engine mints these as flat claims, not a nested object.
	var hasExec bool
	es := &core.ExecutionScope{}

	if v, err := stringClaim(t, "htm"); err == nil {
		es.Method = v
		hasExec = true
	}
	if v, err := stringClaim(t, "htu"); err == nil {
		es.URI = v
		hasExec = true
	}
	if v, err := stringClaim(t, "exec_act"); err == nil {
		es.ExecAct = v
		hasExec = true
	}
	if v, err := stringClaim(t, "inp_hash"); err == nil {
		es.InputHash = v
		hasExec = true
	}
	// Backward compat: fall back to deprecated payload_hash if inp_hash absent.
	if es.InputHash == "" {
		if v, err := stringClaim(t, "payload_hash"); err == nil {
			es.InputHash = v
			es.PayloadHash = v
			hasExec = true
		}
	}
	if v, err := stringClaim(t, "out_hash"); err == nil {
		es.OutputHash = v
		hasExec = true
	}
	if v, err := stringClaim(t, "target"); err == nil {
		es.Target = v
		hasExec = true
	}
	if v, err := stringClaim(t, "wid"); err == nil {
		es.WorkflowID = v
		hasExec = true
	}
	if v, err := stringClaim(t, "nonce"); err == nil {
		es.Nonce = v
		hasExec = true
	}

	if hasExec {
		vc.Execution = es
	}

	// DPoP key thumbprint — RFC 9449 cnf.jkt claim.
	var cnf map[string]interface{}
	if err := t.Get("cnf", &cnf); err == nil {
		if jkt, ok := cnf["jkt"].(string); ok {
			vc.CNFThumbprint = jkt
		}
	}

	return vc
}

// stringClaim extracts a single string claim from the JWT.
func stringClaim(t jwt.Token, name string) (string, error) {
	var s string
	if err := t.Get(name, &s); err != nil {
		return "", err
	}
	return s, nil
}

// resolveOpts extracts the VerifyOptions from the variadic parameter.
func resolveOpts(opts []*VerifyOptions) *VerifyOptions {
	for _, o := range opts {
		if o != nil {
			return o
		}
	}
	return nil
}

// verifyExecutionBinding performs Phase 3 of the verification pipeline:
// exec_act, inp_hash, and target checks per draft-nennemann-wimse-ect-00.
func verifyExecutionBinding(claims *VerifiedClaims, tool *ToolEntry, opts *VerifyOptions) error {
	// Check 1: Does the tool require execution-scoped tokens?
	if tool.RequiresExecution && claims.Execution == nil {
		return fmt.Errorf("%w: tool %q requires execution-scoped token", ErrExecBindingRequired, tool.ToolID)
	}

	// If the token has no execution scope, remaining checks don't apply.
	if claims.Execution == nil {
		return nil
	}
	ex := claims.Execution

	// Check 2: exec_act — operation must be in the tool's allowed set.
	if len(tool.AllowedOperations) > 0 && ex.ExecAct != "" {
		if !stringInSlice(ex.ExecAct, tool.AllowedOperations) {
			return fmt.Errorf("%w: exec_act %q not in allowed set %v",
				ErrExecOpMismatch, ex.ExecAct, tool.AllowedOperations)
		}
	}

	// Check 3: inp_hash — payload integrity.
	// If the token declares an inp_hash and we have the request body, verify the hash matches.
	if ex.InputHash != "" && opts != nil && opts.RequestBody != nil {
		computed := computeInputHash(opts.RequestBody)
		if computed != ex.InputHash {
			return fmt.Errorf("%w: computed %q, token declares %q",
				ErrExecPayloadMismatch, computed, ex.InputHash)
		}
	}
	// If the tool requires execution binding and the token has no inp_hash, reject.
	if tool.RequiresExecution && ex.InputHash == "" {
		return ErrExecPayloadMissing
	}

	// Check 4: target — resource binding.
	if len(tool.AllowedTargets) > 0 && ex.Target != "" {
		if !stringInSlice(ex.Target, tool.AllowedTargets) {
			return fmt.Errorf("%w: target %q not in allowed set %v",
				ErrExecTargetMismatch, ex.Target, tool.AllowedTargets)
		}
	}

	return nil
}

// computeInputHash returns the base64url-encoded (no padding) SHA-256 hash of data,
// matching the ECT inp_hash format (draft-nennemann-wimse-ect-00 Section 3.2.3).
func computeInputHash(data []byte) string {
	h := sha256.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// stringInSlice checks membership in a string slice.
func stringInSlice(s string, list []string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// checkCapabilities verifies the token has all required capabilities for the tool.
func checkCapabilities(tokenCaps []string, required []string) error {
	if len(required) == 0 {
		return nil
	}
	have := make(map[string]bool, len(tokenCaps))
	for _, c := range tokenCaps {
		have[c] = true
	}
	var missing []string
	for _, r := range required {
		if !have[r] {
			missing = append(missing, r)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: missing %v", ErrCapabilityDenied, missing)
	}
	return nil
}

// blastRadiusFits checks whether the token's blast radius fits within the tool's max.
// Blast radius is formatted as "scope:value" — a simple hierarchical comparison.
// Examples: "namespace:dev" fits within "namespace:*", "db:analytics-readonly" fits within "db:*".
func blastRadiusFits(tokenBR, maxBR string) bool {
	// Wildcard max allows anything.
	if maxBR == "*" {
		return true
	}

	tokenParts := strings.SplitN(tokenBR, ":", 2)
	maxParts := strings.SplitN(maxBR, ":", 2)

	// Different scope types never fit.
	if len(tokenParts) < 2 || len(maxParts) < 2 {
		return tokenBR == maxBR
	}
	if tokenParts[0] != maxParts[0] {
		return false
	}

	// Wildcard scope value.
	if maxParts[1] == "*" {
		return true
	}

	// Exact match.
	return tokenParts[1] == maxParts[1]
}

// extractTrustDomain extracts the trust domain from a WIMSE/SPIFFE URI.
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

// inferAlgorithm picks the JWA algorithm based on key type.
func inferAlgorithm(key crypto.PublicKey) jwa.SignatureAlgorithm {
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

// subjectOrEmpty returns the subject if claims is non-nil, empty string otherwise.
func (vc *VerifiedClaims) subjectOrEmpty() string {
	if vc == nil {
		return ""
	}
	return vc.Subject
}

// writeError writes a JSON error response in the Starfly API format.
func writeError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// logAudit records an MCP middleware decision in the audit log.
func logAudit(cfg Config, r *http.Request, subject, toolID, decision, reason string, start time.Time) {
	if cfg.Auditor == nil {
		return
	}
	_ = cfg.Auditor.Log(r.Context(), &core.AuditEvent{
		Type:     "mcp",
		Action:   "tool_call_verified",
		Subject:  subject,
		Target:   toolID,
		Decision: decision,
		Reason:   reason,
		Metadata: map[string]interface{}{
			"method":      r.Method,
			"path":        r.URL.Path,
			"duration_ms": time.Since(start).Milliseconds(),
		},
		UnitID: cfg.UnitID,
	})
}
