package exchange

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/secrets"
	"github.com/starfly-fabrics/starfly/pkg/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

const tracerName = "github.com/starfly-fabrics/starfly/pkg/exchange"

// Sentinel errors for exchange failures.
var (
	ErrInvalidGrantType     = errors.New("invalid grant_type")
	ErrUnsupportedToken     = errors.New("unsupported subject_token_type")
	ErrInvalidSubject       = errors.New("malformed subject URI")
	ErrPolicyDenied         = errors.New("policy denied exchange")
	ErrSubjectRevoked       = errors.New("subject identity has been revoked")
	ErrActorTokenInvalid    = errors.New("actor token invalid")
	ErrWorkloadValidation   = errors.New("workload validation failed")
)


// grantTypeTokenExchange is the RFC 8693 grant type for token exchange.
const grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

// subjectTokenTypeJWT is the RFC 8693 token type for JWT bearer tokens.
const subjectTokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"

const (
	// Source credential token type URIs (ADR-0006).
	subjectTokenTypeSPIFFE   = "urn:starfly:token-type:spiffe-svid"
	subjectTokenTypeOIDC     = "urn:starfly:token-type:oidc"
	subjectTokenTypeKerberos = "urn:starfly:token-type:kerberos"
	subjectTokenTypeSAML     = "urn:starfly:token-type:saml"
	subjectTokenTypeAWSSTS   = "urn:starfly:token-type:aws-sts"
	subjectTokenTypeGCPWIF   = "urn:starfly:token-type:gcp-wif"
	subjectTokenTypeAzureMI  = "urn:starfly:token-type:azure-mi"
	subjectTokenTypeMTLS     = "urn:starfly:token-type:mtls"
	subjectTokenTypeOAuth2   = "urn:ietf:params:oauth:token-type:access_token"
	subjectTokenTypeSAML2    = "urn:ietf:params:oauth:token-type:saml2" // RFC 8693 alias for SAML
	subjectTokenTypeAPIKey   = "urn:starfly:token-type:api-key"

	// Agent credential token type URIs.
	subjectTokenTypeAgentMCP      = "urn:starfly:token-type:agent-mcp"
	subjectTokenTypeAgentA2A      = "urn:starfly:token-type:agent-a2a"
	subjectTokenTypeAgentPassport = "urn:starfly:token-type:agent-passport"
)

// Option configures optional Engine dependencies.
type Option func(*Engine)

// WithSyncBus injects a signal bus so that successful exchanges flash an
// identity_event to the fabric. Flash failures are logged but never fail
// the exchange.
func WithSyncBus(bus core.SyncBus, unitID string) Option {
	return func(e *Engine) {
		e.syncBus = bus
		e.unitID = unitID
	}
}

// WithRevocationChecker injects a revocation index so that exchanges check
// whether the subject identity has been revoked before issuing a token.
func WithRevocationChecker(rc core.RevocationIndex) Option {
	return func(e *Engine) {
		e.revocation = rc
	}
}

// WithOnRevocationError sets a callback invoked when a revocation check fails
// and the engine fails open. Use this to increment a Prometheus counter.
func WithOnRevocationError(fn func()) Option {
	return func(e *Engine) {
		e.onRevocationError = fn
	}
}

// WithOnExchange sets a callback invoked after every successful or denied
// exchange. Parameters: subject URI, target audience, result ("ok" or "denied"),
// and duration. Used to feed the SSE event broadcaster.
func WithOnExchange(fn func(subject, target, result string, duration time.Duration)) Option {
	return func(e *Engine) {
		e.onExchange = fn
	}
}

// WithIssuer sets the issuer claim in minted JWTs. Defaults to "starfly".
func WithIssuer(issuer string) Option {
	return func(e *Engine) { e.issuer = issuer }
}

// WithTTL sets the default token TTL. Defaults to 5 minutes.
func WithTTL(ttl time.Duration) Option {
	return func(e *Engine) { e.ttl = ttl }
}

// WithExecutionScopeTTL sets the TTL for execution-scoped tokens.
// Defaults to 30 seconds.
func WithExecutionScopeTTL(ttl time.Duration) Option {
	return func(e *Engine) { e.executionTTL = ttl }
}

// WithSecretSource injects a secret source registry for converged
// credential management (ADR-0014). When configured, the exchange
// engine encrypts fetched secrets into the JWT's "secrets" claim.
func WithSecretSource(reg *secrets.Registry) Option {
	return func(e *Engine) { e.secretSource = reg }
}

// WithEncryptionKeyStore injects an encryption key store used to look up
// workload public keys for JWE encryption of secret bundles.
func WithEncryptionKeyStore(ks secrets.EncryptionKeyStore) Option {
	return func(e *Engine) { e.encryptionKeyStore = ks }
}

// WithOnSecretDelivery sets a callback invoked after every secret delivery
// attempt. Parameters: source name, result ("ok", "no_key", "source_unavailable",
// "fetch_error", "encrypt_error"), and duration.
func WithOnSecretDelivery(fn func(source, result string, duration time.Duration)) Option {
	return func(e *Engine) { e.onSecretDelivery = fn }
}

// WithDevMode enables dev mode. When false (production), hardware assurance
// claims from the X-Starfly-Attestation header are capped at "software"
// because hardware attestation requires a verified platform credential in
// the subject token (e.g. SPIRE SVID), not a client-supplied header alone.
func WithDevMode(devMode bool) Option {
	return func(e *Engine) { e.devMode = devMode }
}

// attestationAssurance returns the assurance level for att, capped at "software"
// in non-dev mode (HARDEN-003).
func (e *Engine) attestationAssurance(att *core.ServerAttestation) string {
	level := att.AssuranceLevel()
	if !e.devMode && level == "hardware" {
		return "software"
	}
	return level
}

// Engine implements core.TokenExchanger. It validates a source credential,
// evaluates OPA policy, and mints a WIMSE-compliant JWT signed with the
// active key from the keyring. The keyring supports atomic key rotation
// via the lifecycle.SigningKeyManager interface.
type Engine struct {
	identity   core.IdentityProvider
	policy     core.PolicyEngine
	auditor    core.Auditor
	keyring    *Keyring
	signKey    jwk.Key // kept in sync with keyring.ActiveKey() for backward compat
	issuer     string
	ttl        time.Duration
	syncBus    core.SyncBus
	unitID     string
	revocation        core.RevocationIndex
	onRevocationError func()
	nonces            *nonceTracker
	executionTTL      time.Duration
	onExchange         func(subject, target, result string, duration time.Duration)
	secretSource       *secrets.Registry
	encryptionKeyStore secrets.EncryptionKeyStore
	onSecretDelivery   func(source, result string, duration time.Duration)
	devMode            bool
}

var _ core.TokenExchanger = (*Engine)(nil)

// PublicKeySet returns a JWK Set containing ALL public signing keys.
// During key rotation, both old and new keys are served so tokens
// signed with either key can be verified.
func (e *Engine) PublicKeySet() (jwk.Set, error) {
	if e.keyring != nil {
		return e.keyring.PublicKeySet()
	}
	// Fallback for engines created without a keyring.
	pub, err := e.signKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("extracting public key: %w", err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		return nil, fmt.Errorf("adding key to set: %w", err)
	}
	return set, nil
}

// Keyring returns the engine's keyring for lifecycle operations.
// Returns nil if the engine was created without keyring support.
func (e *Engine) Keyring() *Keyring {
	return e.keyring
}

// publicKeySet returns the engine's public key set for token verification.
// Used internally to verify actor tokens in delegation flows.
func (e *Engine) publicKeySet() jwk.Set {
	set, err := e.PublicKeySet()
	if err != nil {
		// This should never happen — the key was generated at boot.
		slog.Error("failed to get public key set", "error", err)
		return jwk.NewSet()
	}
	return set
}

// New creates an Engine with an ephemeral RSA-2048 signing key.
// The key is generated fresh each boot — KMS-backed signing is Phase 2+.
func New(identity core.IdentityProvider, policy core.PolicyEngine, auditor core.Auditor, opts ...Option) (*Engine, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating dev signing key: %w", err)
	}

	key, err := jwk.Import(privKey)
	if err != nil {
		return nil, fmt.Errorf("importing signing key: %w", err)
	}
	if err := key.Set(jwk.KeyIDKey, "starfly-dev-1"); err != nil {
		return nil, fmt.Errorf("setting kid: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		return nil, fmt.Errorf("setting alg: %w", err)
	}
	if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, fmt.Errorf("setting use: %w", err)
	}

	slog.Warn("exchange engine using ephemeral dev signing key — do not use in production",
		"kid", "starfly-dev-1",
		"alg", "RS256",
	)

	kr, err := NewKeyring(key)
	if err != nil {
		return nil, fmt.Errorf("initializing keyring: %w", err)
	}

	e := &Engine{
		identity:     identity,
		policy:       policy,
		auditor:      auditor,
		keyring:      kr,
		signKey:      key,
		issuer:       "starfly",
		ttl:          5 * time.Minute,
		executionTTL: ExecutionScopeTTL,
		nonces:       newNonceTracker(),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e, nil
}

// Exchange performs an RFC 8693 token exchange: validates the source credential,
// evaluates OPA policy, mints a WIMSE JWT, and logs an audit event.
func (e *Engine) Exchange(ctx context.Context, req *core.TokenExchangeRequest) (*core.TokenExchangeResponse, error) {
	exchangeStart := time.Now()
	ctx, span := otel.Tracer(tracerName).Start(ctx, "exchange.Exchange")
	defer span.End()

	// 1. Validate grant type.
	if req.GrantType != grantTypeTokenExchange {
		err := fmt.Errorf("%w: got %q", ErrInvalidGrantType, req.GrantType)
		telemetry.SpanError(span, err)
		return nil, err
	}

	// 2. Map subject token type to credential type.
	credType, err := mapCredType(req.SubjectTokenType)
	if err != nil {
		telemetry.SpanError(span, err)
		return nil, err
	}

	// 3. Validate workload identity.
	var workload *core.WorkloadIdentity
	{
		_, validateSpan := otel.Tracer(tracerName).Start(ctx, "exchange.ValidateWorkload")
		workload, err = e.identity.ValidateWorkload(ctx, req.SubjectToken, credType)
		if err != nil {
			telemetry.SpanError(validateSpan, err)
			validateSpan.End()
			telemetry.SpanError(span, err)
			return nil, fmt.Errorf("%w: %w", ErrWorkloadValidation, err)
		}
		validateSpan.SetAttributes(
			attribute.String("trust_domain", workload.TrustDomain),
		)
		validateSpan.End()
	}

	span.SetAttributes(
		attribute.String("trust_domain", workload.TrustDomain),
		attribute.String("audience", req.Audience),
	)

	// 3b. Reject malformed WIMSE subject URIs before entering the pipeline.
	// A double prefix (wimse://…/sa/wimse://…) indicates a construction bug in
	// the caller — most commonly a cross-fabric token replay where the WIMSE JWT
	// sub claim is re-wrapped by the dev-mode identity provider.
	if strings.Count(workload.ID, "wimse://") > 1 {
		err := fmt.Errorf("%w: double WIMSE prefix in subject %q", ErrInvalidSubject, workload.ID)
		telemetry.SpanError(span, err)
		return nil, err
	}

	// 3c. Check revocation index if configured.
	if e.revocation != nil {
		_, revokeSpan := otel.Tracer(tracerName).Start(ctx, "exchange.CheckRevocation")
		revokeEntry, revokeErr := e.revocation.IsRevoked(ctx, workload.ID)
		if revokeErr != nil {
			telemetry.SpanError(revokeSpan, revokeErr)
			revokeSpan.SetAttributes(attribute.Bool("fail_open", true))
			revokeSpan.End()
			slog.Error("revocation check failed, failing open", "error", revokeErr, "workload_id", workload.ID)
			_ = e.auditor.Log(ctx, &core.AuditEvent{
				Type:     "exchange",
				Action:   "revocation_check_failed",
				Subject:  workload.ID,
				Target:   req.Audience,
				Decision: "allowed",
				Reason:   "revocation check failed, failing open: " + revokeErr.Error(),
			})
			if e.onRevocationError != nil {
				e.onRevocationError()
			}
			// Fail open: log the error but allow the exchange to proceed.
		} else if revokeEntry != nil {
			revokeSpan.SetAttributes(attribute.Bool("revoked", true))
			revokeSpan.End()
			reason := "subject identity revoked"
			if revokeEntry.Reason != "" {
				reason = "subject identity revoked: " + revokeEntry.Reason
			}
			_ = e.auditor.Log(ctx, &core.AuditEvent{
				Type:     "exchange",
				Action:   "token_exchange",
				Subject:  workload.ID,
				Target:   req.Audience,
				Decision: "denied",
				Reason:   reason,
			})
			err := fmt.Errorf("%w: %s", ErrSubjectRevoked, workload.ID)
			telemetry.SpanError(span, err)
			return nil, err
		} else {
			revokeSpan.End()
		}
	}

	// 3d. Validate and log attestation metadata if present.
	if req.Attestation != nil {
		if err := ValidateAttestation(req.Attestation, 0); err != nil {
			_ = e.auditor.Log(ctx, &core.AuditEvent{
				Type:     "exchange",
				Action:   "attestation_invalid",
				Subject:  workload.ID,
				Target:   req.Audience,
				Decision: "denied",
				Reason:   err.Error(),
			})
			telemetry.SpanError(span, err)
			return nil, fmt.Errorf("attestation validation: %w", err)
		}
		assurance := e.attestationAssurance(req.Attestation)
		slog.Debug("attestation received",
			"source", req.Attestation.Platform.Source,
			"assurance_level", assurance,
			"agent_version", req.Attestation.AgentVersion,
		)
		if req.Attestation.Workload != nil && req.Attestation.Workload.BinaryHash != "" {
			span.SetAttributes(
				attribute.String("attestation.binary_hash", req.Attestation.Workload.BinaryHash),
			)
		}
		span.SetAttributes(
			attribute.String("attestation.assurance_level", assurance),
		)

		// Audit attestation evaluation (SA-006).
		auditMeta := map[string]interface{}{
			"source":          req.Attestation.Platform.Source,
			"assurance_level": assurance,
			"agent_version":   req.Attestation.AgentVersion,
		}
		if req.Attestation.Workload != nil && req.Attestation.Workload.BinaryHash != "" {
			auditMeta["binary_hash"] = req.Attestation.Workload.BinaryHash
		}
		_ = e.auditor.Log(ctx, &core.AuditEvent{
			Type:     "exchange",
			Action:   "attestation_evaluated",
			Subject:  workload.ID,
			Target:   req.Audience,
			Decision: "allowed",
			Metadata: auditMeta,
		})
	}

	// 4. Evaluate policy.
	policyInput := &core.PolicyInput{
		Action:  "exchange",
		Subject: workload,
		Target:  req.Audience,
		Context: map[string]interface{}{
			"scope": req.Scope,
		},
	}

	if strings.HasPrefix(credType, "agent-") {
		policyInput.Context["agent_platform"] = credType
		policyInput.Context["is_agent"] = true
	}

	// SA-003: Inject attestation fields into policy input context.
	if req.Attestation != nil {
		attestMap := map[string]interface{}{
			"platform": map[string]interface{}{
				"source":    req.Attestation.Platform.Source,
				"cred_type": req.Attestation.Platform.CredType,
			},
			"agent_version":   req.Attestation.AgentVersion,
			"assurance_level": e.attestationAssurance(req.Attestation),
		}
		if req.Attestation.Platform.Metadata != nil {
			attestMap["platform"].(map[string]interface{})["metadata"] = req.Attestation.Platform.Metadata
		}
		if req.Attestation.Workload != nil {
			wl := map[string]interface{}{}
			if req.Attestation.Workload.BinaryHash != "" {
				wl["binary_hash"] = req.Attestation.Workload.BinaryHash
			}
			if req.Attestation.Workload.Namespace != "" {
				wl["namespace"] = req.Attestation.Workload.Namespace
			}
			if req.Attestation.Workload.PodName != "" {
				wl["pod_name"] = req.Attestation.Workload.PodName
			}
			if req.Attestation.Workload.ImageDigest != "" {
				wl["image_digest"] = req.Attestation.Workload.ImageDigest
			}
			if req.Attestation.Workload.NodeName != "" {
				wl["node_name"] = req.Attestation.Workload.NodeName
			}
			if len(wl) > 0 {
				attestMap["workload"] = wl
			}
		}
		if len(req.Attestation.Hardware) > 0 {
			hw := make([]map[string]interface{}, 0, len(req.Attestation.Hardware))
			for _, h := range req.Attestation.Hardware {
				hw = append(hw, map[string]interface{}{
					"type": h.Type,
				})
			}
			attestMap["hardware"] = hw
		}
		policyInput.Context["attestation"] = attestMap
	}

	var decision *core.PolicyDecision
	{
		_, policySpan := otel.Tracer(tracerName).Start(ctx, "exchange.EvaluatePolicy")
		decision, err = e.policy.Evaluate(ctx, policyInput)
		if err != nil {
			telemetry.SpanError(policySpan, err)
			policySpan.End()
			telemetry.SpanError(span, err)
			return nil, fmt.Errorf("evaluating policy: %w", err)
		}
		policySpan.SetAttributes(
			attribute.Bool("decision", decision.Allowed),
		)
		policySpan.End()
	}

	// 5. If denied, audit and return error.
	if !decision.Allowed {
		span.SetAttributes(attribute.String("decision", "denied"))
		_ = e.auditor.Log(ctx, &core.AuditEvent{
			Type:     "exchange",
			Action:   "token_exchange",
			Subject:  workload.ID,
			Target:   req.Audience,
			Decision: "denied",
			Reason:   decision.Reason,
		})
		err := fmt.Errorf("%w: %s", ErrPolicyDenied, decision.Reason)
		telemetry.SpanError(span, err)
		return nil, err
	}

	span.SetAttributes(attribute.String("decision", "allowed"))

	// 5a. Validate delegation chain if ActorToken is present (on-behalf-of flow).
	var delegation *delegationContext
	if req.ActorToken != "" {
		_, delegSpan := otel.Tracer(tracerName).Start(ctx, "exchange.ValidateDelegation")

		// Parse the actor token (must be a valid Starfly-signed JWT).
		actorToken, parseErr := jwt.Parse([]byte(req.ActorToken), jwt.WithKeySet(e.publicKeySet()))
		if parseErr != nil {
			err := fmt.Errorf("%w: %v", ErrActorTokenInvalid, parseErr)
			telemetry.SpanError(delegSpan, err)
			delegSpan.End()
			_ = e.auditor.Log(ctx, &core.AuditEvent{
				Type:     "exchange",
				Action:   "token_exchange",
				Subject:  workload.ID,
				Target:   req.Audience,
				Decision: "denied",
				Reason:   err.Error(),
			})
			telemetry.SpanError(span, err)
			return nil, err
		}

		// Extract delegation context from actor token.
		dc, dcErr := parseDelegationContext(actorToken)
		if dcErr != nil {
			telemetry.SpanError(delegSpan, dcErr)
			delegSpan.End()
			telemetry.SpanError(span, dcErr)
			return nil, dcErr
		}

		// Extract requested caps from policy decision (what B is asking for).
		var requestedCaps []string
		if caps, ok := decision.Claims["caps"]; ok {
			if capSlice, ok := caps.([]interface{}); ok {
				for _, c := range capSlice {
					if s, ok := c.(string); ok {
						requestedCaps = append(requestedCaps, s)
					}
				}
			}
		}
		var requestedBR string
		if br, ok := decision.Claims["blast_radius"]; ok {
			if s, ok := br.(string); ok {
				requestedBR = s
			}
		}

		// Enforce delegation rules.
		if err := validateDelegation(dc, requestedCaps, requestedBR); err != nil {
			telemetry.SpanError(delegSpan, err)
			delegSpan.End()
			_ = e.auditor.Log(ctx, &core.AuditEvent{
				Type:     "exchange",
				Action:   "token_exchange",
				Subject:  workload.ID,
				Target:   req.Audience,
				Decision: "denied",
				Reason:   err.Error(),
			})
			telemetry.SpanError(span, err)
			return nil, err
		}

		delegation = dc
		delegSpan.SetAttributes(
			attribute.String("delegation.parent", dc.ParentSubject),
			attribute.Int("delegation.parent_depth", dc.Depth),
			attribute.Int("delegation.chain_length", len(dc.OBOChain)+1),
		)
		delegSpan.End()
	}

	// 5b. Validate DPoP proof if present.
	var dpop *dpopResult
	if req.DPoPProof != "" {
		_, dpopSpan := otel.Tracer(tracerName).Start(ctx, "exchange.ValidateDPoP")
		var dpopErr error
		dpop, dpopErr = validateDPoP(req.DPoPProof)
		if dpopErr != nil {
			telemetry.SpanError(dpopSpan, dpopErr)
			dpopSpan.End()
			telemetry.SpanError(span, dpopErr)
			return nil, dpopErr
		}
		dpopSpan.SetAttributes(attribute.String("dpop.jkt", dpop.Thumbprint))
		dpopSpan.End()
	}

	// 5c. Validate execution scope if present.
	var execScope *core.ExecutionScope
	if req.ExecutionScope != nil {
		_, execSpan := otel.Tracer(tracerName).Start(ctx, "exchange.ValidateExecutionScope")
		if err := validateExecutionScope(req.ExecutionScope); err != nil {
			telemetry.SpanError(execSpan, err)
			execSpan.End()
			telemetry.SpanError(span, err)
			return nil, err
		}
		if err := e.nonces.check(req.ExecutionScope.Nonce); err != nil {
			telemetry.SpanError(execSpan, err)
			execSpan.End()
			telemetry.SpanError(span, err)
			return nil, err
		}
		execScope = req.ExecutionScope
		execSpan.SetAttributes(
			attribute.String("exec.htm", execScope.Method),
			attribute.String("exec.htu", execScope.URI),
		)
		execSpan.End()
	}

	// 5d. Secret delivery — converged credential management (ADR-0014).
	// Fetch secrets from configured sources and encrypt into a JWE for the
	// workload's registered encryption key. Fails open: if no key is registered
	// or the source is unavailable, the exchange proceeds without secrets.
	var secretsClaim string
	if e.secretSource != nil {
		_, secSpan := otel.Tracer(tracerName).Start(ctx, "exchange.SecretDelivery")
		secStart := time.Now()
		secretsClaim = e.deliverSecrets(ctx, workload.ID, decision)
		secDuration := time.Since(secStart)
		if secretsClaim != "" {
			secSpan.SetAttributes(attribute.Bool("secrets_delivered", true))
		}
		secSpan.End()
		_ = secDuration // used by onSecretDelivery callback inside deliverSecrets
	}

	// 6. Build and sign WIMSE JWT.
	var signed []byte
	{
		_, signSpan := otel.Tracer(tracerName).Start(ctx, "exchange.SignJWT")
		now := time.Now().UTC()
		ttl := e.ttl
		if execScope != nil {
			ttl = e.executionTTL // short-lived for execution-scoped tokens
		}
		exp := now.Add(ttl)

		builder := jwt.NewBuilder().
			Subject(workload.ID).
			Issuer(e.issuer).
			Audience([]string{req.Audience}).
			IssuedAt(now).
			Expiration(exp)

		token, err := builder.Build()
		if err != nil {
			telemetry.SpanError(signSpan, err)
			signSpan.End()
			return nil, fmt.Errorf("building JWT: %w", err)
		}

		// Set WIMSE trust domain claim.
		if err := token.Set("td", workload.TrustDomain); err != nil {
			telemetry.SpanError(signSpan, err)
			signSpan.End()
			return nil, fmt.Errorf("setting td claim: %w", err)
		}

		// Set optional claims from policy decision.
		if caps, ok := decision.Claims["caps"]; ok {
			if err := token.Set("caps", caps); err != nil {
				telemetry.SpanError(signSpan, err)
				signSpan.End()
				return nil, fmt.Errorf("setting caps claim: %w", err)
			}
		}
		if br, ok := decision.Claims["blast_radius"]; ok {
			if err := token.Set("blast_radius", br); err != nil {
				telemetry.SpanError(signSpan, err)
				signSpan.End()
				return nil, fmt.Errorf("setting blast_radius claim: %w", err)
			}
		}

		// Set delegation_depth from policy if not in a delegation flow.
		// This allows the initial agent token to carry delegation permission.
		if delegation == nil {
			if dd, ok := decision.Claims["delegation_depth"]; ok {
				if err := token.Set("delegation_depth", dd); err != nil {
					telemetry.SpanError(signSpan, err)
					signSpan.End()
					return nil, fmt.Errorf("setting delegation_depth claim: %w", err)
				}
			}
		}

		// Set delegation claims if this is an on-behalf-of flow.
		if delegation != nil {
			// Decrement depth.
			newDepth := delegation.Depth - 1
			if delegation.Depth < 0 {
				newDepth = -1 // preserve unrestricted
			}
			if newDepth >= 0 {
				if err := token.Set("delegation_depth", newDepth); err != nil {
					telemetry.SpanError(signSpan, err)
					signSpan.End()
					return nil, fmt.Errorf("setting delegation_depth claim: %w", err)
				}
			}

			// Build and set obo chain.
			oboChain := buildOBOChain(delegation)
			if err := token.Set("obo", oboChain); err != nil {
				telemetry.SpanError(signSpan, err)
				signSpan.End()
				return nil, fmt.Errorf("setting obo claim: %w", err)
			}
		}

		// Set cnf claim with DPoP thumbprint for proof-of-possession binding.
		if dpop != nil {
			cnf := map[string]interface{}{
				"jkt": dpop.Thumbprint,
			}
			if err := token.Set("cnf", cnf); err != nil {
				telemetry.SpanError(signSpan, err)
				signSpan.End()
				return nil, fmt.Errorf("setting cnf claim: %w", err)
			}
		}

		// Set attestation claims when attestation header was present (SA-004, ADR-0013).
		if req.Attestation != nil {
			if err := token.Set("assurance_level", e.attestationAssurance(req.Attestation)); err != nil {
				telemetry.SpanError(signSpan, err)
				signSpan.End()
				return nil, fmt.Errorf("setting assurance_level claim: %w", err)
			}
			attestClaims := map[string]interface{}{
				"platform": map[string]interface{}{
					"source":    req.Attestation.Platform.Source,
					"cred_type": req.Attestation.Platform.CredType,
				},
				"agent_version": req.Attestation.AgentVersion,
			}
			if req.Attestation.Workload != nil {
				wl := map[string]interface{}{}
				if req.Attestation.Workload.BinaryHash != "" {
					wl["binary_hash"] = req.Attestation.Workload.BinaryHash
				}
				if req.Attestation.Workload.Namespace != "" {
					wl["namespace"] = req.Attestation.Workload.Namespace
				}
				if len(wl) > 0 {
					attestClaims["workload"] = wl
				}
			}
			if err := token.Set("attestation", attestClaims); err != nil {
				telemetry.SpanError(signSpan, err)
				signSpan.End()
				return nil, fmt.Errorf("setting attestation claim: %w", err)
			}
		}

		// Set execution scope claims (htm, htu, exec_act, inp_hash, target, wid, nonce).
		// Claim names align with draft-nennemann-wimse-ect-00.
		if execScope != nil {
			if err := token.Set("htm", execScope.Method); err != nil {
				telemetry.SpanError(signSpan, err)
				signSpan.End()
				return nil, fmt.Errorf("setting htm claim: %w", err)
			}
			if err := token.Set("htu", execScope.URI); err != nil {
				telemetry.SpanError(signSpan, err)
				signSpan.End()
				return nil, fmt.Errorf("setting htu claim: %w", err)
			}
			// inp_hash — ECT-aligned input hash (replaces payload_hash).
			inpHash := execScope.InputHash
			if inpHash == "" {
				inpHash = execScope.PayloadHash // backward compat
			}
			if inpHash != "" {
				if err := token.Set("inp_hash", inpHash); err != nil {
					telemetry.SpanError(signSpan, err)
					signSpan.End()
					return nil, fmt.Errorf("setting inp_hash claim: %w", err)
				}
			}
			// exec_act — ECT-aligned operation.
			if execScope.ExecAct != "" {
				if err := token.Set("exec_act", execScope.ExecAct); err != nil {
					telemetry.SpanError(signSpan, err)
					signSpan.End()
					return nil, fmt.Errorf("setting exec_act claim: %w", err)
				}
			}
			// target — downstream resource binding.
			if execScope.Target != "" {
				if err := token.Set("target", execScope.Target); err != nil {
					telemetry.SpanError(signSpan, err)
					signSpan.End()
					return nil, fmt.Errorf("setting target claim: %w", err)
				}
			}
			// wid — workflow identifier.
			if execScope.WorkflowID != "" {
				if err := token.Set("wid", execScope.WorkflowID); err != nil {
					telemetry.SpanError(signSpan, err)
					signSpan.End()
					return nil, fmt.Errorf("setting wid claim: %w", err)
				}
			}
			if err := token.Set("nonce", execScope.Nonce); err != nil {
				telemetry.SpanError(signSpan, err)
				signSpan.End()
				return nil, fmt.Errorf("setting nonce claim: %w", err)
			}
		}

		// Set encrypted secrets claim (ADR-0014 converged credential management).
		if secretsClaim != "" {
			if err := token.Set("secrets", secretsClaim); err != nil {
				telemetry.SpanError(signSpan, err)
				signSpan.End()
				return nil, fmt.Errorf("setting secrets claim: %w", err)
			}
		}

		// Use the keyring's active key for signing (supports rotation).
		activeKey := e.signKey
		if e.keyring != nil {
			activeKey = e.keyring.ActiveKey()
		}
		signed, err = jwt.Sign(token, jwt.WithKey(jwa.RS256(), activeKey))
		if err != nil {
			telemetry.SpanError(signSpan, err)
			signSpan.End()
			return nil, fmt.Errorf("signing JWT: %w", err)
		}
		signSpan.End()
	}

	// 7. Audit allow.
	{
		_, auditSpan := otel.Tracer(tracerName).Start(ctx, "exchange.AuditLog")
		auditEvent := &core.AuditEvent{
			Type:     "exchange",
			Action:   "token_exchange",
			Subject:  workload.ID,
			Target:   req.Audience,
			Decision: "allowed",
		}
		if secretsClaim != "" {
			auditEvent.Metadata = map[string]interface{}{
				"secret_delivery": "ok",
			}
		}
		_ = e.auditor.Log(ctx, auditEvent)
		auditSpan.End()
	}

	// 8. Flash signal to sync bus (fire-and-forget).
	if e.syncBus != nil {
		sig := &core.Signal{
			Type: "identity_event",
			Payload: map[string]interface{}{
				"workload_id":  workload.ID,
				"audience":     req.Audience,
				"trust_domain": workload.TrustDomain,
			},
		}
		if err := e.syncBus.Flash(ctx, sig); err != nil {
			slog.Error("signal flash failed", "error", err, "workload_id", workload.ID)
			_ = e.auditor.Log(ctx, &core.AuditEvent{
				Type:    "sync",
				Action:  "signal_flash_failed",
				Subject: workload.ID,
				Target:  req.Audience,
				Reason:  err.Error(),
			})
		} else {
			_ = e.auditor.Log(ctx, &core.AuditEvent{
				Type:    "sync",
				Action:  "signal_flashed",
				Subject: workload.ID,
				Target:  req.Audience,
			})
		}
	}

	// 9. Fire exchange callback for SSE event stream.
	if e.onExchange != nil {
		e.onExchange(workload.ID, req.Audience, "ok", time.Since(exchangeStart))
	}

	// 10. Return response.
	responseTTL := e.ttl
	if execScope != nil {
		responseTTL = e.executionTTL
	}
	var delegationDepth int
	if delegation != nil {
		delegationDepth = len(delegation.OBOChain) + 1
	}
	return &core.TokenExchangeResponse{
		AccessToken:     string(signed),
		IssuedTokenType: subjectTokenTypeJWT,
		TokenType:       "Bearer",
		ExpiresIn:       int(responseTTL.Seconds()),
		Scope:           req.Scope,
		DelegationDepth: delegationDepth,
	}, nil
}

// mapCredType maps an RFC 8693 subject_token_type to an internal credential type.
// The bare JWT URI maps to k8s-sa for backward compatibility (ADR-0006).
// SPIFFE and OIDC callers use their own URIs.
func mapCredType(tokenType string) (string, error) {
	switch tokenType {
	case subjectTokenTypeJWT:
		return "k8s-sa", nil // backward compat: bare JWT = K8s SA
	case subjectTokenTypeSPIFFE:
		return "spiffe-svid", nil
	case subjectTokenTypeOIDC:
		return "oidc", nil
	case subjectTokenTypeKerberos:
		return "kerberos", nil
	case subjectTokenTypeSAML:
		return "saml", nil
	case subjectTokenTypeAWSSTS:
		return "aws-sts", nil
	case subjectTokenTypeGCPWIF:
		return "gcp-wif", nil
	case subjectTokenTypeAzureMI:
		return "azure-mi", nil
	case subjectTokenTypeMTLS:
		return "mtls", nil
	case subjectTokenTypeOAuth2:
		return "oauth2", nil
	case subjectTokenTypeSAML2:
		return "saml", nil // RFC 8693 standard URI routes to same SAML provider
	case subjectTokenTypeAPIKey:
		return "api-key", nil
	case subjectTokenTypeAgentMCP:
		return "agent-mcp", nil
	case subjectTokenTypeAgentA2A:
		return "agent-a2a", nil
	case subjectTokenTypeAgentPassport:
		return "agent-passport", nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedToken, tokenType)
	}
}

// deliverSecrets extracts secret_refs from the policy decision, fetches
// secrets from the registry, encrypts them to the workload's registered
// encryption key, and returns the JWE compact serialization.
// Returns empty string if secrets cannot be delivered (fail open).
func (e *Engine) deliverSecrets(ctx context.Context, workloadID string, decision *core.PolicyDecision) string {
	secStart := time.Now()
	callMetric := func(result string) {
		if e.onSecretDelivery != nil {
			e.onSecretDelivery("registry", result, time.Since(secStart))
		}
	}

	// Extract secret_refs from policy decision claims.
	rawRefs, ok := decision.Claims["secret_refs"]
	if !ok {
		return ""
	}

	refSlice, ok := rawRefs.([]interface{})
	if !ok || len(refSlice) == 0 {
		return ""
	}

	// Parse refs.
	var refs []secrets.SecretRef
	for _, raw := range refSlice {
		refMap, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		ref := secrets.SecretRef{}
		if s, ok := refMap["source"].(string); ok {
			ref.Source = s
		}
		if s, ok := refMap["path"].(string); ok {
			ref.Path = s
		}
		if s, ok := refMap["key"].(string); ok {
			ref.Key = s
		}
		if s, ok := refMap["alias"].(string); ok {
			ref.Alias = s
		}
		if ref.Source != "" && ref.Path != "" && ref.Key != "" {
			refs = append(refs, ref)
		}
	}
	if len(refs) == 0 {
		return ""
	}

	// Look up encryption key.
	if e.encryptionKeyStore == nil {
		callMetric("no_key")
		return ""
	}
	encKey, err := e.encryptionKeyStore.Get(ctx, workloadID)
	if err != nil {
		slog.Debug("no encryption key for workload, skipping secret delivery",
			"workload_id", workloadID, "error", err)
		callMetric("no_key")
		return ""
	}

	// Fetch secrets.
	bundle, err := e.secretSource.Fetch(ctx, refs)
	if err != nil {
		slog.Error("secret fetch failed, skipping delivery",
			"workload_id", workloadID, "error", err)
		callMetric("source_unavailable")
		return ""
	}

	// Warn if bundle is large.
	if len(bundle.Claims) > 0 {
		estimatedSize := 0
		for k, v := range bundle.Claims {
			estimatedSize += len(k) + len(v)
		}
		if estimatedSize > 4096 {
			slog.Warn("secret bundle exceeds 4KB",
				"workload_id", workloadID, "size_bytes", estimatedSize)
		}
	}

	// Encrypt bundle.
	encrypted, err := secrets.EncryptSecretBundle(bundle, encKey)
	if err != nil {
		slog.Error("secret encryption failed, skipping delivery",
			"workload_id", workloadID, "error", err)
		callMetric("encrypt_error")
		return ""
	}

	callMetric("ok")
	return encrypted
}
