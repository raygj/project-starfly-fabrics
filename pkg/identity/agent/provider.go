package agent

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
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "github.com/starfly-fabrics/starfly/pkg/identity/agent"

var (
	ErrMissingAgentName    = errors.New("agent_name is required")
	ErrInvalidPlatform     = errors.New("platform must be one of: mcp, a2a, watsonx, custom")
	ErrEmptyCapabilities   = errors.New("capabilities must not be empty")
	ErrInvalidIdentityID   = errors.New("identity_id must be a wimse:// URI")
)

var validPlatforms = map[string]string{
	"mcp":     core.AttestMethodMCP,
	"a2a":     core.AttestMethodA2A,
	"watsonx": core.AttestMethodWatsonx,
	"custom":  core.AttestMethodCustom,
}

var _ core.AgentIdentityProvider = (*Provider)(nil)

// Provider issues and revokes verifiable WIMSE identities for AI agents.
type Provider struct {
	trustDomains map[string]core.TrustDomain
	auditor      core.Auditor
	syncBus      core.SyncBus
	signKey      jwk.Key
	issuer       string
	ttl          time.Duration
	devMode      bool
}

type Option func(*Provider)

func WithTrustDomains(domains []core.TrustDomain) Option {
	return func(p *Provider) {
		for _, d := range domains {
			if d.Enabled {
				p.trustDomains[d.Name] = d
			}
		}
	}
}

func WithAuditor(a core.Auditor) Option {
	return func(p *Provider) { p.auditor = a }
}

func WithSyncBus(bus core.SyncBus) Option {
	return func(p *Provider) { p.syncBus = bus }
}

func WithDevMode(dev bool) Option {
	return func(p *Provider) { p.devMode = dev }
}

func WithTTL(ttl time.Duration) Option {
	return func(p *Provider) { p.ttl = ttl }
}

func WithIssuer(issuer string) Option {
	return func(p *Provider) { p.issuer = issuer }
}

// NewProvider creates an agent identity provider with an ephemeral
// signing key. Production deployments should use KMS-backed signing.
func NewProvider(opts ...Option) (*Provider, error) {
	p := &Provider{
		trustDomains: make(map[string]core.TrustDomain),
		issuer:       "starfly",
		ttl:          5 * time.Minute,
	}
	for _, opt := range opts {
		opt(p)
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("agent: generating signing key: %w", err)
	}
	key, err := jwk.Import(privKey)
	if err != nil {
		return nil, fmt.Errorf("agent: importing signing key: %w", err)
	}
	if err := key.Set(jwk.KeyIDKey, "starfly-agent-dev-1"); err != nil {
		return nil, fmt.Errorf("agent: setting kid: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		return nil, fmt.Errorf("agent: setting alg: %w", err)
	}

	p.signKey = key

	slog.Warn("agent identity provider using ephemeral dev signing key",
		"kid", "starfly-agent-dev-1",
	)

	return p, nil
}

func (p *Provider) IssueAgentIdentity(ctx context.Context, req *core.AgentIdentityRequest) (*core.AgentIdentity, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "identity.agent.issue")
	defer span.End()

	if err := p.validateRequest(req); err != nil {
		spanError(span, err)
		return nil, err
	}

	attestMethod := validPlatforms[req.Platform]
	span.SetAttributes(
		attribute.String("agent.platform", req.Platform),
		attribute.String("agent.name", req.AgentName),
		attribute.String("attestation.method", attestMethod),
	)

	td := p.resolveTrustDomain(req)
	wimseURI := fmt.Sprintf("wimse://%s/agent/%s/%s", td, req.Platform, req.AgentName)

	span.SetAttributes(attribute.String("trust_domain", td))

	now := time.Now().UTC()
	exp := now.Add(p.ttl)

	token, err := p.mintToken(wimseURI, req, td, now, exp)
	if err != nil {
		spanError(span, err)
		return nil, fmt.Errorf("agent: minting token: %w", err)
	}

	identity := &core.AgentIdentity{
		WorkloadID: wimseURI,
		Token:      string(token),
		ExpiresAt:  exp,
	}

	if p.auditor != nil {
		_ = p.auditor.Log(ctx, &core.AuditEvent{
			Type:     "identity",
			Action:   "agent_identity_issued",
			Subject:  wimseURI,
			Target:   req.Platform,
			Decision: "allowed",
			Metadata: map[string]interface{}{
				"agent_name":       req.AgentName,
				"platform":         req.Platform,
				"capabilities":     req.Capabilities,
				"delegation_depth": req.DelegationDepth,
				"trust_domain":     td,
			},
		})
	}

	return identity, nil
}

func (p *Provider) RevokeIdentity(ctx context.Context, identityID string) error {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "identity.agent.revoke")
	defer span.End()

	if !strings.HasPrefix(identityID, "wimse://") {
		err := fmt.Errorf("%w: %q", ErrInvalidIdentityID, identityID)
		spanError(span, err)
		return err
	}

	span.SetAttributes(attribute.String("identity_id", identityID))

	if p.auditor != nil {
		_ = p.auditor.Log(ctx, &core.AuditEvent{
			Type:    "identity",
			Action:  "agent_identity_revoked",
			Subject: identityID,
		})
	}

	if p.syncBus != nil {
		sig := &core.Signal{
			Type: "identity_event",
			Payload: map[string]interface{}{
				"action":      "revoked",
				"identity_id": identityID,
			},
		}
		if err := p.syncBus.Flash(ctx, sig); err != nil {
			slog.Error("agent: signal flash failed on revoke", "error", err, "identity_id", identityID)
			spanError(span, err)
			return fmt.Errorf("agent: flashing revocation signal: %w", err)
		}
	}

	return nil
}

func (p *Provider) validateRequest(req *core.AgentIdentityRequest) error {
	if req.AgentName == "" {
		return ErrMissingAgentName
	}
	if _, ok := validPlatforms[req.Platform]; !ok {
		return fmt.Errorf("%w: got %q", ErrInvalidPlatform, req.Platform)
	}
	if len(req.Capabilities) == 0 {
		return ErrEmptyCapabilities
	}
	return nil
}

func (p *Provider) resolveTrustDomain(req *core.AgentIdentityRequest) string {
	if p.devMode {
		return "dev.local"
	}

	// Platform-specific trust domain resolution via metadata hint.
	if td, ok := req.Metadata["trust_domain"]; ok && td != "" {
		if _, exists := p.trustDomains[td]; exists {
			return td
		}
	}

	// Fall back to first configured trust domain.
	for name := range p.trustDomains {
		return name
	}

	return "dev.local"
}

func (p *Provider) mintToken(sub string, req *core.AgentIdentityRequest, td string, now, exp time.Time) ([]byte, error) {
	builder := jwt.NewBuilder().
		Subject(sub).
		Issuer(p.issuer).
		IssuedAt(now).
		Expiration(exp)

	tok, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("building JWT: %w", err)
	}

	if err := tok.Set("td", td); err != nil {
		return nil, fmt.Errorf("setting td: %w", err)
	}
	if err := tok.Set("agent_platform", req.Platform); err != nil {
		return nil, fmt.Errorf("setting agent_platform: %w", err)
	}
	if err := tok.Set("caps", req.Capabilities); err != nil {
		return nil, fmt.Errorf("setting caps: %w", err)
	}
	if req.MaxBlastRadius != "" {
		if err := tok.Set("blast_radius", req.MaxBlastRadius); err != nil {
			return nil, fmt.Errorf("setting blast_radius: %w", err)
		}
	}
	if req.OnBehalfOf != "" {
		if err := tok.Set("obo", req.OnBehalfOf); err != nil {
			return nil, fmt.Errorf("setting obo: %w", err)
		}
	}
	if req.DelegationDepth > 0 {
		if err := tok.Set("delegation_depth", req.DelegationDepth); err != nil {
			return nil, fmt.Errorf("setting delegation_depth: %w", err)
		}
	}

	return jwt.Sign(tok, jwt.WithKey(jwa.RS256(), p.signKey))
}

func spanError(span trace.Span, err error) {
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}
