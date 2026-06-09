package kerberos

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	tracerName = "github.com/starfly-fabrics/starfly/pkg/identity/kerberos"
	credType   = "kerberos"
)

var _ core.IdentityProvider = (*Provider)(nil)

type replayEntry struct {
	expiresAt time.Time
}

// Provider validates Kerberos service tickets and returns WorkloadIdentity.
type Provider struct {
	trustDomains map[string]core.TrustDomain
	keytabPath   string
	kt           *keytab.Keytab
	devMode      bool
	replayCache  sync.Map      // key: string (sha256 of AP-REQ), value: replayEntry
	replayWindow time.Duration // how long to remember seen authenticators
}

// Option configures the Provider.
type Option func(*Provider)

// WithTrustDomains maps Kerberos realms to WIMSE trust domains.
func WithTrustDomains(domains []core.TrustDomain) Option {
	return func(p *Provider) {
		for _, d := range domains {
			if d.Enabled {
				p.trustDomains[d.Name] = d
			}
		}
	}
}

// WithKeytabPath sets the path to the Kerberos keytab file for ticket decryption.
func WithKeytabPath(path string) Option {
	return func(p *Provider) { p.keytabPath = path }
}

// WithDevMode enables development mode (skips ticket crypto validation).
func WithDevMode(dev bool) Option {
	return func(p *Provider) { p.devMode = dev }
}

// WithReplayWindow sets how long seen authenticators are remembered. Defaults to 5 minutes.
func WithReplayWindow(d time.Duration) Option {
	return func(p *Provider) { p.replayWindow = d }
}

// NewProvider creates a Kerberos identity provider.
func NewProvider(opts ...Option) (*Provider, error) {
	p := &Provider{
		trustDomains: make(map[string]core.TrustDomain),
	}
	for _, opt := range opts {
		opt(p)
	}
	if !p.devMode && p.keytabPath != "" {
		kt, err := keytab.Load(p.keytabPath)
		if err != nil {
			return nil, fmt.Errorf("loading keytab: %w", err)
		}
		p.kt = kt
	}
	return p, nil
}

// ValidateWorkload validates a base64-encoded Kerberos AP-REQ or (in dev mode)
// a base64-encoded principal name, and returns a WIMSE WorkloadIdentity.
func (p *Provider) ValidateWorkload(ctx context.Context, credential string, ct string) (*core.WorkloadIdentity, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "identity.kerberos.ValidateWorkload")
	defer span.End()

	if ct != credType {
		err := fmt.Errorf("unsupported credential type: %s", ct)
		telemetry.SpanError(span, err)
		return nil, err
	}

	raw, err := base64.StdEncoding.DecodeString(credential)
	if err != nil {
		err = fmt.Errorf("malformed base64 credential: %w", err)
		telemetry.SpanError(span, err)
		return nil, err
	}

	if p.devMode {
		return p.devModeValidate(span, string(raw))
	}

	return p.prodValidate(ctx, span, raw)
}

func (p *Provider) devModeValidate(span trace.Span, principal string) (*core.WorkloadIdentity, error) {
	if principal == "" {
		return nil, fmt.Errorf("empty principal in dev mode credential")
	}

	realm := "DEV.LOCAL"
	if parts := strings.SplitN(principal, "@", 2); len(parts) == 2 {
		realm = parts[1]
		principal = parts[0]
	}

	span.SetAttributes(
		attribute.String("kerberos.principal", principal),
		attribute.String("kerberos.realm", realm),
	)

	wimseURI := fmt.Sprintf("wimse://dev.local/kerberos/%s", principal)
	return &core.WorkloadIdentity{
		ID:          wimseURI,
		TrustDomain: "dev.local",
		Attestation: &core.AttestationEvidence{
			Method:    credType,
			Timestamp: time.Now().UTC(),
		},
		Claims: map[string]interface{}{
			"principal": principal,
			"realm":     realm,
			"dev_mode":  true,
		},
	}, nil
}

func (p *Provider) prodValidate(ctx context.Context, span trace.Span, raw []byte) (*core.WorkloadIdentity, error) {
	if p.kt == nil {
		err := fmt.Errorf("no keytab configured for Kerberos validation")
		telemetry.SpanError(span, err)
		return nil, err
	}

	var apreq messages.APReq
	if err := apreq.Unmarshal(raw); err != nil {
		err = fmt.Errorf("malformed AP-REQ: %w", err)
		telemetry.SpanError(span, err)
		return nil, err
	}

	realm := apreq.Ticket.Realm
	span.SetAttributes(attribute.String("kerberos.realm", realm))

	if err := apreq.Ticket.DecryptEncPart(p.kt, nil); err != nil {
		err = fmt.Errorf("ticket decryption failed: %w", err)
		telemetry.SpanError(span, err)
		return nil, err
	}

	// Replay detection: hash the entire AP-REQ bytes as the cache key.
	h := sha256.Sum256(raw)
	replayKey := hex.EncodeToString(h[:])

	if _, loaded := p.replayCache.Load(replayKey); loaded {
		err := fmt.Errorf("kerberos AP-REQ replay detected")
		telemetry.SpanError(span, err)
		return nil, err
	}

	principal := composePrincipal(apreq.Ticket.DecryptedEncPart.CName, realm)
	span.SetAttributes(attribute.String("kerberos.principal", principal))

	realmLower := strings.ToLower(realm)
	domain, ok := p.trustDomains[realmLower]
	if !ok {
		err := fmt.Errorf("unknown Kerberos realm: %s", realm)
		telemetry.SpanError(span, err)
		return nil, err
	}

	wimseURI := fmt.Sprintf("wimse://%s/kerberos/%s", domain.Name, principal)

	// Store in replay cache after successful validation.
	window := p.replayWindow
	if window == 0 {
		window = 5 * time.Minute
	}
	p.replayCache.Store(replayKey, replayEntry{expiresAt: time.Now().Add(window)})

	_ = ctx

	return &core.WorkloadIdentity{
		ID:          wimseURI,
		TrustDomain: domain.Name,
		Attestation: &core.AttestationEvidence{
			Method:    credType,
			Timestamp: time.Now().UTC(),
		},
		Claims: map[string]interface{}{
			"principal": principal,
			"realm":     realm,
			"etype":     apreq.Ticket.DecryptedEncPart.Key.KeyType,
		},
	}, nil
}

// CleanupReplayCache removes expired entries from the replay cache and returns
// the number of entries removed.
func (p *Provider) CleanupReplayCache() int {
	now := time.Now()
	removed := 0
	p.replayCache.Range(func(key, value interface{}) bool {
		entry, ok := value.(replayEntry)
		if !ok {
			return true
		}
		if now.After(entry.expiresAt) {
			p.replayCache.Delete(key)
			removed++
		}
		return true
	})
	return removed
}

func composePrincipal(name types.PrincipalName, realm string) string {
	principal := strings.Join(name.NameString, "/")
	return principal + "@" + realm
}
