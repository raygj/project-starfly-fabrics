package signals

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

const receiverTracerName = "github.com/starfly-fabrics/starfly/pkg/signals/receiver"

// Sentinel errors for receiver operations.
var (
	ErrUnknownIssuer = fmt.Errorf("unknown SET issuer")
	ErrInvalidSET    = fmt.Errorf("invalid SET")
	ErrSignalDenied  = fmt.Errorf("signal denied by policy")
	ErrDuplicateJTI  = fmt.Errorf("duplicate JTI")
)

const (
	defaultJTITTL      = 24 * time.Hour
	jtiCleanupInterval = 256 // prune expired JTIs every N insertions
)

// Receiver validates incoming Security Event Tokens (SETs), evaluates policy,
// and routes events to the sync bus and revocation index.
type Receiver struct {
	jwksResolver core.JWKSResolver
	policy       core.PolicyEngine
	syncBus      core.SyncBus
	auditor      core.Auditor
	revocation   *InMemoryRevocationIndex
	unitID       string
	devMode      bool

	// revocationGrace is the grace period added to token expiry for revocation entries.
	revocationGrace time.Duration

	// onSignal is an optional callback invoked after a signal is successfully processed.
	onSignal func(eventType, subject, result string)

	// jtiSeen deduplicates incoming SET JTIs. keyed by JTI, value is expiry.
	jtiSeen      map[string]time.Time
	jtiMu        sync.Mutex
	jtiTTL       time.Duration
	jtiWriteCount int
}

// ReceiverOption configures the Receiver.
type ReceiverOption func(*Receiver)

// WithReceiverJWKS injects the JWKS resolver for SET signature verification.
func WithReceiverJWKS(r core.JWKSResolver) ReceiverOption {
	return func(rx *Receiver) { rx.jwksResolver = r }
}

// WithReceiverPolicy injects the policy engine for signal evaluation.
func WithReceiverPolicy(p core.PolicyEngine) ReceiverOption {
	return func(rx *Receiver) { rx.policy = p }
}

// WithReceiverSyncBus injects the sync bus for cross-unit propagation.
func WithReceiverSyncBus(bus core.SyncBus, unitID string) ReceiverOption {
	return func(rx *Receiver) {
		rx.syncBus = bus
		rx.unitID = unitID
	}
}

// WithReceiverAuditor injects an auditor for logging.
func WithReceiverAuditor(a core.Auditor) ReceiverOption {
	return func(rx *Receiver) { rx.auditor = a }
}

// WithReceiverRevocation injects the revocation index for token revocation tracking.
func WithReceiverRevocation(idx *InMemoryRevocationIndex) ReceiverOption {
	return func(rx *Receiver) { rx.revocation = idx }
}

// WithReceiverDevMode enables dev mode (skips SET signature verification).
func WithReceiverDevMode(dev bool) ReceiverOption {
	return func(rx *Receiver) { rx.devMode = dev }
}

// WithReceiverOnSignal sets an optional callback invoked after a signal is processed.
func WithReceiverOnSignal(fn func(eventType, subject, result string)) ReceiverOption {
	return func(rx *Receiver) { rx.onSignal = fn }
}

// WithReceiverRevocationGrace sets the grace period added to token expiry for
// revocation entries. Defaults to 1 hour.
func WithReceiverRevocationGrace(d time.Duration) ReceiverOption {
	return func(rx *Receiver) { rx.revocationGrace = d }
}

// WithReceiverJTITTL sets the TTL for the JTI deduplication store.
// Defaults to 24 hours. Set to 0 to disable deduplication.
func WithReceiverJTITTL(d time.Duration) ReceiverOption {
	return func(rx *Receiver) { rx.jtiTTL = d }
}

// NewReceiver creates a Receiver with the given options.
func NewReceiver(opts ...ReceiverOption) *Receiver {
	rx := &Receiver{
		revocationGrace: 1 * time.Hour,
		jtiTTL:          defaultJTITTL,
		jtiSeen:         make(map[string]time.Time),
	}
	for _, opt := range opts {
		opt(rx)
	}
	slog.Info("SSF receiver initialized", "dev_mode", rx.devMode, "unit_id", rx.unitID)
	return rx
}

// checkAndMarkJTI returns ErrDuplicateJTI if jti was already seen within TTL.
// On first sight it records the JTI and lazily prunes expired entries.
func (rx *Receiver) checkAndMarkJTI(jti string) error {
	if rx.jtiTTL == 0 || jti == "" {
		return nil
	}
	now := time.Now()
	rx.jtiMu.Lock()
	defer rx.jtiMu.Unlock()
	if exp, seen := rx.jtiSeen[jti]; seen && now.Before(exp) {
		return fmt.Errorf("%w: %s", ErrDuplicateJTI, jti)
	}
	rx.jtiSeen[jti] = now.Add(rx.jtiTTL)
	rx.jtiWriteCount++
	if rx.jtiWriteCount >= jtiCleanupInterval {
		for k, exp := range rx.jtiSeen {
			if now.After(exp) {
				delete(rx.jtiSeen, k)
			}
		}
		rx.jtiWriteCount = 0
	}
	return nil
}

// ReceiveEvent validates an incoming SET, evaluates signal policy, and routes
// the event. If the event triggers revocation (per policy), entries are added
// to the revocation index.
func (rx *Receiver) ReceiveEvent(ctx context.Context, event *core.SecurityEvent) error {
	ctx, span := otel.Tracer(receiverTracerName).Start(ctx, "receiver.ReceiveEvent")
	defer span.End()

	if event == nil {
		return fmt.Errorf("%w: nil event", ErrInvalidSET)
	}
	if len(event.Events) == 0 {
		return fmt.Errorf("%w: no events in SET", ErrInvalidSET)
	}
	if err := rx.checkAndMarkJTI(event.JTI); err != nil {
		telemetry.SpanError(span, err)
		return err
	}

	span.SetAttributes(
		attribute.String("event.jti", event.JTI),
		attribute.String("event.issuer", event.Issuer),
		attribute.Int("event.event_count", len(event.Events)),
	)

	// Evaluate signal policy.
	if rx.policy != nil {
		decision, err := rx.evaluatePolicy(ctx, event)
		if err != nil {
			telemetry.SpanError(span, err)
			return fmt.Errorf("evaluating signal policy: %w", err)
		}
		if !decision.Allowed {
			rx.audit(ctx, "signal", "event_denied", event.JTI, event.Issuer, "denied", decision.Reason)
			err := fmt.Errorf("%w: %s", ErrSignalDenied, decision.Reason)
			telemetry.SpanError(span, err)
			return err
		}

		// Check if policy says to revoke tokens.
		if shouldRevoke, ok := decision.Claims["revoke_tokens"]; ok {
			if revoke, isBool := shouldRevoke.(bool); isBool && revoke {
				rx.handleRevocation(ctx, event)
			}
		}
	}

	// Propagate to sync bus if configured and policy allows.
	if rx.syncBus != nil {
		eventTypes := make([]string, 0, len(event.Events))
		for et := range event.Events {
			eventTypes = append(eventTypes, et)
		}

		sig := &core.Signal{
			Type:   "caep_signal",
			Source: rx.unitID,
			Payload: map[string]interface{}{
				"jti":         event.JTI,
				"issuer":      event.Issuer,
				"event_types": eventTypes,
				"action":      "received",
			},
		}
		if err := rx.syncBus.Flash(ctx, sig); err != nil {
			slog.Error("sync bus flash failed for received SET", "error", err, "jti", event.JTI)
		}
	}

	rx.audit(ctx, "signal", "event_received", event.JTI, event.Issuer, "allowed", "")

	// Notify callback (SSE broadcaster, etc.)
	if rx.onSignal != nil {
		subjectID := event.Issuer
		if event.SubjectID != nil {
			if event.SubjectID.URI != "" {
				subjectID = event.SubjectID.URI
			} else if event.SubjectID.SpiffeID != "" {
				subjectID = event.SubjectID.SpiffeID
			}
		}
		for et := range event.Events {
			rx.onSignal(et, subjectID, "accepted")
			break
		}
	}

	return nil
}

// ReceiveSET validates a raw signed SET (JWT bytes), verifies the signature
// using the JWKS resolver, parses it into a SecurityEvent, and processes it.
func (rx *Receiver) ReceiveSET(ctx context.Context, rawSET []byte) error {
	ctx, span := otel.Tracer(receiverTracerName).Start(ctx, "receiver.ReceiveSET")
	defer span.End()

	event, err := rx.parseSET(ctx, rawSET)
	if err != nil {
		telemetry.SpanError(span, err)
		return err
	}

	return rx.ReceiveEvent(ctx, event)
}

// parseSET validates and parses a raw SET JWT. In dev mode, signature
// verification is skipped.
func (rx *Receiver) parseSET(ctx context.Context, rawSET []byte) (*core.SecurityEvent, error) {
	var token jwt.Token
	var err error

	if rx.devMode {
		token, err = jwt.ParseInsecure(rawSET)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSET, err)
		}
	} else {
		if rx.jwksResolver == nil {
			return nil, fmt.Errorf("%w: no JWKS resolver configured", ErrInvalidSET)
		}

		// Extract issuer and kid from the JWT without verification first.
		insecure, parseErr := jwt.ParseInsecure(rawSET)
		if parseErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSET, parseErr)
		}

		issuer, _ := insecure.Issuer()
		if issuer == "" {
			return nil, fmt.Errorf("%w: missing issuer", ErrInvalidSET)
		}

		// Extract kid from JWS header.
		msg, jwtErr := jws.Parse(rawSET)
		if jwtErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSET, jwtErr)
		}
		sigs := msg.Signatures()
		if len(sigs) == 0 {
			return nil, fmt.Errorf("%w: no signatures", ErrInvalidSET)
		}
		kid, _ := sigs[0].ProtectedHeaders().KeyID()

		// Resolve the public key from the issuer's JWKS.
		pubKey, resolveErr := rx.jwksResolver.ResolveKey(ctx, issuer, kid)
		if resolveErr != nil {
			return nil, fmt.Errorf("%w: resolving key for issuer %s: %v", ErrUnknownIssuer, issuer, resolveErr)
		}

		jwkKey, importErr := jwk.Import(pubKey)
		if importErr != nil {
			return nil, fmt.Errorf("%w: importing resolved key: %v", ErrInvalidSET, importErr)
		}

		alg, _ := sigs[0].ProtectedHeaders().Algorithm()
		token, err = jwt.Parse(rawSET, jwt.WithKey(alg, jwkKey))
		if err != nil {
			return nil, fmt.Errorf("%w: signature verification failed: %v", ErrInvalidSET, err)
		}
	}

	// Build SecurityEvent from the validated JWT.
	issuer, _ := token.Issuer()
	jti, _ := token.JwtID()
	iat, _ := token.IssuedAt()
	aud, _ := token.Audience()

	audience := ""
	if len(aud) > 0 {
		audience = aud[0]
	}

	event := &core.SecurityEvent{
		Issuer:   issuer,
		JTI:      jti,
		IssuedAt: iat.Unix(),
		Audience: audience,
		Events:   make(map[string]map[string]interface{}),
	}

	// Extract sub_id claim.
	var subID map[string]interface{}
	if err := token.Get("sub_id", &subID); err == nil {
		event.SubjectID = &core.SubjectIdentifier{}
		if f, ok := subID["format"].(string); ok {
			event.SubjectID.Format = f
		}
		if s, ok := subID["spiffe_id"].(string); ok {
			event.SubjectID.SpiffeID = s
		}
		if u, ok := subID["uri"].(string); ok {
			event.SubjectID.URI = u
		}
		if e, ok := subID["email"].(string); ok {
			event.SubjectID.Email = e
		}
	}

	// Extract events claim.
	var events map[string]interface{}
	if err := token.Get("events", &events); err == nil {
		for eventType, eventData := range events {
			if eventMap, ok := eventData.(map[string]interface{}); ok {
				event.Events[eventType] = eventMap
			} else {
				event.Events[eventType] = map[string]interface{}{}
			}
		}
	}

	// Extract txn claim.
	var txn string
	if err := token.Get("txn", &txn); err == nil {
		event.TransactionID = txn
	}

	return event, nil
}

// evaluatePolicy builds a PolicyInput from the SecurityEvent and evaluates it.
func (rx *Receiver) evaluatePolicy(ctx context.Context, event *core.SecurityEvent) (*core.PolicyDecision, error) {
	// Build a synthetic WorkloadIdentity from the event subject.
	subject := &core.WorkloadIdentity{
		ID: event.Issuer,
	}
	if event.SubjectID != nil {
		if event.SubjectID.SpiffeID != "" {
			subject.ID = event.SubjectID.SpiffeID
		} else if event.SubjectID.URI != "" {
			subject.ID = event.SubjectID.URI
		}
		subject.Attestation = &core.AttestationEvidence{
			Method:    "ssf-event",
			Timestamp: time.Now().UTC(),
		}
	}

	// Gather event types for policy context.
	eventTypes := make([]string, 0, len(event.Events))
	for et := range event.Events {
		eventTypes = append(eventTypes, et)
	}

	policyCtx := map[string]interface{}{
		"event_types": eventTypes,
		"jti":         event.JTI,
	}

	// Add first event's claims to context for policy evaluation.
	for _, eventData := range event.Events {
		for k, v := range eventData {
			policyCtx[k] = v
		}
		break // only use first event for policy context
	}

	input := &core.PolicyInput{
		Action:  "signal",
		Subject: subject,
		Target:  event.Audience,
		Context: policyCtx,
	}

	return rx.policy.Evaluate(ctx, input)
}

// handleRevocation adds revocation entries for the event's subject.
func (rx *Receiver) handleRevocation(ctx context.Context, event *core.SecurityEvent) {
	if rx.revocation == nil {
		return
	}

	subjectID := ""
	if event.SubjectID != nil {
		if event.SubjectID.SpiffeID != "" {
			subjectID = event.SubjectID.SpiffeID
		} else if event.SubjectID.URI != "" {
			subjectID = event.SubjectID.URI
		}
	}
	if subjectID == "" {
		slog.Warn("cannot revoke: no subject identifier in event", "jti", event.JTI)
		return
	}

	reason := "caep-event"
	for eventType := range event.Events {
		reason = eventType
		break
	}

	expiresAt := time.Now().Add(rx.revocationGrace)
	if err := rx.revocation.Revoke(ctx, subjectID, reason, expiresAt); err != nil {
		slog.Error("revocation failed", "error", err, "subject_id", subjectID, "jti", event.JTI)
		return
	}

	rx.audit(ctx, "signal", "token_revoked", subjectID, event.Issuer, "allowed", reason)
	slog.Info("subject revoked via CAEP", "subject_id", subjectID, "reason", reason, "jti", event.JTI)
}

// audit logs an audit event if an auditor is configured.
func (rx *Receiver) audit(ctx context.Context, typ, action, subject, target, decision, reason string) {
	if rx.auditor == nil {
		return
	}
	_ = rx.auditor.Log(ctx, &core.AuditEvent{
		Type:     typ,
		Action:   action,
		Subject:  subject,
		Target:   target,
		Decision: decision,
		Reason:   reason,
		UnitID:   rx.unitID,
	})
}
