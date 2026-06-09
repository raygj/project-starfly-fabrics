package signals

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

const transmitterTracerName = "github.com/starfly-fabrics/starfly/pkg/signals/transmitter"

// Transmitter signs and delivers Security Event Tokens (SETs) to configured
// SSF stream receivers. It manages stream lifecycle and routes events to
// matching streams based on event type subscriptions.
type Transmitter struct {
	mu      sync.RWMutex
	streams map[string]*streamState

	signKey  jwk.Key
	issuer   string
	syncBus  core.SyncBus
	auditor  core.Auditor
	store    core.Store
	unitID   string
	client   *http.Client
}

// streamState tracks an active SSF stream and its configuration.
type streamState struct {
	stream  core.Stream
	config  core.StreamConfig
	created time.Time
}

// TransmitterOption configures the Transmitter.
type TransmitterOption func(*Transmitter)

// WithTransmitterSyncBus injects the sync bus for cross-unit signal propagation.
func WithTransmitterSyncBus(bus core.SyncBus, unitID string) TransmitterOption {
	return func(t *Transmitter) {
		t.syncBus = bus
		t.unitID = unitID
	}
}

// WithTransmitterAuditor injects an auditor for logging signal events.
func WithTransmitterAuditor(a core.Auditor) TransmitterOption {
	return func(t *Transmitter) { t.auditor = a }
}

// WithTransmitterStore injects a store for persisting stream state.
func WithTransmitterStore(s core.Store) TransmitterOption {
	return func(t *Transmitter) { t.store = s }
}

// WithTransmitterIssuer sets the issuer URI for signed SETs.
func WithTransmitterIssuer(issuer string) TransmitterOption {
	return func(t *Transmitter) { t.issuer = issuer }
}

// WithTransmitterHTTPTimeout sets the HTTP client timeout for SET delivery.
// Defaults to 10 seconds.
func WithTransmitterHTTPTimeout(d time.Duration) TransmitterOption {
	return func(t *Transmitter) { t.client = &http.Client{Timeout: d} }
}

// NewTransmitter creates a Transmitter with an ephemeral RSA-2048 signing key.
func NewTransmitter(opts ...TransmitterOption) (*Transmitter, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating SET signing key: %w", err)
	}

	key, err := jwk.Import(privKey)
	if err != nil {
		return nil, fmt.Errorf("importing SET signing key: %w", err)
	}
	if err := key.Set(jwk.KeyIDKey, "starfly-ssf-1"); err != nil {
		return nil, fmt.Errorf("setting kid: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		return nil, fmt.Errorf("setting alg: %w", err)
	}

	tx := &Transmitter{
		streams: make(map[string]*streamState),
		signKey: key,
		issuer:  "starfly",
		client:  core.NewDefaultHTTPClient(),
	}
	for _, opt := range opts {
		opt(tx)
	}

	slog.Info("SSF transmitter initialized", "issuer", tx.issuer, "kid", "starfly-ssf-1")
	return tx, nil
}

// PublicKeySet returns the JWKS containing the transmitter's public signing key.
// Receivers use this to verify SETs.
func (tx *Transmitter) PublicKeySet() (jwk.Set, error) {
	pub, err := tx.signKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("extracting public key: %w", err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		return nil, fmt.Errorf("adding key to set: %w", err)
	}
	return set, nil
}

// CreateStream creates a new SSF stream for a receiver. Returns the stream
// with a generated ID and the events that will actually be delivered
// (intersection of requested events and supported events).
func (tx *Transmitter) CreateStream(ctx context.Context, cfg *core.StreamConfig) (*core.Stream, error) {
	_, span := otel.Tracer(transmitterTracerName).Start(ctx, "transmitter.CreateStream")
	defer span.End()

	if cfg.Audience == "" {
		return nil, fmt.Errorf("stream config must have an audience")
	}

	if cfg.EndpointURL != "" {
		u, err := url.Parse(cfg.EndpointURL)
		if err != nil {
			return nil, fmt.Errorf("invalid endpoint URL: %w", err)
		}
		if u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
			return nil, fmt.Errorf("stream endpoint must use HTTPS: %s", cfg.EndpointURL)
		}
	}

	streamID := generateJTI() // reuse JTI generator for unique IDs

	// Determine events to deliver: intersection of requested and supported.
	supported := EventTypes()
	supportedSet := make(map[string]bool, len(supported))
	for _, et := range supported {
		supportedSet[et] = true
	}

	var delivered []string
	for _, req := range cfg.EventsRequested {
		if supportedSet[req] {
			delivered = append(delivered, req)
		}
	}
	if len(delivered) == 0 {
		delivered = supported // default: all supported events
	}

	stream := core.Stream{
		ID:              streamID,
		Issuer:          tx.issuer,
		Audience:        cfg.Audience,
		EventsSupported: supported,
		Status:          StreamStatusEnabled,
	}

	tx.mu.Lock()
	tx.streams[streamID] = &streamState{
		stream:  stream,
		config:  *cfg,
		created: time.Now().UTC(),
	}
	tx.mu.Unlock()

	span.SetAttributes(
		attribute.String("stream_id", streamID),
		attribute.String("audience", cfg.Audience),
		attribute.Int("events_delivered", len(delivered)),
	)

	tx.audit(ctx, "signal", "stream_created", streamID, cfg.Audience)

	slog.Info("SSF stream created",
		"stream_id", streamID,
		"audience", cfg.Audience,
		"events_delivered", len(delivered),
	)

	return &stream, nil
}

// DeleteStream removes a stream and stops event delivery.
func (tx *Transmitter) DeleteStream(ctx context.Context, streamID string) error {
	_, span := otel.Tracer(transmitterTracerName).Start(ctx, "transmitter.DeleteStream")
	defer span.End()

	span.SetAttributes(attribute.String("stream_id", streamID))

	tx.mu.Lock()
	state, ok := tx.streams[streamID]
	if !ok {
		tx.mu.Unlock()
		return fmt.Errorf("stream not found: %s", streamID)
	}
	delete(tx.streams, streamID)
	tx.mu.Unlock()

	tx.audit(ctx, "signal", "stream_deleted", streamID, state.config.Audience)
	return nil
}

// GetStreamStatus returns the current status of a stream.
func (tx *Transmitter) GetStreamStatus(ctx context.Context, streamID string) (*core.StreamStatus, error) {
	_, span := otel.Tracer(transmitterTracerName).Start(ctx, "transmitter.GetStreamStatus")
	defer span.End()

	tx.mu.RLock()
	state, ok := tx.streams[streamID]
	tx.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("stream not found: %s", streamID)
	}

	return &core.StreamStatus{
		StreamID: streamID,
		Status:   state.stream.Status,
	}, nil
}

// TransmitEvent signs the event as a SET and delivers it to all matching
// streams. Delivery is fire-and-forget per stream — failures are logged
// but don't block other streams. Also flashes to the sync bus if configured.
func (tx *Transmitter) TransmitEvent(ctx context.Context, event *core.SecurityEvent) error {
	ctx, span := otel.Tracer(transmitterTracerName).Start(ctx, "transmitter.TransmitEvent")
	defer span.End()

	if event.JTI == "" {
		event.JTI = generateJTI()
	}
	if event.IssuedAt == 0 {
		event.IssuedAt = time.Now().Unix()
	}
	if event.Issuer == "" {
		event.Issuer = tx.issuer
	}

	// Sign the event as a SET (JWT).
	signed, err := tx.signSET(event)
	if err != nil {
		telemetry.SpanError(span, err)
		return fmt.Errorf("signing SET: %w", err)
	}

	span.SetAttributes(
		attribute.String("event.jti", event.JTI),
		attribute.Int("event.event_count", len(event.Events)),
	)

	// Determine which event types are in this SET.
	eventTypes := make([]string, 0, len(event.Events))
	for et := range event.Events {
		eventTypes = append(eventTypes, et)
	}

	// Deliver to matching streams.
	tx.mu.RLock()
	streams := make([]*streamState, 0, len(tx.streams))
	for _, s := range tx.streams {
		if s.stream.Status == StreamStatusEnabled {
			streams = append(streams, s)
		}
	}
	tx.mu.RUnlock()

	var delivered int
	for _, s := range streams {
		if s.config.EndpointURL == "" {
			continue
		}
		if s.config.DeliveryMethod != "" && s.config.DeliveryMethod != "push" {
			continue // only push delivery for now
		}

		go tx.deliverSET(ctx, s, signed, event.JTI)
		delivered++
	}

	span.SetAttributes(attribute.Int("streams_delivered", delivered))

	// Flash to sync bus for cross-unit propagation.
	if tx.syncBus != nil {
		sig := &core.Signal{
			Type:   "caep_signal",
			Source: tx.unitID,
			Payload: map[string]interface{}{
				"jti":         event.JTI,
				"event_types": eventTypes,
			},
		}
		if err := tx.syncBus.Flash(ctx, sig); err != nil {
			slog.Error("sync bus flash failed for SET", "error", err, "jti", event.JTI)
		}
	}

	tx.audit(ctx, "signal", "event_transmitted", event.JTI, event.Audience)
	return nil
}

// signSET creates a signed JWT (SET) from a SecurityEvent.
func (tx *Transmitter) signSET(event *core.SecurityEvent) ([]byte, error) {
	now := time.Now().UTC()

	builder := jwt.NewBuilder().
		Issuer(event.Issuer).
		Audience([]string{event.Audience}).
		IssuedAt(now).
		JwtID(event.JTI)

	token, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("building SET JWT: %w", err)
	}

	// Set SSF-specific claims.
	if event.SubjectID != nil {
		if err := token.Set("sub_id", event.SubjectID); err != nil {
			return nil, fmt.Errorf("setting sub_id: %w", err)
		}
	}
	if err := token.Set("events", event.Events); err != nil {
		return nil, fmt.Errorf("setting events: %w", err)
	}
	if event.TransactionID != "" {
		if err := token.Set("txn", event.TransactionID); err != nil {
			return nil, fmt.Errorf("setting txn: %w", err)
		}
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), tx.signKey))
	if err != nil {
		return nil, fmt.Errorf("signing SET: %w", err)
	}

	return signed, nil
}

// deliverSET sends a signed SET to a stream's endpoint via HTTP POST.
// Fire-and-forget: errors are logged but don't propagate.
func (tx *Transmitter) deliverSET(ctx context.Context, s *streamState, signed []byte, jti string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.EndpointURL, bytes.NewReader(signed))
	if err != nil {
		slog.Error("creating SET delivery request", "error", err, "endpoint", s.config.EndpointURL)
		return
	}
	req.Header.Set("Content-Type", "application/secevent+jwt")

	resp, err := tx.client.Do(req)
	if err != nil {
		slog.Error("SET delivery failed", "error", err, "stream_id", s.stream.ID, "endpoint", s.config.EndpointURL)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		slog.Debug("SET delivered", "stream_id", s.stream.ID, "jti", jti, "status", resp.StatusCode)
	} else {
		slog.Warn("SET delivery non-success", "stream_id", s.stream.ID, "jti", jti, "status", resp.StatusCode)
	}
}

// StreamCount returns the number of active streams.
func (tx *Transmitter) StreamCount() int {
	tx.mu.RLock()
	defer tx.mu.RUnlock()
	return len(tx.streams)
}

// ListStreams returns a snapshot of all active streams and their configurations.
// Used by the operator's InProcessConnection to assemble the current soul manifest.
func (tx *Transmitter) ListStreams() []StreamInfo {
	tx.mu.RLock()
	defer tx.mu.RUnlock()
	infos := make([]StreamInfo, 0, len(tx.streams))
	for _, s := range tx.streams {
		infos = append(infos, StreamInfo{
			StreamID:        s.stream.ID,
			Audience:        s.stream.Audience,
			Status:          s.stream.Status,
			EventsRequested: s.config.EventsRequested,
			EndpointURL:     s.config.EndpointURL,
			Created:         s.created,
		})
	}
	return infos
}

// StreamInfo is a read-only snapshot of an active stream's state.
type StreamInfo struct {
	StreamID        string
	Audience        string
	Status          string
	EventsRequested []string
	EndpointURL     string
	Created         time.Time
}

// audit logs an audit event if an auditor is configured.
func (tx *Transmitter) audit(ctx context.Context, typ, action, subject, target string) {
	if tx.auditor == nil {
		return
	}
	_ = tx.auditor.Log(ctx, &core.AuditEvent{
		Type:    typ,
		Action:  action,
		Subject: subject,
		Target:  target,
		UnitID:  tx.unitID,
	})
}
