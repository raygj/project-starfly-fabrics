package audit

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// SignedAuditEvent wraps an AuditEvent with a cryptographic signature
// for tamper detection.
type SignedAuditEvent struct {
	Event     *core.AuditEvent `json:"event"`
	Signature string           `json:"signature"` // hex-encoded HMAC-SHA256
}

// SigningLogger is a structured audit logger that signs every event with
// HMAC-SHA256 before writing. It implements core.Auditor.
type SigningLogger struct {
	w   *bufio.Writer
	mu  sync.Mutex
	enc *json.Encoder
	key []byte
}

// Compile-time check: SigningLogger implements core.Auditor.
var _ core.Auditor = (*SigningLogger)(nil)

// NewSigningLogger creates a SigningLogger that writes HMAC-signed JSON
// audit events to w. The key is the HMAC-SHA256 signing key.
func NewSigningLogger(w io.Writer, key []byte) *SigningLogger {
	bw := bufio.NewWriter(w)
	return &SigningLogger{
		w:   bw,
		enc: json.NewEncoder(bw),
		key: key,
	}
}

// Log records a signed audit event. The event is serialized to JSON,
// signed with HMAC-SHA256, and written as a SignedAuditEvent.
func (l *SigningLogger) Log(ctx context.Context, event *core.AuditEvent) error {
	_, span := otel.Tracer(tracerName).Start(ctx, "audit.SignedLog")
	defer span.End()

	span.SetAttributes(
		attribute.String("event.type", event.Type),
		attribute.String("event.action", event.Action),
		attribute.Bool("signed", true),
	)

	l.mu.Lock()
	defer l.mu.Unlock()

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Serialize the event to compute the signature.
	eventJSON, err := json.Marshal(event)
	if err != nil {
		telemetry.SpanError(span, err)
		return fmt.Errorf("marshaling event for signing: %w", err)
	}

	sig := computeHMAC(eventJSON, l.key)

	signed := SignedAuditEvent{
		Event:     event,
		Signature: hex.EncodeToString(sig),
	}

	if err := l.enc.Encode(signed); err != nil {
		telemetry.SpanError(span, err)
		return err
	}
	return nil
}

// Close flushes any buffered data to the underlying writer.
func (l *SigningLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Flush()
}

// VerifySignedEvent checks whether a SignedAuditEvent's signature is valid
// for the given HMAC key. Returns nil if valid, an error if tampered or
// malformed.
func VerifySignedEvent(signed *SignedAuditEvent, key []byte) error {
	eventJSON, err := json.Marshal(signed.Event)
	if err != nil {
		return fmt.Errorf("marshaling event for verification: %w", err)
	}

	sigBytes, err := hex.DecodeString(signed.Signature)
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}

	expected := computeHMAC(eventJSON, key)
	if !hmac.Equal(sigBytes, expected) {
		return fmt.Errorf("signature verification failed: event has been tampered with")
	}
	return nil
}

// computeHMAC computes HMAC-SHA256 over data with the given key.
func computeHMAC(data, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
