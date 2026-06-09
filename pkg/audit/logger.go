package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

const tracerName = "github.com/starfly-fabrics/starfly/pkg/audit"

// Logger is a structured audit logger that writes AuditEvents as
// newline-delimited JSON. It is safe for concurrent use.
type Logger struct {
	w   *bufio.Writer
	mu  sync.Mutex
	enc *json.Encoder
}

// Compile-time check: Logger implements core.Auditor.
var _ core.Auditor = (*Logger)(nil)

// New creates a Logger that writes JSON audit events to w.
func New(w io.Writer) *Logger {
	bw := bufio.NewWriter(w)
	return &Logger{
		w:   bw,
		enc: json.NewEncoder(bw),
	}
}

// Log records an audit event as a single JSON line. If the event's
// Timestamp is zero it is set to the current UTC time.
func (l *Logger) Log(ctx context.Context, event *core.AuditEvent) error {
	_, span := otel.Tracer(tracerName).Start(ctx, "audit.Log")
	defer span.End()

	span.SetAttributes(
		attribute.String("event.type", event.Type),
		attribute.String("event.action", event.Action),
	)

	l.mu.Lock()
	defer l.mu.Unlock()

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	if err := l.enc.Encode(event); err != nil {
		telemetry.SpanError(span, err)
		return err
	}
	return nil
}

// Close flushes any buffered data to the underlying writer.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.w.Flush()
}
