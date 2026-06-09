package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/starfly-fabrics/starfly/pkg/core"
)

const (
	streamName    = "STARFLY_SIGNALS"
	subjectPrefix = "starfly"
	maxAge        = 15 * time.Minute
)

// Bus implements core.SyncBus over an embedded or external NATS connection
// with JetStream for durable signal delivery.
type Bus struct {
	conn        *nats.Conn
	js          jetstream.JetStream
	srv         *server.Server // nil when using external NATS
	unitID      string
	trustDomain string
	ctx         context.Context
	cancel      context.CancelFunc
}

var _ core.SyncBus = (*Bus)(nil)

// New creates a Bus. In embedded mode it starts an in-process NATS server with
// JetStream enabled and no TCP listener. In external mode it connects to the
// configured NATS URL.
func New(cfg core.NATSConfig, unitID, trustDomain string) (*Bus, error) {
	b := &Bus{
		unitID:      unitID,
		trustDomain: trustDomain,
	}
	b.ctx, b.cancel = context.WithCancel(context.Background())

	if cfg.Embedded {
		opts := &server.Options{
			DontListen: true,
			JetStream:  true,
			StoreDir:   cfg.JetStreamDir,
		}
		srv, err := server.NewServer(opts)
		if err != nil {
			return nil, fmt.Errorf("creating embedded NATS server: %w", err)
		}
		srv.Start()
		if !srv.ReadyForConnections(5 * time.Second) {
			return nil, errors.New("embedded NATS server failed to become ready")
		}
		b.srv = srv

		nc, err := nats.Connect(nats.DefaultURL, nats.InProcessServer(srv))
		if err != nil {
			srv.Shutdown()
			return nil, fmt.Errorf("connecting to embedded NATS: %w", err)
		}
		b.conn = nc
	} else {
		if cfg.URL == "" {
			return nil, errors.New("nats.url must be set when embedded is false")
		}
		nc, err := nats.Connect(cfg.URL)
		if err != nil {
			return nil, fmt.Errorf("connecting to external NATS at %s: %w", cfg.URL, err)
		}
		b.conn = nc
	}

	js, err := jetstream.New(b.conn)
	if err != nil {
		b.conn.Close()
		if b.srv != nil {
			b.srv.Shutdown()
		}
		return nil, fmt.Errorf("creating JetStream context: %w", err)
	}
	b.js = js

	// Create or update the stream.
	_, err = js.CreateOrUpdateStream(context.Background(), jetstream.StreamConfig{
		Name:     streamName,
		Subjects: []string{subjectPrefix + ".>"},
		MaxAge:   maxAge,
	})
	if err != nil {
		b.conn.Close()
		if b.srv != nil {
			b.srv.Shutdown()
		}
		return nil, fmt.Errorf("creating JetStream stream %s: %w", streamName, err)
	}

	mode := "external"
	if cfg.Embedded {
		mode = "embedded"
	}
	slog.Info("sync bus ready",
		"mode", mode,
		"stream", streamName,
		"unit_id", unitID,
	)

	return b, nil
}

// Flash publishes a signal to the NATS subject for this trust domain.
func (b *Bus) Flash(ctx context.Context, signal *core.Signal) error {
	signal.Source = b.unitID
	if signal.Timestamp.IsZero() {
		signal.Timestamp = time.Now().UTC()
	}

	data, err := json.Marshal(signal)
	if err != nil {
		return fmt.Errorf("marshaling signal: %w", err)
	}

	subject := fmt.Sprintf("%s.%s.%s", subjectPrefix, b.trustDomain, signal.Type)
	_, err = b.js.Publish(ctx, subject, data)
	if err != nil {
		return fmt.Errorf("publishing signal to %s: %w", subject, err)
	}

	return nil
}

// Subscribe registers a handler for incoming signals of the given type.
// It creates an ephemeral JetStream consumer that delivers only new messages
// and launches a background goroutine to process them. Self-originated signals
// are skipped to prevent loops.
func (b *Bus) Subscribe(ctx context.Context, signalType string, handler core.SignalHandler) error {
	subject := b.signalSubject(signalType)

	cons, err := b.js.CreateConsumer(ctx, streamName, jetstream.ConsumerConfig{
		FilterSubject:     subject,
		DeliverPolicy:     jetstream.DeliverNewPolicy,
		AckPolicy:         jetstream.AckExplicitPolicy,
		InactiveThreshold: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("creating subscribe consumer for %s: %w", subject, err)
	}

	go b.consumeLoop(cons, handler)

	slog.Info("subscribed to signals", "subject", subject, "unit_id", b.unitID)
	return nil
}

// consumeLoop polls a JetStream consumer until the bus context is cancelled.
func (b *Bus) consumeLoop(cons jetstream.Consumer, handler core.SignalHandler) {
	for {
		select {
		case <-b.ctx.Done():
			return
		default:
		}

		msg, err := cons.Next(jetstream.FetchMaxWait(1 * time.Second))
		if err != nil {
			// Timeout is expected when no messages are available.
			continue
		}

		var sig core.Signal
		if err := json.Unmarshal(msg.Data(), &sig); err != nil {
			slog.Error("unmarshaling subscribed signal", "error", err)
			_ = msg.Nak()
			continue
		}

		// Skip self-originated signals to prevent loops.
		if sig.Source == b.unitID {
			_ = msg.Ack()
			continue
		}

		if err := handler(b.ctx, &sig); err != nil {
			slog.Error("signal handler error", "error", err, "type", sig.Type, "source", sig.Source)
			_ = msg.Nak()
			continue
		}

		_ = msg.Ack()
	}
}

// Replay retrieves signals published since the given time. It creates an
// ephemeral consumer with DeliverByStartTimePolicy and reads until the stream
// is exhausted (indicated by a fetch timeout).
func (b *Bus) Replay(ctx context.Context, since time.Time) ([]*core.Signal, error) {
	subject := b.replaySubject()

	cons, err := b.js.CreateConsumer(ctx, streamName, jetstream.ConsumerConfig{
		FilterSubject:     subject,
		DeliverPolicy:     jetstream.DeliverByStartTimePolicy,
		OptStartTime:      &since,
		AckPolicy:         jetstream.AckNonePolicy,
		InactiveThreshold: 5 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("creating replay consumer for %s: %w", subject, err)
	}

	var signals []*core.Signal
	for {
		msg, err := cons.Next(jetstream.FetchMaxWait(2 * time.Second))
		if err != nil {
			// Timeout means we've reached the end of the stream.
			break
		}

		var sig core.Signal
		if err := json.Unmarshal(msg.Data(), &sig); err != nil {
			slog.Error("unmarshaling replayed signal", "error", err)
			continue
		}
		signals = append(signals, &sig)
	}

	return signals, nil
}

// signalSubject returns the NATS subject for subscribing to a specific signal type.
func (b *Bus) signalSubject(signalType string) string {
	domain := b.trustDomain
	if domain == "" {
		domain = "*"
	}
	if signalType == ">" {
		return fmt.Sprintf("%s.%s.>", subjectPrefix, domain)
	}
	return fmt.Sprintf("%s.%s.%s", subjectPrefix, domain, signalType)
}

// replaySubject returns the NATS subject for replaying all signal types.
func (b *Bus) replaySubject() string {
	if b.trustDomain == "" {
		return subjectPrefix + ".>"
	}
	return fmt.Sprintf("%s.%s.>", subjectPrefix, b.trustDomain)
}

// NewPeerBus creates a Bus that shares the embedded NATS server of an existing
// Bus but uses a different unit ID. This enables multi-unit topologies in
// integration and scale tests. The caller is responsible for draining the
// returned Bus; it will not shut down the shared NATS server.
func NewPeerBus(existing *Bus, unitID, trustDomain string) (*Bus, error) {
	if existing.srv == nil {
		return nil, errors.New("NewPeerBus requires an embedded NATS server")
	}

	nc, err := nats.Connect(nats.DefaultURL, nats.InProcessServer(existing.srv))
	if err != nil {
		return nil, fmt.Errorf("connecting to shared NATS server: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("creating JetStream context: %w", err)
	}

	b := &Bus{
		conn:        nc,
		js:          js,
		unitID:      unitID,
		trustDomain: trustDomain,
	}
	b.ctx, b.cancel = context.WithCancel(context.Background())
	return b, nil
}

// Drain gracefully drains the NATS connection and shuts down the embedded
// server if one is running.
func (b *Bus) Drain() error {
	b.cancel()
	if b.conn != nil {
		if err := b.conn.Drain(); err != nil {
			slog.Error("draining NATS connection", "error", err)
		}
	}
	if b.srv != nil {
		b.srv.Shutdown()
		b.srv.WaitForShutdown()
	}
	slog.Info("sync bus shut down")
	return nil
}
