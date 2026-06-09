package sync

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/starfly-fabrics/starfly/pkg/core"
)

func testBus(t *testing.T) *Bus {
	t.Helper()
	dir := t.TempDir()
	cfg := core.NATSConfig{
		Embedded:     true,
		JetStreamDir: dir,
	}
	bus, err := New(cfg, "test-unit-01", "example.com")
	if err != nil {
		t.Fatalf("creating test bus: %v", err)
	}
	t.Cleanup(func() { _ = bus.Drain() })
	return bus
}

func TestBus_Flash(t *testing.T) {
	bus := testBus(t)
	ctx := context.Background()

	sig := &core.Signal{
		Type: "identity_event",
		Payload: map[string]interface{}{
			"workload_id": "wimse://example.com/ns/default/sa/my-app",
			"audience":    "https://api.target.example.com",
		},
	}

	if err := bus.Flash(ctx, sig); err != nil {
		t.Fatalf("Flash: %v", err)
	}

	// Consume from JetStream to verify delivery.
	cons, err := bus.js.CreateConsumer(ctx, streamName, jetstream.ConsumerConfig{
		FilterSubject: "starfly.example.com.identity_event",
		DeliverPolicy: jetstream.DeliverAllPolicy,
	})
	if err != nil {
		t.Fatalf("creating consumer: %v", err)
	}

	msg, err := cons.Next(jetstream.FetchMaxWait(2 * time.Second))
	if err != nil {
		t.Fatalf("consuming message: %v", err)
	}

	var received core.Signal
	if err := json.Unmarshal(msg.Data(), &received); err != nil {
		t.Fatalf("unmarshaling signal: %v", err)
	}

	if received.Type != "identity_event" {
		t.Errorf("Type = %q, want %q", received.Type, "identity_event")
	}
	if received.Source != "test-unit-01" {
		t.Errorf("Source = %q, want %q", received.Source, "test-unit-01")
	}
}

func TestBus_Flash_PayloadCorrect(t *testing.T) {
	bus := testBus(t)
	ctx := context.Background()

	sig := &core.Signal{
		Type: "identity_event",
		Payload: map[string]interface{}{
			"workload_id":  "wimse://example.com/ns/default/sa/my-app",
			"audience":     "https://api.target.example.com",
			"trust_domain": "example.com",
		},
	}

	if err := bus.Flash(ctx, sig); err != nil {
		t.Fatalf("Flash: %v", err)
	}

	cons, err := bus.js.CreateConsumer(ctx, streamName, jetstream.ConsumerConfig{
		FilterSubject: "starfly.example.com.identity_event",
		DeliverPolicy: jetstream.DeliverAllPolicy,
	})
	if err != nil {
		t.Fatalf("creating consumer: %v", err)
	}

	msg, err := cons.Next(jetstream.FetchMaxWait(2 * time.Second))
	if err != nil {
		t.Fatalf("consuming message: %v", err)
	}

	var received core.Signal
	if err := json.Unmarshal(msg.Data(), &received); err != nil {
		t.Fatalf("unmarshaling signal: %v", err)
	}

	// Verify structure.
	if received.Type != "identity_event" {
		t.Errorf("Type = %q, want %q", received.Type, "identity_event")
	}
	if received.Source != "test-unit-01" {
		t.Errorf("Source = %q, want %q", received.Source, "test-unit-01")
	}
	if received.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
	if received.Payload["workload_id"] != "wimse://example.com/ns/default/sa/my-app" {
		t.Errorf("Payload.workload_id = %v, want WIMSE URI", received.Payload["workload_id"])
	}
	if received.Payload["audience"] != "https://api.target.example.com" {
		t.Errorf("Payload.audience = %v", received.Payload["audience"])
	}
	if received.Payload["trust_domain"] != "example.com" {
		t.Errorf("Payload.trust_domain = %v", received.Payload["trust_domain"])
	}
}

func TestBus_Flash_JetStreamPersists(t *testing.T) {
	bus := testBus(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		sig := &core.Signal{
			Type: "identity_event",
			Payload: map[string]interface{}{
				"index": float64(i),
			},
		}
		if err := bus.Flash(ctx, sig); err != nil {
			t.Fatalf("Flash %d: %v", i, err)
		}
	}

	cons, err := bus.js.CreateConsumer(ctx, streamName, jetstream.ConsumerConfig{
		FilterSubject: "starfly.example.com.identity_event",
		DeliverPolicy: jetstream.DeliverAllPolicy,
	})
	if err != nil {
		t.Fatalf("creating consumer: %v", err)
	}

	for i := 0; i < 3; i++ {
		msg, err := cons.Next(jetstream.FetchMaxWait(2 * time.Second))
		if err != nil {
			t.Fatalf("consuming message %d: %v", i, err)
		}
		var received core.Signal
		if err := json.Unmarshal(msg.Data(), &received); err != nil {
			t.Fatalf("unmarshaling signal %d: %v", i, err)
		}
		idx, ok := received.Payload["index"].(float64)
		if !ok || int(idx) != i {
			t.Errorf("message %d: index = %v, want %d", i, received.Payload["index"], i)
		}
	}
}

// testBusWithID creates a second Bus sharing the same embedded NATS server
// as an existing Bus, but with a different unit ID.
func testBusWithID(t *testing.T, existing *Bus, unitID string) *Bus {
	t.Helper()

	nc, err := nats.Connect(nats.DefaultURL, nats.InProcessServer(existing.srv))
	if err != nil {
		t.Fatalf("connecting to existing NATS server: %v", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		t.Fatalf("creating JetStream context: %v", err)
	}

	b := &Bus{
		conn:        nc,
		js:          js,
		unitID:      unitID,
		trustDomain: existing.trustDomain,
	}
	b.ctx, b.cancel = context.WithCancel(context.Background())
	t.Cleanup(func() { _ = b.Drain() })
	return b
}

func TestBus_Subscribe(t *testing.T) {
	bus1 := testBus(t)
	bus2 := testBusWithID(t, bus1, "test-unit-02")
	ctx := context.Background()

	received := make(chan *core.Signal, 1)
	handler := func(_ context.Context, sig *core.Signal) error {
		received <- sig
		return nil
	}

	if err := bus1.Subscribe(ctx, "identity_event", handler); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// Give the consumer goroutine a moment to start.
	time.Sleep(200 * time.Millisecond)

	// Flash from bus2 — bus1 should receive it.
	sig := &core.Signal{
		Type:    "identity_event",
		Payload: map[string]interface{}{"from": "unit-02"},
	}
	if err := bus2.Flash(ctx, sig); err != nil {
		t.Fatalf("Flash: %v", err)
	}

	select {
	case got := <-received:
		if got.Source != "test-unit-02" {
			t.Errorf("Source = %q, want %q", got.Source, "test-unit-02")
		}
		if got.Type != "identity_event" {
			t.Errorf("Type = %q, want %q", got.Type, "identity_event")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for subscribed signal")
	}
}

func TestBus_Subscribe_IgnoresSelf(t *testing.T) {
	bus := testBus(t)
	ctx := context.Background()

	var callCount atomic.Int32
	handler := func(_ context.Context, sig *core.Signal) error {
		callCount.Add(1)
		return nil
	}

	if err := bus.Subscribe(ctx, "identity_event", handler); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Flash from self — handler should NOT fire.
	sig := &core.Signal{
		Type:    "identity_event",
		Payload: map[string]interface{}{"self": true},
	}
	if err := bus.Flash(ctx, sig); err != nil {
		t.Fatalf("Flash: %v", err)
	}

	// Wait enough time for the message to be processed.
	time.Sleep(3 * time.Second)

	if n := callCount.Load(); n != 0 {
		t.Errorf("handler called %d times, want 0 (self-originated signals should be skipped)", n)
	}
}

func TestBus_Replay(t *testing.T) {
	bus := testBus(t)
	ctx := context.Background()

	before := time.Now().Add(-1 * time.Second)

	// Flash 3 signals.
	for i := 0; i < 3; i++ {
		sig := &core.Signal{
			Type:    "identity_event",
			Payload: map[string]interface{}{"index": float64(i)},
		}
		if err := bus.Flash(ctx, sig); err != nil {
			t.Fatalf("Flash %d: %v", i, err)
		}
	}

	signals, err := bus.Replay(ctx, before)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}

	if len(signals) != 3 {
		t.Fatalf("Replay returned %d signals, want 3", len(signals))
	}

	for i, sig := range signals {
		idx, ok := sig.Payload["index"].(float64)
		if !ok || int(idx) != i {
			t.Errorf("signal %d: index = %v, want %d", i, sig.Payload["index"], i)
		}
	}
}

func TestBus_Replay_AfterRestart(t *testing.T) {
	bus1 := testBus(t)
	ctx := context.Background()

	before := time.Now().Add(-1 * time.Second)

	// Flash 3 signals on bus1.
	for i := 0; i < 3; i++ {
		sig := &core.Signal{
			Type:    "identity_event",
			Payload: map[string]interface{}{"index": float64(i)},
		}
		if err := bus1.Flash(ctx, sig); err != nil {
			t.Fatalf("Flash %d: %v", i, err)
		}
	}

	// Create bus2 sharing the same server (simulating a restart/new unit).
	bus2 := testBusWithID(t, bus1, "test-unit-02")

	signals, err := bus2.Replay(ctx, before)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}

	if len(signals) != 3 {
		t.Fatalf("Replay returned %d signals, want 3", len(signals))
	}

	for i, sig := range signals {
		if sig.Source != "test-unit-01" {
			t.Errorf("signal %d: Source = %q, want %q", i, sig.Source, "test-unit-01")
		}
	}
}

func TestBus_New_ExternalEmptyURL(t *testing.T) {
	_, err := New(core.NATSConfig{Embedded: false, URL: ""}, "unit", "example.com")
	if err == nil {
		t.Error("expected error for empty external URL")
	}
}

func TestBus_New_ExternalUnreachable(t *testing.T) {
	_, err := New(core.NATSConfig{Embedded: false, URL: "nats://127.0.0.1:1"}, "unit", "example.com")
	if err == nil {
		t.Error("expected error for unreachable external NATS")
	}
}

func TestBus_Flash_PresetTimestamp(t *testing.T) {
	bus := testBus(t)
	ctx := context.Background()

	fixedTime := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	sig := &core.Signal{
		Type:      "identity_event",
		Timestamp: fixedTime,
		Payload:   map[string]interface{}{"preset": true},
	}

	if err := bus.Flash(ctx, sig); err != nil {
		t.Fatalf("Flash: %v", err)
	}

	cons, err := bus.js.CreateConsumer(ctx, streamName, jetstream.ConsumerConfig{
		FilterSubject: "starfly.example.com.identity_event",
		DeliverPolicy: jetstream.DeliverAllPolicy,
	})
	if err != nil {
		t.Fatalf("creating consumer: %v", err)
	}

	msg, err := cons.Next(jetstream.FetchMaxWait(2 * time.Second))
	if err != nil {
		t.Fatalf("consuming: %v", err)
	}

	var received core.Signal
	if err := json.Unmarshal(msg.Data(), &received); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !received.Timestamp.Equal(fixedTime) {
		t.Errorf("Timestamp = %v, want %v", received.Timestamp, fixedTime)
	}
}

func TestBus_Subscribe_HandlerError(t *testing.T) {
	bus1 := testBus(t)
	bus2 := testBusWithID(t, bus1, "test-unit-02")
	ctx := context.Background()

	var handlerCalls atomic.Int32
	handler := func(_ context.Context, _ *core.Signal) error {
		handlerCalls.Add(1)
		return errors.New("handler failed")
	}

	if err := bus1.Subscribe(ctx, "identity_event", handler); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	sig := &core.Signal{
		Type:    "identity_event",
		Payload: map[string]interface{}{"test": true},
	}
	if err := bus2.Flash(ctx, sig); err != nil {
		t.Fatalf("Flash: %v", err)
	}

	time.Sleep(3 * time.Second)
	if n := handlerCalls.Load(); n == 0 {
		t.Error("handler should have been called at least once")
	}
}

func TestBus_Subscribe_BadMessageData(t *testing.T) {
	bus := testBus(t)
	ctx := context.Background()

	var handlerCalls atomic.Int32
	handler := func(_ context.Context, _ *core.Signal) error {
		handlerCalls.Add(1)
		return nil
	}

	if err := bus.Subscribe(ctx, "identity_event", handler); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Publish invalid JSON directly to trigger unmarshal error in consumeLoop.
	_, err := bus.js.Publish(ctx, "starfly.example.com.identity_event", []byte("not-json"))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	time.Sleep(3 * time.Second)
	if n := handlerCalls.Load(); n != 0 {
		t.Errorf("handler called %d times, want 0 (bad message should be nak'd)", n)
	}
}

func TestBus_SignalSubject_EmptyDomain(t *testing.T) {
	bus := &Bus{trustDomain: "", unitID: "test"}
	got := bus.signalSubject("identity_event")
	want := "starfly.*.identity_event"
	if got != want {
		t.Errorf("signalSubject = %q, want %q", got, want)
	}
}

func TestBus_SignalSubject_Wildcard(t *testing.T) {
	bus := &Bus{trustDomain: "example.com", unitID: "test"}
	got := bus.signalSubject(">")
	want := "starfly.example.com.>"
	if got != want {
		t.Errorf("signalSubject(>) = %q, want %q", got, want)
	}
}

func TestBus_SignalSubject_WildcardEmptyDomain(t *testing.T) {
	bus := &Bus{trustDomain: "", unitID: "test"}
	got := bus.signalSubject(">")
	want := "starfly.*.>"
	if got != want {
		t.Errorf("signalSubject(>) = %q, want %q", got, want)
	}
}

func TestBus_ReplaySubject_EmptyDomain(t *testing.T) {
	bus := &Bus{trustDomain: "", unitID: "test"}
	got := bus.replaySubject()
	want := "starfly.>"
	if got != want {
		t.Errorf("replaySubject = %q, want %q", got, want)
	}
}

func TestBus_ReplaySubject_WithDomain(t *testing.T) {
	bus := &Bus{trustDomain: "example.com", unitID: "test"}
	got := bus.replaySubject()
	want := "starfly.example.com.>"
	if got != want {
		t.Errorf("replaySubject = %q, want %q", got, want)
	}
}

func TestNewPeerBus(t *testing.T) {
	bus1 := testBus(t)
	ctx := context.Background()

	peer, err := NewPeerBus(bus1, "peer-unit", "example.com")
	if err != nil {
		t.Fatalf("NewPeerBus: %v", err)
	}
	t.Cleanup(func() { _ = peer.Drain() })

	if peer.unitID != "peer-unit" {
		t.Errorf("unitID = %q, want peer-unit", peer.unitID)
	}
	if peer.trustDomain != "example.com" {
		t.Errorf("trustDomain = %q, want example.com", peer.trustDomain)
	}

	sig := &core.Signal{
		Type:    "identity_event",
		Payload: map[string]interface{}{"from": "peer"},
	}
	if err := peer.Flash(ctx, sig); err != nil {
		t.Fatalf("peer Flash: %v", err)
	}

	cons, err := bus1.js.CreateConsumer(ctx, streamName, jetstream.ConsumerConfig{
		FilterSubject: "starfly.example.com.identity_event",
		DeliverPolicy: jetstream.DeliverAllPolicy,
	})
	if err != nil {
		t.Fatalf("creating consumer: %v", err)
	}

	msg, err := cons.Next(jetstream.FetchMaxWait(2 * time.Second))
	if err != nil {
		t.Fatalf("consuming: %v", err)
	}
	var received core.Signal
	if err := json.Unmarshal(msg.Data(), &received); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if received.Source != "peer-unit" {
		t.Errorf("Source = %q, want peer-unit", received.Source)
	}
}

func TestNewPeerBus_ShutdownServer(t *testing.T) {
	bus := testBus(t)
	bus.srv.Shutdown()
	bus.srv.WaitForShutdown()

	_, err := NewPeerBus(bus, "peer", "example.com")
	if err == nil {
		t.Error("expected error when server is shut down")
	}
}

func TestNewPeerBus_RequiresEmbedded(t *testing.T) {
	bus := &Bus{srv: nil}
	_, err := NewPeerBus(bus, "peer", "example.com")
	if err == nil {
		t.Error("expected error when existing bus has no embedded server")
	}
}

func TestBus_Replay_BadDataInStream(t *testing.T) {
	bus := testBus(t)
	ctx := context.Background()
	before := time.Now().Add(-1 * time.Second)

	// Publish valid signal, then invalid JSON, then another valid signal.
	sig1 := &core.Signal{
		Type:    "identity_event",
		Payload: map[string]interface{}{"index": float64(0)},
	}
	if err := bus.Flash(ctx, sig1); err != nil {
		t.Fatalf("Flash 1: %v", err)
	}

	_, err := bus.js.Publish(ctx, "starfly.example.com.identity_event", []byte("bad-json"))
	if err != nil {
		t.Fatalf("Publish bad data: %v", err)
	}

	sig2 := &core.Signal{
		Type:    "identity_event",
		Payload: map[string]interface{}{"index": float64(2)},
	}
	if err := bus.Flash(ctx, sig2); err != nil {
		t.Fatalf("Flash 2: %v", err)
	}

	signals, err := bus.Replay(ctx, before)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	// Should get 2 valid signals (bad JSON is skipped).
	if len(signals) != 2 {
		t.Errorf("Replay returned %d signals, want 2 (bad JSON skipped)", len(signals))
	}
}

func TestBus_Replay_EmptyStream(t *testing.T) {
	bus := testBus(t)
	ctx := context.Background()

	signals, err := bus.Replay(ctx, time.Now().Add(-1*time.Second))
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(signals) != 0 {
		t.Errorf("Replay on empty stream returned %d signals, want 0", len(signals))
	}
}

func TestBus_New_EmbeddedBadDir(t *testing.T) {
	cfg := core.NATSConfig{
		Embedded:     true,
		JetStreamDir: "/dev/null/impossible/path",
	}
	_, err := New(cfg, "unit", "example.com")
	if err == nil {
		t.Error("expected error for impossible JetStream dir")
	}
}

func TestBus_New_ExternalSuccess(t *testing.T) {
	// Start a real NATS server with JetStream to test the external connection path.
	dir := t.TempDir()
	srv, err := server.NewServer(&server.Options{
		Port:      -1, // random available port
		JetStream: true,
		StoreDir:  dir,
	})
	if err != nil {
		t.Fatalf("creating test server: %v", err)
	}
	srv.Start()
	t.Cleanup(srv.Shutdown)
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("test NATS server failed to start")
	}

	url := srv.ClientURL()
	bus, err := New(core.NATSConfig{
		Embedded: false,
		URL:      url,
	}, "ext-unit", "example.com")
	if err != nil {
		t.Fatalf("New(external): %v", err)
	}
	t.Cleanup(func() { _ = bus.Drain() })

	// Verify it works.
	sig := &core.Signal{
		Type:    "identity_event",
		Payload: map[string]interface{}{"ext": true},
	}
	if err := bus.Flash(context.Background(), sig); err != nil {
		t.Fatalf("Flash: %v", err)
	}
}

func TestBus_New_EmbeddedReadOnlyDir(t *testing.T) {
	dir := t.TempDir()
	roDir := dir + "/readonly"
	if err := os.Mkdir(roDir, 0o555); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cfg := core.NATSConfig{
		Embedded:     true,
		JetStreamDir: roDir + "/nats",
	}
	_, err := New(cfg, "unit", "example.com")
	if err == nil {
		t.Error("expected error for read-only JetStream dir")
	}
}

func TestBus_New_ExternalNonJetStream(t *testing.T) {
	// Start a NATS server WITHOUT JetStream to test JetStream creation error.
	srv, err := server.NewServer(&server.Options{
		Port:      -1,
		JetStream: false,
	})
	if err != nil {
		t.Fatalf("creating server: %v", err)
	}
	srv.Start()
	t.Cleanup(srv.Shutdown)
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("server failed to start")
	}

	_, err = New(core.NATSConfig{
		Embedded: false,
		URL:      srv.ClientURL(),
	}, "unit", "example.com")
	if err == nil {
		t.Error("expected error when connecting to non-JetStream NATS")
	}
}

func TestBus_Flash_MarshalError(t *testing.T) {
	bus := testBus(t)
	ctx := context.Background()

	sig := &core.Signal{
		Type:    "identity_event",
		Payload: map[string]interface{}{"bad": make(chan int)},
	}
	err := bus.Flash(ctx, sig)
	if err == nil {
		t.Error("expected marshal error for channel in payload")
	}
}

func TestBus_Subscribe_ConsumerError(t *testing.T) {
	bus := testBus(t)

	// Use a cancelled context to trigger consumer creation failure.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := bus.Subscribe(ctx, "identity_event", func(_ context.Context, _ *core.Signal) error {
		return nil
	})
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestBus_Flash_PublishError(t *testing.T) {
	bus := testBus(t)
	// Drain the connection so publish fails.
	_ = bus.conn.Drain()

	sig := &core.Signal{
		Type:    "identity_event",
		Payload: map[string]interface{}{"test": true},
	}
	err := bus.Flash(context.Background(), sig)
	if err == nil {
		t.Error("expected publish error on drained connection")
	}
}

func TestBus_Replay_ConsumerError(t *testing.T) {
	bus := testBus(t)

	// Cancelled context should fail consumer creation.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := bus.Replay(ctx, time.Now().Add(-1*time.Second))
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestBus_Drain_NilConnNilSrv(t *testing.T) {
	b := &Bus{}
	b.ctx, b.cancel = context.WithCancel(context.Background())
	if err := b.Drain(); err != nil {
		t.Fatalf("Drain: %v", err)
	}
}

func TestBus_Drain(t *testing.T) {
	bus := testBus(t)
	ctx := context.Background()

	sig := &core.Signal{
		Type:    "identity_event",
		Payload: map[string]interface{}{"test": true},
	}
	if err := bus.Flash(ctx, sig); err != nil {
		t.Fatalf("Flash: %v", err)
	}

	// Drain should not panic.
	if err := bus.Drain(); err != nil {
		t.Fatalf("Drain: %v", err)
	}
}
