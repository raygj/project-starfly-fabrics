package federation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// ─────────────────────────────────────────────────────────────────────
// COMPILE-TIME ASSERTION
// ─────────────────────────────────────────────────────────────────────

// Verify at compile time that CompositeGateway satisfies SignalGateway.
var _ SignalGateway = (*CompositeGateway)(nil)

// ─────────────────────────────────────────────────────────────────────
// MOCKS (test-local, supplement existing mocks in inbound_test.go)
// ─────────────────────────────────────────────────────────────────────

// mockFullSyncBus satisfies core.SyncBus for testing SubscribeToSyncBus.
type mockFullSyncBus struct {
	mu       sync.Mutex
	handlers map[string]core.SignalHandler
	flashed  []*core.Signal
}

func newMockFullSyncBus() *mockFullSyncBus {
	return &mockFullSyncBus{
		handlers: make(map[string]core.SignalHandler),
	}
}

func (m *mockFullSyncBus) Flash(_ context.Context, signal *core.Signal) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flashed = append(m.flashed, signal)
	return nil
}

func (m *mockFullSyncBus) Subscribe(_ context.Context, signalType string, handler core.SignalHandler) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[signalType] = handler
	return nil
}

func (m *mockFullSyncBus) Replay(_ context.Context, _ time.Time) ([]*core.Signal, error) {
	return nil, nil
}

// deliver simulates a signal arriving on the bus for testing.
func (m *mockFullSyncBus) deliver(ctx context.Context, signalType string, signal *core.Signal) error {
	m.mu.Lock()
	h, ok := m.handlers[signalType]
	m.mu.Unlock()
	if !ok {
		return nil
	}
	return h(ctx, signal)
}

// stubRevSyncer satisfies RevocationSyncer for Syncer construction in
// composite tests. Named differently from mockRevocationSyncer in sync_test.go
// to avoid redeclaration within the same test package.
type stubRevSyncer struct {
	hash string
}

func (m *stubRevSyncer) Hash() string                          { return m.hash }
func (m *stubRevSyncer) Export() ([]byte, error)               { return []byte("{}"), nil }
func (m *stubRevSyncer) Import(_ []byte) error                 { return nil }
func (m *stubRevSyncer) Cleanup(_ context.Context) (int, error) { return 0, nil }

// ─────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────

// newTestComposite builds a CompositeGateway with a relay pointed at
// the given test server and a no-op syncer.
func newTestComposite(t *testing.T, relayServer *httptest.Server) *CompositeGateway {
	t.Helper()

	peers := []PeerSignalConfig{
		{FabricID: "peer-alpha", Endpoint: relayServer.URL + "/v1/signals/events"},
		{FabricID: "peer-beta", Endpoint: relayServer.URL + "/v1/signals/events"},
	}

	cfg := SignalGatewayConfig{Peers: peers}

	relay := NewRelay(cfg, WithRelayHTTPClient(relayServer.Client()))
	inbound := NewInboundHandler(peers)
	syncer := NewSyncer(cfg, &stubRevSyncer{hash: "abc123"})

	return NewCompositeGateway(relay, inbound, syncer)
}

// ─────────────────────────────────────────────────────────────────────
// TESTS: H-3 — CompositeGateway satisfies SignalGateway
// ─────────────────────────────────────────────────────────────────────

func TestCompositeGateway_InterfaceSatisfaction(t *testing.T) {
	// Runtime check that the composite can be assigned to the interface.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cg := newTestComposite(t, srv)

	// Assign to interface variable to verify satisfaction at runtime.
	var gw SignalGateway = cg
	_ = gw

	// Verify the composite was actually constructed.
	if cg.relay == nil {
		t.Fatal("composite gateway relay should not be nil")
	}
}

func TestCompositeGateway_RelayRevocationDelegates(t *testing.T) {
	var received int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var sig RevocationSignal
		if err := json.NewDecoder(r.Body).Decode(&sig); err != nil {
			t.Errorf("decoding relay body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		received++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cg := newTestComposite(t, srv)
	ctx := context.Background()

	sig := testSignal("relay-delegate-001")
	if err := cg.RelayRevocation(ctx, sig); err != nil {
		t.Fatalf("RelayRevocation error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	// Should have relayed to 2 peers.
	if received != 2 {
		t.Errorf("relay received count = %d, want 2", received)
	}
}

func TestCompositeGateway_ReceiveRevocationDelegates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cg := newTestComposite(t, srv)
	ctx := context.Background()

	sig := RevocationSignal{
		SubjectID:    "spiffe://example.com/workload/svc",
		Reason:       "session-revoked",
		RevokedAt:    time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(1 * time.Hour),
		EventJTI:     "inbound-delegate-001",
		SourceFabric: "peer-alpha", // must be trusted
		TrustDomain:  "example.com",
	}

	// InboundHandler has no revocation index configured in this test,
	// so it just validates trust and dedup.
	if err := cg.ReceiveRevocation(ctx, sig); err != nil {
		t.Fatalf("ReceiveRevocation error: %v", err)
	}

	// Verify inbound state was updated.
	state := cg.inbound.State()
	ps, ok := state["peer-alpha"]
	if !ok {
		t.Fatal("peer-alpha not found in inbound state")
	}
	if ps.ReceivedCount != 1 {
		t.Errorf("received count = %d, want 1", ps.ReceivedCount)
	}
}

func TestCompositeGateway_StateMergesAllComponents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cg := newTestComposite(t, srv)
	ctx := context.Background()

	// Relay a signal to update relay state.
	relaySig := testSignal("state-merge-001")
	if err := cg.RelayRevocation(ctx, relaySig); err != nil {
		t.Fatalf("relay error: %v", err)
	}

	// Receive a signal to update inbound state.
	inSig := RevocationSignal{
		SubjectID:    "spiffe://example.com/workload/svc",
		Reason:       "credential-change",
		RevokedAt:    time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(1 * time.Hour),
		EventJTI:     "state-merge-002",
		SourceFabric: "peer-alpha",
		TrustDomain:  "example.com",
	}
	if err := cg.ReceiveRevocation(ctx, inSig); err != nil {
		t.Fatalf("receive error: %v", err)
	}

	// Get merged state.
	state := cg.State()

	if state.Peers == nil {
		t.Fatal("state.Peers is nil")
	}

	alphaState, ok := state.Peers["peer-alpha"]
	if !ok {
		t.Fatal("peer-alpha missing from merged state")
	}

	// Relay should have set RelayedCount.
	if alphaState.RelayedCount < 1 {
		t.Errorf("RelayedCount = %d, want >= 1", alphaState.RelayedCount)
	}

	// Inbound should have set ReceivedCount.
	if alphaState.ReceivedCount < 1 {
		t.Errorf("ReceivedCount = %d, want >= 1", alphaState.ReceivedCount)
	}

	// UpdatedAt should be recent.
	if time.Since(state.UpdatedAt) > 5*time.Second {
		t.Errorf("UpdatedAt too old: %v", state.UpdatedAt)
	}
}

func TestCompositeGateway_CloseStopsAllComponents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cg := newTestComposite(t, srv)

	// Start the syncer to verify Close actually stops it.
	if err := cg.syncer.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}

	if err := cg.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	// After close, syncer should be stopped — verify by checking the
	// stop channel is closed (wg.Wait already completed in Close).
	select {
	case <-cg.syncer.stopCh:
		// expected — channel is closed
	default:
		t.Error("syncer stopCh not closed after Close()")
	}
}

func TestCompositeGateway_SyncStateDelegatesToSyncer(t *testing.T) {
	exportData := []byte(`{"entries":[],"count":0,"hash":"sha256:empty"}`)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/signals/events", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v1/federation/revocation-hash", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"hash": "sha256:abc123"})
	})
	mux.HandleFunc("/v1/federation/revocation-export", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(exportData)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	peers := []PeerSignalConfig{
		{FabricID: "peer-alpha", Endpoint: srv.URL + "/v1/signals/events"},
	}
	cfg := SignalGatewayConfig{Peers: peers}

	relay := NewRelay(cfg, WithRelayHTTPClient(srv.Client()))
	inbound := NewInboundHandler(peers)
	syncer := NewSyncer(cfg, &stubRevSyncer{hash: "sha256:abc123"}, WithSyncerHTTPClient(srv.Client()))

	cg := NewCompositeGateway(relay, inbound, syncer)

	err := cg.SyncState(context.Background(), "peer-alpha")
	if err != nil {
		t.Fatalf("SyncState error: %v", err)
	}
}

func TestCompositeGateway_SyncStateUnknownPeer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cg := newTestComposite(t, srv)

	err := cg.SyncState(context.Background(), "nonexistent-peer")
	if err == nil {
		t.Fatal("SyncState with unknown peer should return error")
	}
}

func TestCompositeGateway_CloseWithNilComponents(t *testing.T) {
	cg := NewCompositeGateway(nil, nil, nil)
	err := cg.Close()
	if err != nil {
		t.Fatalf("Close with nil components should not error, got: %v", err)
	}
}

func TestCompositeGateway_StateWithNilComponents(t *testing.T) {
	cg := NewCompositeGateway(nil, nil, nil)
	state := cg.State()
	if state.Peers == nil {
		t.Fatal("State should return initialized Peers map even with nil components")
	}
	if len(state.Peers) != 0 {
		t.Errorf("expected 0 peers with nil components, got %d", len(state.Peers))
	}
}

func TestCompositeGateway_SubscribeToSyncBusNilRelay(t *testing.T) {
	cg := NewCompositeGateway(nil, nil, nil)
	bus := newMockFullSyncBus()

	err := cg.SubscribeToSyncBus(context.Background(), bus, "fabric-local")
	if err == nil {
		t.Error("SubscribeToSyncBus with nil relay should return error")
	}
}

func TestCompositeGateway_NilComponentsReturnError(t *testing.T) {
	cg := NewCompositeGateway(nil, nil, nil)
	ctx := context.Background()

	if err := cg.RelayRevocation(ctx, RevocationSignal{}); err == nil {
		t.Error("RelayRevocation with nil relay should return error")
	}
	if err := cg.ReceiveRevocation(ctx, RevocationSignal{}); err == nil {
		t.Error("ReceiveRevocation with nil inbound should return error")
	}
	if err := cg.SyncState(ctx, "any-peer"); err == nil {
		t.Error("SyncState with nil syncer should return error")
	}
}

// ─────────────────────────────────────────────────────────────────────
// TESTS: H-4 — Sync Bus Bridge
// ─────────────────────────────────────────────────────────────────────

func TestCompositeGateway_SubscribeToSyncBus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cg := newTestComposite(t, srv)
	bus := newMockFullSyncBus()
	ctx := context.Background()

	err := cg.SubscribeToSyncBus(ctx, bus, "fabric-local")
	if err != nil {
		t.Fatalf("SubscribeToSyncBus error: %v", err)
	}

	// Verify subscriptions were registered for both signal types.
	bus.mu.Lock()
	handlerCount := len(bus.handlers)
	bus.mu.Unlock()

	if handlerCount != len(revocationSignalTypes) {
		t.Errorf("handler count = %d, want %d", handlerCount, len(revocationSignalTypes))
	}

	// Double subscription should error.
	err = cg.SubscribeToSyncBus(ctx, bus, "fabric-local")
	if err == nil {
		t.Error("double SubscribeToSyncBus should return error")
	}
}

func TestCompositeGateway_SyncBusBridgeRelays(t *testing.T) {
	var relayedSignals []RevocationSignal
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var sig RevocationSignal
		if err := json.NewDecoder(r.Body).Decode(&sig); err != nil {
			t.Errorf("decoding relayed signal: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		relayedSignals = append(relayedSignals, sig)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cg := newTestComposite(t, srv)
	bus := newMockFullSyncBus()
	ctx := context.Background()

	if err := cg.SubscribeToSyncBus(ctx, bus, "fabric-local"); err != nil {
		t.Fatalf("SubscribeToSyncBus error: %v", err)
	}

	// Simulate a local identity.revoked signal arriving on the bus.
	localSignal := &core.Signal{
		Type:      "identity.revoked",
		Source:    "unit-01",
		Timestamp: time.Now().UTC(),
		Payload: map[string]interface{}{
			"subject_id":   "spiffe://example.com/workload/compromised",
			"reason":       "credential-change",
			"event_jti":    "bus-bridge-jti-001",
			"trust_domain": "example.com",
		},
	}

	if err := bus.deliver(ctx, "identity.revoked", localSignal); err != nil {
		t.Fatalf("deliver error: %v", err)
	}

	mu.Lock()
	count := len(relayedSignals)
	mu.Unlock()

	// Should have been relayed to 2 peers.
	if count != 2 {
		t.Fatalf("relayed signal count = %d, want 2", count)
	}

	mu.Lock()
	first := relayedSignals[0]
	mu.Unlock()

	if first.SubjectID != "spiffe://example.com/workload/compromised" {
		t.Errorf("subject_id = %q, want spiffe://example.com/workload/compromised", first.SubjectID)
	}
	if first.SourceFabric != "fabric-local" {
		t.Errorf("source_fabric = %q, want fabric-local", first.SourceFabric)
	}
	if first.Reason != "credential-change" {
		t.Errorf("reason = %q, want credential-change", first.Reason)
	}
}

func TestCompositeGateway_SyncBusBridgeSkipsMissingSubject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("relay should not be called for signal without subject_id")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cg := newTestComposite(t, srv)
	bus := newMockFullSyncBus()
	ctx := context.Background()

	if err := cg.SubscribeToSyncBus(ctx, bus, "fabric-local"); err != nil {
		t.Fatalf("SubscribeToSyncBus error: %v", err)
	}

	// Signal without subject_id — should be skipped.
	noSubjectSignal := &core.Signal{
		Type:      "identity.revoked",
		Source:    "unit-01",
		Timestamp: time.Now().UTC(),
		Payload:   map[string]interface{}{},
	}

	if err := bus.deliver(ctx, "identity.revoked", noSubjectSignal); err != nil {
		t.Fatalf("deliver error: %v", err)
	}
}

func TestCompositeGateway_SyncBusNilBusErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cg := newTestComposite(t, srv)
	ctx := context.Background()

	err := cg.SubscribeToSyncBus(ctx, nil, "fabric-local")
	if err == nil {
		t.Error("SubscribeToSyncBus with nil bus should return error")
	}
}
