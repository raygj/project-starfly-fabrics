package signals

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/starfly-fabrics/starfly/pkg/core"
)

// ── Mock collaborators ──────────────────────────────────────────────

type mockAuditor struct {
	events []*core.AuditEvent
}

func (m *mockAuditor) Log(_ context.Context, event *core.AuditEvent) error {
	m.events = append(m.events, event)
	return nil
}

type mockSyncBus struct {
	flashes []*core.Signal
	err     error
}

func (m *mockSyncBus) Flash(_ context.Context, signal *core.Signal) error {
	m.flashes = append(m.flashes, signal)
	return m.err
}

func (m *mockSyncBus) Subscribe(context.Context, string, core.SignalHandler) error {
	return errors.New("not implemented")
}

func (m *mockSyncBus) Replay(context.Context, time.Time) ([]*core.Signal, error) {
	return nil, errors.New("not implemented")
}

// ── Tests ───────────────────────────────────────────────────────────

func TestNewTransmitter(t *testing.T) {
	tx, err := NewTransmitter(WithTransmitterIssuer("test-unit"))
	if err != nil {
		t.Fatalf("NewTransmitter error: %v", err)
	}
	if tx.StreamCount() != 0 {
		t.Errorf("StreamCount = %d, want 0", tx.StreamCount())
	}
}

func TestTransmitter_PublicKeySet(t *testing.T) {
	tx, err := NewTransmitter()
	if err != nil {
		t.Fatalf("NewTransmitter error: %v", err)
	}

	set, err := tx.PublicKeySet()
	if err != nil {
		t.Fatalf("PublicKeySet error: %v", err)
	}
	if set.Len() != 1 {
		t.Fatalf("key count = %d, want 1", set.Len())
	}
	key, ok := set.Key(0)
	if !ok {
		t.Fatal("no key at index 0")
	}
	kid, _ := key.KeyID()
	if kid != "starfly-ssf-1" {
		t.Errorf("kid = %q, want %q", kid, "starfly-ssf-1")
	}
}

func TestTransmitter_CreateDeleteStream(t *testing.T) {
	tx, err := NewTransmitter()
	if err != nil {
		t.Fatalf("NewTransmitter error: %v", err)
	}
	ctx := context.Background()

	// Create stream.
	stream, err := tx.CreateStream(ctx, &core.StreamConfig{
		Audience:        "receiver.example.com",
		EventsRequested: []string{EventCredentialChange, EventSessionRevoked},
		DeliveryMethod:  "push",
		EndpointURL:     "https://receiver.example.com/events",
	})
	if err != nil {
		t.Fatalf("CreateStream error: %v", err)
	}
	if stream.ID == "" {
		t.Error("stream ID should not be empty")
	}
	if stream.Status != StreamStatusEnabled {
		t.Errorf("status = %q, want %q", stream.Status, StreamStatusEnabled)
	}
	if tx.StreamCount() != 1 {
		t.Errorf("StreamCount = %d, want 1", tx.StreamCount())
	}

	// Get status.
	status, err := tx.GetStreamStatus(ctx, stream.ID)
	if err != nil {
		t.Fatalf("GetStreamStatus error: %v", err)
	}
	if status.Status != StreamStatusEnabled {
		t.Errorf("status = %q, want %q", status.Status, StreamStatusEnabled)
	}

	// Delete stream.
	err = tx.DeleteStream(ctx, stream.ID)
	if err != nil {
		t.Fatalf("DeleteStream error: %v", err)
	}
	if tx.StreamCount() != 0 {
		t.Errorf("StreamCount after delete = %d, want 0", tx.StreamCount())
	}

	// Delete again should fail.
	err = tx.DeleteStream(ctx, stream.ID)
	if err == nil {
		t.Error("expected error for deleting non-existent stream")
	}
}

func TestTransmitter_CreateStream_RejectsHTTP(t *testing.T) {
	tx, err := NewTransmitter()
	if err != nil {
		t.Fatalf("NewTransmitter error: %v", err)
	}
	ctx := context.Background()

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"https allowed", "https://receiver.example.com/events", false},
		{"http rejected", "http://receiver.example.com/events", true},
		{"localhost http allowed", "http://localhost:8080/events", false},
		{"127.0.0.1 http allowed", "http://127.0.0.1:9090/events", false},
		{"empty URL allowed", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tx.CreateStream(ctx, &core.StreamConfig{
				Audience:    "test",
				EndpointURL: tt.url,
			})
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), "HTTPS") {
					t.Errorf("error = %q, want containing 'HTTPS'", err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestTransmitter_CreateStream_NoAudience(t *testing.T) {
	tx, err := NewTransmitter()
	if err != nil {
		t.Fatalf("NewTransmitter error: %v", err)
	}

	_, err = tx.CreateStream(context.Background(), &core.StreamConfig{})
	if err == nil {
		t.Error("expected error for stream without audience")
	}
}

func TestTransmitter_GetStreamStatus_NotFound(t *testing.T) {
	tx, err := NewTransmitter()
	if err != nil {
		t.Fatalf("NewTransmitter error: %v", err)
	}

	_, err = tx.GetStreamStatus(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent stream")
	}
}

func TestTransmitter_TransmitEvent_SignsAndDelivers(t *testing.T) {
	var deliveredCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/secevent+jwt" {
			t.Errorf("Content-Type = %q, want %q", r.Header.Get("Content-Type"), "application/secevent+jwt")
		}
		deliveredCount.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	auditor := &mockAuditor{}
	bus := &mockSyncBus{}
	tx, err := NewTransmitter(
		WithTransmitterAuditor(auditor),
		WithTransmitterSyncBus(bus, "unit-1"),
		WithTransmitterIssuer("starfly-test"),
	)
	if err != nil {
		t.Fatalf("NewTransmitter error: %v", err)
	}
	ctx := context.Background()

	// Create a stream pointing to our test server.
	_, err = tx.CreateStream(ctx, &core.StreamConfig{
		Audience:       "test-receiver",
		DeliveryMethod: "push",
		EndpointURL:    server.URL,
	})
	if err != nil {
		t.Fatalf("CreateStream error: %v", err)
	}

	// Transmit an event.
	event := NewSecurityEvent("starfly-test", "test-receiver", &core.SubjectIdentifier{
		Format:   "spiffe",
		SpiffeID: "spiffe://example.com/workload-1",
	})
	AddEvent(event, EventSessionRevoked, map[string]interface{}{
		"reason": "admin_action",
	})

	err = tx.TransmitEvent(ctx, event)
	if err != nil {
		t.Fatalf("TransmitEvent error: %v", err)
	}

	// Wait for async delivery.
	time.Sleep(100 * time.Millisecond)

	if deliveredCount.Load() != 1 {
		t.Errorf("delivered count = %d, want 1", deliveredCount.Load())
	}

	// Sync bus should have been flashed.
	if len(bus.flashes) != 1 {
		t.Fatalf("bus flash count = %d, want 1", len(bus.flashes))
	}
	if bus.flashes[0].Type != "caep_signal" {
		t.Errorf("signal type = %q, want %q", bus.flashes[0].Type, "caep_signal")
	}
}

func TestTransmitter_TransmitEvent_VerifySETSignature(t *testing.T) {
	var mu sync.Mutex
	var receivedSET []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 8192)
		n, _ := r.Body.Read(buf)
		mu.Lock()
		receivedSET = buf[:n]
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	tx, err := NewTransmitter(WithTransmitterIssuer("starfly-test"))
	if err != nil {
		t.Fatalf("NewTransmitter error: %v", err)
	}
	ctx := context.Background()

	_, err = tx.CreateStream(ctx, &core.StreamConfig{
		Audience:       "test-receiver",
		DeliveryMethod: "push",
		EndpointURL:    server.URL,
	})
	if err != nil {
		t.Fatalf("CreateStream error: %v", err)
	}

	event := NewSecurityEvent("starfly-test", "test-receiver", nil)
	AddEvent(event, EventCredentialChange, map[string]interface{}{
		"change_type": ChangeTypeRevoke,
	})

	err = tx.TransmitEvent(ctx, event)
	if err != nil {
		t.Fatalf("TransmitEvent error: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	setData := make([]byte, len(receivedSET))
	copy(setData, receivedSET)
	mu.Unlock()

	if len(setData) == 0 {
		t.Fatal("no SET received by test server")
	}

	// Verify the SET signature using the transmitter's public key set.
	pubKeys, err := tx.PublicKeySet()
	if err != nil {
		t.Fatalf("PublicKeySet error: %v", err)
	}

	token, err := jwt.Parse(setData, jwt.WithKeySet(pubKeys))
	if err != nil {
		t.Fatalf("SET verification failed: %v", err)
	}

	iss, _ := token.Issuer()
	if iss != "starfly-test" {
		t.Errorf("SET issuer = %q, want %q", iss, "starfly-test")
	}

	jti, _ := token.JwtID()
	if jti == "" {
		t.Error("SET JTI should not be empty")
	}
}

func TestTransmitter_TransmitEvent_NoStreams(t *testing.T) {
	tx, err := NewTransmitter()
	if err != nil {
		t.Fatalf("NewTransmitter error: %v", err)
	}

	// Transmit with no streams — should succeed (no-op delivery).
	event := NewSecurityEvent("starfly", "nobody", nil)
	AddEvent(event, EventSessionRevoked, map[string]interface{}{})

	err = tx.TransmitEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("TransmitEvent error: %v", err)
	}
}

func TestTransmitter_TransmitEvent_SyncBusError(t *testing.T) {
	bus := &mockSyncBus{err: errors.New("NATS unavailable")}
	tx, err := NewTransmitter(WithTransmitterSyncBus(bus, "unit-1"))
	if err != nil {
		t.Fatalf("NewTransmitter error: %v", err)
	}

	event := NewSecurityEvent("starfly", "audience", nil)
	AddEvent(event, EventSessionRevoked, map[string]interface{}{})

	// Should succeed even when sync bus fails (fire-and-forget).
	err = tx.TransmitEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("TransmitEvent should succeed even with sync bus error: %v", err)
	}
}

func TestTransmitter_ListStreams(t *testing.T) {
	tx, err := NewTransmitter()
	if err != nil {
		t.Fatalf("NewTransmitter error: %v", err)
	}

	// Empty list initially.
	if got := tx.ListStreams(); len(got) != 0 {
		t.Fatalf("expected 0 streams, got %d", len(got))
	}

	ctx := context.Background()

	// Create two streams.
	s1, err := tx.CreateStream(ctx, &core.StreamConfig{
		Audience:        "https://a.example.com",
		EventsRequested: []string{EventCredentialChange},
		EndpointURL:     "https://a.example.com/events",
	})
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
	_, err = tx.CreateStream(ctx, &core.StreamConfig{
		Audience:        "https://b.example.com",
		EventsRequested: []string{EventSessionRevoked},
	})
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}

	infos := tx.ListStreams()
	if len(infos) != 2 {
		t.Fatalf("expected 2 streams, got %d", len(infos))
	}

	// Verify fields are populated.
	found := false
	for _, info := range infos {
		if info.StreamID == s1.ID {
			found = true
			if info.Audience != "https://a.example.com" {
				t.Errorf("audience = %q, want %q", info.Audience, "https://a.example.com")
			}
			if info.EndpointURL != "https://a.example.com/events" {
				t.Errorf("endpoint = %q", info.EndpointURL)
			}
			if info.Created.IsZero() {
				t.Error("created should not be zero")
			}
		}
	}
	if !found {
		t.Errorf("stream %q not found in ListStreams", s1.ID)
	}

	// Delete one, verify list shrinks.
	if err := tx.DeleteStream(ctx, s1.ID); err != nil {
		t.Fatalf("DeleteStream: %v", err)
	}
	if got := tx.ListStreams(); len(got) != 1 {
		t.Errorf("expected 1 stream after delete, got %d", len(got))
	}
}

// ── Mock store ──────────────────────────────────────────────────────

type mockStore struct{}

func (m *mockStore) Get(_ context.Context, _ string) (*core.StoreEntry, error) { return nil, nil }
func (m *mockStore) Put(_ context.Context, _ string, _ []byte) (*core.StoreEntry, error) {
	return nil, nil
}
func (m *mockStore) Delete(_ context.Context, _ string) error          { return nil }
func (m *mockStore) List(_ context.Context, _ string) ([]string, error) { return nil, nil }

// ── Option function tests ───────────────────────────────────────────

func TestWithTransmitterStore(t *testing.T) {
	tx, err := NewTransmitter(WithTransmitterStore(&mockStore{}))
	if err != nil {
		t.Fatalf("NewTransmitter: %v", err)
	}
	if tx.store == nil {
		t.Error("expected store to be set")
	}
}

func TestWithTransmitterHTTPTimeout(t *testing.T) {
	tx, err := NewTransmitter(WithTransmitterHTTPTimeout(30 * time.Second))
	if err != nil {
		t.Fatalf("NewTransmitter: %v", err)
	}
	if tx.client.Timeout != 30*time.Second {
		t.Errorf("timeout = %v, want 30s", tx.client.Timeout)
	}
}

// ── signSET edge cases ──────────────────────────────────────────────

func TestTransmitter_SignSET_WithSubjectAndTxn(t *testing.T) {
	tx, err := NewTransmitter(WithTransmitterIssuer("test"))
	if err != nil {
		t.Fatalf("NewTransmitter: %v", err)
	}

	event := NewSecurityEvent("test", "audience", &core.SubjectIdentifier{
		Format:   "spiffe",
		SpiffeID: "spiffe://example.com/workload",
	})
	event.TransactionID = "txn-abc"
	AddEvent(event, EventSessionRevoked, map[string]interface{}{})

	signed, err := tx.signSET(event)
	if err != nil {
		t.Fatalf("signSET: %v", err)
	}

	token, err := jwt.ParseInsecure(signed)
	if err != nil {
		t.Fatalf("ParseInsecure: %v", err)
	}

	var subID map[string]interface{}
	if err := token.Get("sub_id", &subID); err != nil {
		t.Fatalf("Get sub_id: %v", err)
	}

	var txn string
	if err := token.Get("txn", &txn); err != nil {
		t.Fatalf("Get txn: %v", err)
	}
	if txn != "txn-abc" {
		t.Errorf("txn = %q, want txn-abc", txn)
	}
}

// ── TransmitEvent edge cases ────────────────────────────────────────

func TestTransmitter_TransmitEvent_AutoFillsFields(t *testing.T) {
	tx, err := NewTransmitter(WithTransmitterIssuer("auto-issuer"))
	if err != nil {
		t.Fatalf("NewTransmitter: %v", err)
	}

	event := &core.SecurityEvent{
		Events: map[string]map[string]interface{}{
			EventSessionRevoked: {"reason": "test"},
		},
	}

	if err := tx.TransmitEvent(context.Background(), event); err != nil {
		t.Fatalf("TransmitEvent: %v", err)
	}
	if event.JTI == "" {
		t.Error("JTI should be auto-filled")
	}
	if event.IssuedAt == 0 {
		t.Error("IssuedAt should be auto-filled")
	}
	if event.Issuer != "auto-issuer" {
		t.Errorf("Issuer = %q, want auto-issuer", event.Issuer)
	}
}

func TestTransmitter_TransmitEvent_DisabledStream(t *testing.T) {
	var delivered atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delivered.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	tx, err := NewTransmitter()
	if err != nil {
		t.Fatalf("NewTransmitter: %v", err)
	}
	ctx := context.Background()

	stream, err := tx.CreateStream(ctx, &core.StreamConfig{
		Audience:       "test",
		DeliveryMethod: "push",
		EndpointURL:    server.URL,
	})
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}

	tx.mu.Lock()
	tx.streams[stream.ID].stream.Status = StreamStatusDisabled
	tx.mu.Unlock()

	event := NewSecurityEvent("starfly", "test", nil)
	AddEvent(event, EventSessionRevoked, map[string]interface{}{})

	if err := tx.TransmitEvent(ctx, event); err != nil {
		t.Fatalf("TransmitEvent: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if delivered.Load() != 0 {
		t.Errorf("delivered = %d, want 0 for disabled stream", delivered.Load())
	}
}

func TestTransmitter_TransmitEvent_NonPushDelivery(t *testing.T) {
	var delivered atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delivered.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	tx, err := NewTransmitter()
	if err != nil {
		t.Fatalf("NewTransmitter: %v", err)
	}
	ctx := context.Background()

	_, err = tx.CreateStream(ctx, &core.StreamConfig{
		Audience:       "test",
		DeliveryMethod: "poll",
		EndpointURL:    server.URL,
	})
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}

	event := NewSecurityEvent("starfly", "test", nil)
	AddEvent(event, EventSessionRevoked, map[string]interface{}{})

	if err := tx.TransmitEvent(ctx, event); err != nil {
		t.Fatalf("TransmitEvent: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if delivered.Load() != 0 {
		t.Errorf("delivered = %d, want 0 for poll delivery", delivered.Load())
	}
}

func TestTransmitter_TransmitEvent_NoEndpointURL(t *testing.T) {
	tx, err := NewTransmitter()
	if err != nil {
		t.Fatalf("NewTransmitter: %v", err)
	}
	ctx := context.Background()

	_, err = tx.CreateStream(ctx, &core.StreamConfig{
		Audience:       "test",
		DeliveryMethod: "push",
	})
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}

	event := NewSecurityEvent("starfly", "test", nil)
	AddEvent(event, EventSessionRevoked, map[string]interface{}{})

	if err := tx.TransmitEvent(ctx, event); err != nil {
		t.Fatalf("TransmitEvent: %v", err)
	}
}

// ── deliverSET edge cases ───────────────────────────────────────────

func TestTransmitter_DeliverSET_Non2xxResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	tx, err := NewTransmitter()
	if err != nil {
		t.Fatalf("NewTransmitter: %v", err)
	}
	ctx := context.Background()

	_, err = tx.CreateStream(ctx, &core.StreamConfig{
		Audience:       "test",
		DeliveryMethod: "push",
		EndpointURL:    server.URL,
	})
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}

	event := NewSecurityEvent("starfly", "test", nil)
	AddEvent(event, EventSessionRevoked, map[string]interface{}{})

	if err := tx.TransmitEvent(ctx, event); err != nil {
		t.Fatalf("TransmitEvent: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
}

func TestTransmitter_DeliverSET_ServerDown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	serverURL := server.URL
	server.Close()

	tx, err := NewTransmitter()
	if err != nil {
		t.Fatalf("NewTransmitter: %v", err)
	}
	ctx := context.Background()

	_, err = tx.CreateStream(ctx, &core.StreamConfig{
		Audience:       "test",
		DeliveryMethod: "push",
		EndpointURL:    serverURL,
	})
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}

	event := NewSecurityEvent("starfly", "test", nil)
	AddEvent(event, EventSessionRevoked, map[string]interface{}{})

	if err := tx.TransmitEvent(ctx, event); err != nil {
		t.Fatalf("TransmitEvent: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
}
