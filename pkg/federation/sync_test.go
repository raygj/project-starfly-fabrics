package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────
// Mock RevocationSyncer
// ─────────────────────────────────────────────────────────────────────

type mockRevocationSyncer struct {
	mu           sync.Mutex
	hash         string
	exported     []byte
	imported     []byte
	cleanupCount int
}

func (m *mockRevocationSyncer) Hash() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hash
}

func (m *mockRevocationSyncer) Export() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.exported, nil
}

func (m *mockRevocationSyncer) Import(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.imported = make([]byte, len(data))
	copy(m.imported, data)
	return nil
}

func (m *mockRevocationSyncer) Cleanup(_ context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupCount++
	return 0, nil
}

func (m *mockRevocationSyncer) getImported() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.imported == nil {
		return nil
	}
	cp := make([]byte, len(m.imported))
	copy(cp, m.imported)
	return cp
}

// ─────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────

// newMockServer creates an httptest.Server that serves revocation hash
// and export endpoints. The peerHash controls what hash is returned.
func newMockServer(peerHash string, exportPayload []byte) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/federation/revocation-hash", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]string{"hash": peerHash}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/federation/revocation-export", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(exportPayload)
	})
	return httptest.NewServer(mux)
}

func newTestSyncer(endpoint string, mock *mockRevocationSyncer) *Syncer {
	cfg := SignalGatewayConfig{
		Peers: []PeerSignalConfig{
			{
				FabricID:     "fabric-eu",
				Endpoint:     endpoint,
				SyncInterval: 1 * time.Hour, // won't tick in tests
			},
		},
	}
	return NewSyncer(cfg, mock, WithSyncerHTTPClient(&http.Client{Timeout: 5 * time.Second}))
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

func TestNewSyncer_CreatesPeerStates(t *testing.T) {
	mock := &mockRevocationSyncer{hash: "sha256:abc"}
	cfg := SignalGatewayConfig{
		Peers: []PeerSignalConfig{
			{FabricID: "peer-a", Endpoint: "https://a.example.com"},
			{FabricID: "peer-b", Endpoint: "https://b.example.com"},
			{FabricID: "peer-c", Endpoint: "https://c.example.com"},
		},
	}
	s := NewSyncer(cfg, mock)

	states := s.State()
	if len(states) != 3 {
		t.Fatalf("expected 3 peer states, got %d", len(states))
	}
	for _, id := range []string{"peer-a", "peer-b", "peer-c"} {
		if _, ok := states[id]; !ok {
			t.Errorf("missing peer state for %s", id)
		}
	}
}

func TestSyncWithPeer_MatchingHashes_NoFullSync(t *testing.T) {
	localHash := "sha256:deadbeef"
	mock := &mockRevocationSyncer{hash: localHash}

	srv := newMockServer(localHash, nil) // same hash, export should not be called
	defer srv.Close()

	s := newTestSyncer(srv.URL, mock)
	peer := s.peers[0]

	if err := s.syncWithPeer(t.Context(), peer); err != nil {
		t.Fatalf("syncWithPeer: %v", err)
	}

	states := s.State()
	st := states[peer.FabricID]
	if st.SyncCount != 1 {
		t.Errorf("expected SyncCount 1, got %d", st.SyncCount)
	}
	if st.FullSyncCount != 0 {
		t.Errorf("expected FullSyncCount 0, got %d", st.FullSyncCount)
	}
	if st.MismatchCount != 0 {
		t.Errorf("expected MismatchCount 0, got %d", st.MismatchCount)
	}
	if mock.getImported() != nil {
		t.Error("Import should not have been called when hashes match")
	}
}

func TestSyncWithPeer_MismatchedHashes_TriggersFullSync(t *testing.T) {
	localHash := "sha256:local111"
	peerHash := "sha256:peer222"
	exportData := []byte(`{"entries":[],"count":0,"hash":"sha256:empty"}`)

	mock := &mockRevocationSyncer{hash: localHash}
	srv := newMockServer(peerHash, exportData)
	defer srv.Close()

	s := newTestSyncer(srv.URL, mock)
	peer := s.peers[0]

	if err := s.syncWithPeer(t.Context(), peer); err != nil {
		t.Fatalf("syncWithPeer: %v", err)
	}

	imported := mock.getImported()
	if imported == nil {
		t.Fatal("expected Import to be called on hash mismatch")
	}
	if string(imported) != string(exportData) {
		t.Errorf("imported data mismatch: got %s", string(imported))
	}
}

func TestSyncWithPeer_UpdatesSyncPeerStateCounts(t *testing.T) {
	localHash := "sha256:aaa"
	peerHash := "sha256:bbb"
	exportData := []byte(`{"entries":[],"count":0,"hash":"sha256:empty"}`)

	mock := &mockRevocationSyncer{hash: localHash}
	srv := newMockServer(peerHash, exportData)
	defer srv.Close()

	s := newTestSyncer(srv.URL, mock)
	peer := s.peers[0]

	// First sync.
	if err := s.syncWithPeer(t.Context(), peer); err != nil {
		t.Fatalf("syncWithPeer: %v", err)
	}

	// Second sync.
	if err := s.syncWithPeer(t.Context(), peer); err != nil {
		t.Fatalf("syncWithPeer: %v", err)
	}

	states := s.State()
	st := states[peer.FabricID]
	if st.SyncCount != 2 {
		t.Errorf("expected SyncCount 2, got %d", st.SyncCount)
	}
	if st.LastSync.IsZero() {
		t.Error("expected LastSync to be set")
	}
	if st.PeerHash != peerHash {
		t.Errorf("expected PeerHash %q, got %q", peerHash, st.PeerHash)
	}
}

func TestSyncWithPeer_Mismatch_IncrementsCounters(t *testing.T) {
	exportData := []byte(`{"entries":[],"count":0,"hash":"sha256:empty"}`)
	mock := &mockRevocationSyncer{hash: "sha256:local"}
	srv := newMockServer("sha256:peer", exportData)
	defer srv.Close()

	s := newTestSyncer(srv.URL, mock)
	peer := s.peers[0]

	if err := s.syncWithPeer(t.Context(), peer); err != nil {
		t.Fatalf("syncWithPeer: %v", err)
	}

	states := s.State()
	st := states[peer.FabricID]
	if st.MismatchCount != 1 {
		t.Errorf("expected MismatchCount 1, got %d", st.MismatchCount)
	}
	if st.FullSyncCount != 1 {
		t.Errorf("expected FullSyncCount 1, got %d", st.FullSyncCount)
	}
	if st.LastMismatch.IsZero() {
		t.Error("expected LastMismatch to be set")
	}
}

func TestSyncWithPeer_HashFetchError_IncrementsErrorCount(t *testing.T) {
	// Server that returns 500 on hash endpoint.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	mock := &mockRevocationSyncer{hash: "sha256:local"}
	s := newTestSyncer(srv.URL, mock)
	peer := s.peers[0]

	err := s.syncWithPeer(t.Context(), peer)
	if err == nil {
		t.Fatal("expected error on 500 response")
	}

	states := s.State()
	st := states[peer.FabricID]
	if st.ErrorCount != 1 {
		t.Errorf("expected ErrorCount 1, got %d", st.ErrorCount)
	}
	if st.LastError == "" {
		t.Error("expected LastError to be set")
	}
}

func TestState_ReturnsDeepCopy(t *testing.T) {
	mock := &mockRevocationSyncer{hash: "sha256:test"}
	cfg := SignalGatewayConfig{
		Peers: []PeerSignalConfig{
			{FabricID: "peer-x", Endpoint: "https://x.example.com"},
		},
	}
	s := NewSyncer(cfg, mock)

	state1 := s.State()
	state1["peer-x"].SyncCount = 999
	state1["peer-x"].LastError = "mutated"

	state2 := s.State()
	if state2["peer-x"].SyncCount != 0 {
		t.Errorf("expected SyncCount 0 in fresh copy, got %d", state2["peer-x"].SyncCount)
	}
	if state2["peer-x"].LastError != "" {
		t.Errorf("expected empty LastError in fresh copy, got %q", state2["peer-x"].LastError)
	}
}

func TestSyncWithPeer_ConcurrentSafety(t *testing.T) {
	exportData := []byte(`{"entries":[],"count":0,"hash":"sha256:empty"}`)
	mock := &mockRevocationSyncer{hash: "sha256:local"}
	srv := newMockServer("sha256:peer", exportData)
	defer srv.Close()

	s := newTestSyncer(srv.URL, mock)
	peer := s.peers[0]

	var wg sync.WaitGroup
	errs := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.syncWithPeer(t.Context(), peer); err != nil {
				errs <- err
			}
			// Also read state concurrently.
			_ = s.State()
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent syncWithPeer error: %v", err)
	}

	states := s.State()
	st := states[peer.FabricID]
	if st.SyncCount != 20 {
		t.Errorf("expected SyncCount 20, got %d", st.SyncCount)
	}
}

func TestWithSyncerLogger(t *testing.T) {
	mock := &mockRevocationSyncer{hash: "sha256:abc"}
	cfg := SignalGatewayConfig{
		Peers: []PeerSignalConfig{
			{FabricID: "peer-a", Endpoint: "https://a.example.com"},
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewSyncer(cfg, mock, WithSyncerLogger(logger))
	if s.logger != logger {
		t.Error("WithSyncerLogger did not set logger")
	}
}

func TestSyncWithPeer_ExportFetchError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/federation/revocation-hash", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"hash": "sha256:different"})
	})
	mux.HandleFunc("/v1/federation/revocation-export", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mock := &mockRevocationSyncer{hash: "sha256:local"}
	s := newTestSyncer(srv.URL, mock)
	peer := s.peers[0]

	err := s.syncWithPeer(t.Context(), peer)
	if err == nil {
		t.Fatal("expected error when export endpoint returns 500")
	}

	states := s.State()
	st := states[peer.FabricID]
	if st.ErrorCount != 1 {
		t.Errorf("expected ErrorCount 1, got %d", st.ErrorCount)
	}
}

func TestSyncWithPeer_InvalidHashJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/federation/revocation-hash", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not-json"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mock := &mockRevocationSyncer{hash: "sha256:local"}
	s := newTestSyncer(srv.URL, mock)
	peer := s.peers[0]

	err := s.syncWithPeer(t.Context(), peer)
	if err == nil {
		t.Fatal("expected error on invalid JSON hash response")
	}
	if !strings.Contains(err.Error(), "decoding hash response") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestPeerBaseURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://starfly-eu.example.com/v1/signals/events", "https://starfly-eu.example.com"},
		{"https://starfly-eu.example.com", "https://starfly-eu.example.com"},
		{"http://localhost:8080/api/v1/signals", "http://localhost:8080"},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("input=%s", tc.input), func(t *testing.T) {
			got := peerBaseURL(tc.input)
			if got != tc.want {
				t.Errorf("peerBaseURL(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestSyncWithPeer_CleanupCalledBeforeHash(t *testing.T) {
	localHash := "sha256:deadbeef"
	mock := &mockRevocationSyncer{hash: localHash}

	srv := newMockServer(localHash, nil)
	defer srv.Close()

	s := newTestSyncer(srv.URL, mock)
	peer := s.peers[0]

	if err := s.syncWithPeer(t.Context(), peer); err != nil {
		t.Fatalf("syncWithPeer: %v", err)
	}

	mock.mu.Lock()
	count := mock.cleanupCount
	mock.mu.Unlock()

	if count != 1 {
		t.Errorf("expected Cleanup called once before Hash, got %d calls", count)
	}
}

func TestSyncWithPeer_OversizedExportReturnsError(t *testing.T) {
	// Create an export response that exceeds 10 MiB.
	oversize := strings.Repeat("x", 10<<20+1)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/federation/revocation-hash", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"hash": "sha256:peer"})
	})
	mux.HandleFunc("/v1/federation/revocation-export", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(oversize))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mock := &mockRevocationSyncer{hash: "sha256:local"}
	s := newTestSyncer(srv.URL, mock)
	peer := s.peers[0]

	err := s.syncWithPeer(t.Context(), peer)
	if err == nil {
		t.Fatal("expected error for oversized export response")
	}
	if !strings.Contains(err.Error(), "10 MiB") {
		t.Errorf("expected error to mention size limit, got: %v", err)
	}

	// Import should NOT have been called.
	if mock.getImported() != nil {
		t.Error("Import should not be called when export exceeds size limit")
	}
}

func TestSyncer_DoubleClose_NoPanic(t *testing.T) {
	mock := &mockRevocationSyncer{hash: "sha256:abc"}
	srv := newMockServer("sha256:abc", nil)
	defer srv.Close()

	s := newTestSyncer(srv.URL, mock)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// First Close should succeed.
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	// Second Close must not panic.
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestSyncer_DoubleStart_ReturnsError(t *testing.T) {
	mock := &mockRevocationSyncer{hash: "sha256:abc"}
	srv := newMockServer("sha256:abc", nil)
	defer srv.Close()

	s := newTestSyncer(srv.URL, mock)

	if err := s.Start(); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Second Start must return an error, not spawn duplicate goroutines.
	if err := s.Start(); err == nil {
		t.Fatal("expected error on second Start, got nil")
	}
}
