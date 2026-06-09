package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/signals"
)

// BenchmarkRelayRevocation measures round-trip relay latency via httptest.
func BenchmarkRelayRevocation(b *testing.B) {
	// Setup: create inbound handler + httptest server as the relay target.
	idx := signals.NewRevocationIndex()
	inbound := NewInboundHandler(
		[]PeerSignalConfig{{FabricID: "bench-source", Endpoint: "placeholder"}},
		WithInboundRevocation(idx),
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/federation/revocation-relay", func(w http.ResponseWriter, r *http.Request) {
		var sig RevocationSignal
		if err := json.NewDecoder(r.Body).Decode(&sig); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = inbound.ReceiveRevocation(r.Context(), sig)
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	relay := NewRelay(SignalGatewayConfig{
		Peers: []PeerSignalConfig{{
			FabricID: "bench-target",
			Endpoint: server.URL + "/v1/federation/revocation-relay",
		}},
	}, WithRelayUnitID("bench-source"))

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := relay.RelayRevocation(ctx, RevocationSignal{
			SubjectID:    fmt.Sprintf("bench-subject-%d", i),
			Reason:       "benchmark",
			RevokedAt:    time.Now().UTC(),
			ExpiresAt:    time.Now().Add(1 * time.Hour),
			EventJTI:     fmt.Sprintf("bench-jti-%d", i),
			SourceFabric: "bench-source",
			TrustDomain:  "bench.local",
		})
		if err != nil {
			b.Fatalf("relay: %v", err)
		}
	}
}

// BenchmarkSyncerHashCheck measures the hash comparison HTTP call cost.
func BenchmarkSyncerHashCheck(b *testing.B) {
	idx := signals.NewRevocationIndex()
	// Pre-populate with some entries.
	ctx := context.Background()
	for i := 0; i < 1000; i++ {
		if err := idx.Revoke(ctx, fmt.Sprintf("subject-%d", i), "preload", time.Now().Add(1*time.Hour)); err != nil {
			b.Fatalf("preloading revocation index: %v", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/federation/revocation-hash", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"hash": idx.Hash()})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	// Create an HTTP client to call the hash endpoint.
	client := server.Client()
	url := server.URL + "/v1/federation/revocation-hash"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(url)
		if err != nil {
			b.Fatalf("hash check: %v", err)
		}
		_ = resp.Body.Close()
	}
}
