package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRenewer_RenewsAtRatio(t *testing.T) {
	var exchangeCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		exchangeCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenExchangeResponse{
			AccessToken: "token-refreshed",
			ExpiresIn:   2, // 2 seconds TTL
			TokenType:   "Bearer",
		})
	}))
	defer server.Close()

	client, _ := NewExchangeClient(ExchangeClientConfig{
		ServerURL: server.URL,
		Audience:  "test",
	})

	tokenSrv := NewFileTokenServer(t.TempDir() + "/token")
	_ = tokenSrv.Start(context.Background())

	renewer := NewRenewer(RenewerConfig{
		Attestors: []Attestor{
			&mockAttestor{
				name:      "k8s-sa",
				available: true,
				result: &AttestationResult{
					Source:     "k8s-sa",
					Credential: []byte("test-token"),
					CredType:   "urn:ietf:params:oauth:token-type:jwt",
				},
			},
		},
		Client:       client,
		Server:       tokenSrv,
		RefreshRatio: 0.5, // renew at 50% of 2s = 1s
		AgentVersion: "test",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
	defer cancel()

	_ = renewer.Run(ctx)

	// With 2s TTL and 0.5 ratio, we expect: initial + at least 1 renewal in 3.5s
	count := exchangeCount.Load()
	if count < 2 {
		t.Errorf("expected at least 2 exchanges, got %d", count)
	}
}

func TestRenewer_CleanShutdown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenExchangeResponse{
			AccessToken: "token",
			ExpiresIn:   300,
			TokenType:   "Bearer",
		})
	}))
	defer server.Close()

	client, _ := NewExchangeClient(ExchangeClientConfig{
		ServerURL: server.URL,
		Audience:  "test",
	})

	tokenSrv := NewFileTokenServer(t.TempDir() + "/token")
	_ = tokenSrv.Start(context.Background())

	renewer := NewRenewer(RenewerConfig{
		Attestors: []Attestor{
			&mockAttestor{
				name:      "k8s-sa",
				available: true,
				result: &AttestationResult{
					Source:     "k8s-sa",
					Credential: []byte("test-token"),
					CredType:   "urn:ietf:params:oauth:token-type:jwt",
				},
			},
		},
		Client:       client,
		Server:       tokenSrv,
		RefreshRatio: 0.8,
		AgentVersion: "test",
	})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		_ = renewer.Run(ctx)
		close(done)
	}()

	// Let it do the initial exchange.
	time.Sleep(500 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Clean shutdown.
	case <-time.After(2 * time.Second):
		t.Fatal("renewer did not shut down within 2s")
	}
}

func TestRenewer_BackoffExhausted(t *testing.T) {
	// Server always returns 500 — all retries will fail.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server_error"}`))
	}))
	defer server.Close()

	client, _ := NewExchangeClient(ExchangeClientConfig{
		ServerURL: server.URL,
		Audience:  "test",
	})

	tokenSrv := NewFileTokenServer(t.TempDir() + "/token")
	_ = tokenSrv.Start(context.Background())

	renewer := NewRenewer(RenewerConfig{
		Attestors: []Attestor{
			&mockAttestor{
				name:      "k8s-sa",
				available: true,
				result: &AttestationResult{
					Source:     "k8s-sa",
					Credential: []byte("test-token"),
					CredType:   "urn:ietf:params:oauth:token-type:jwt",
				},
			},
		},
		Client:       client,
		Server:       tokenSrv,
		RefreshRatio: 0.8,
		AgentVersion: "test",
		// Use very short delays so the test runs fast.
		BackoffDelays: []time.Duration{10 * time.Millisecond, 10 * time.Millisecond},
	})

	// backoff() should return ErrBackoffExhausted after all retries fail.
	err := renewer.backoff(context.Background())
	if err == nil {
		t.Fatal("expected error after backoff exhaustion")
	}
	if err != ErrBackoffExhausted {
		t.Errorf("expected ErrBackoffExhausted, got: %v", err)
	}
}

func TestNewRenewer_DefaultRatio(t *testing.T) {
	client, _ := NewExchangeClient(ExchangeClientConfig{
		ServerURL: "http://localhost:9999",
		Audience:  "test",
	})

	r := NewRenewer(RenewerConfig{
		Client:       client,
		Server:       NewFileTokenServer(t.TempDir() + "/token"),
		RefreshRatio: 0,
		AgentVersion: "test",
	})
	if r.ratio != 0.8 {
		t.Errorf("ratio = %f, want 0.8 (default)", r.ratio)
	}
}

func TestNewRenewer_InvalidRatioAboveOne(t *testing.T) {
	client, _ := NewExchangeClient(ExchangeClientConfig{
		ServerURL: "http://localhost:9999",
		Audience:  "test",
	})

	r := NewRenewer(RenewerConfig{
		Client:       client,
		Server:       NewFileTokenServer(t.TempDir() + "/token"),
		RefreshRatio: 1.5,
		AgentVersion: "test",
	})
	if r.ratio != 0.8 {
		t.Errorf("ratio = %f, want 0.8 (default for invalid value)", r.ratio)
	}
}

func TestNewRenewer_NegativeRatio(t *testing.T) {
	client, _ := NewExchangeClient(ExchangeClientConfig{
		ServerURL: "http://localhost:9999",
		Audience:  "test",
	})

	r := NewRenewer(RenewerConfig{
		Client:       client,
		Server:       NewFileTokenServer(t.TempDir() + "/token"),
		RefreshRatio: -0.5,
		AgentVersion: "test",
	})
	if r.ratio != 0.8 {
		t.Errorf("ratio = %f, want 0.8 (default for negative)", r.ratio)
	}
}

func TestRenewer_BackoffContextCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server_error"}`))
	}))
	defer server.Close()

	client, _ := NewExchangeClient(ExchangeClientConfig{
		ServerURL: server.URL,
		Audience:  "test",
	})

	renewer := NewRenewer(RenewerConfig{
		Attestors: []Attestor{
			&mockAttestor{
				name:      "k8s-sa",
				available: true,
				result: &AttestationResult{
					Source:     "k8s-sa",
					Credential: []byte("test-token"),
					CredType:   "urn:ietf:params:oauth:token-type:jwt",
				},
			},
		},
		Client:        client,
		Server:        NewFileTokenServer(t.TempDir() + "/token"),
		RefreshRatio:  0.8,
		AgentVersion:  "test",
		BackoffDelays: []time.Duration{5 * time.Second, 5 * time.Second},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := renewer.backoff(ctx)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if err == ErrBackoffExhausted {
		t.Error("expected context cancellation, not backoff exhaustion")
	}
}

func TestRenewer_BackoffSuccessOnRetry(t *testing.T) {
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := callCount.Add(1)
		if n <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"server_error"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenExchangeResponse{
			AccessToken: "recovered-token",
			ExpiresIn:   300,
			TokenType:   "Bearer",
		})
	}))
	defer server.Close()

	client, _ := NewExchangeClient(ExchangeClientConfig{
		ServerURL: server.URL,
		Audience:  "test",
	})

	metrics := NewMetrics()
	renewer := NewRenewer(RenewerConfig{
		Attestors: []Attestor{
			&mockAttestor{
				name:      "k8s-sa",
				available: true,
				result: &AttestationResult{
					Source:     "k8s-sa",
					Credential: []byte("test-token"),
					CredType:   "urn:ietf:params:oauth:token-type:jwt",
				},
			},
		},
		Client:        client,
		Server:        NewFileTokenServer(t.TempDir() + "/token"),
		RefreshRatio:  0.8,
		AgentVersion:  "test",
		Metrics:       metrics,
		BackoffDelays: []time.Duration{10 * time.Millisecond, 10 * time.Millisecond, 10 * time.Millisecond},
	})

	err := renewer.backoff(context.Background())
	if err != nil {
		t.Fatalf("backoff() should succeed on retry, got: %v", err)
	}
}

func TestRenewer_RunWithMetrics(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenExchangeResponse{
			AccessToken: "token-with-metrics",
			ExpiresIn:   2,
			TokenType:   "Bearer",
		})
	}))
	defer server.Close()

	client, _ := NewExchangeClient(ExchangeClientConfig{
		ServerURL: server.URL,
		Audience:  "test",
	})

	metrics := NewMetrics()
	tokenSrv := NewFileTokenServer(t.TempDir() + "/token")
	_ = tokenSrv.Start(context.Background())

	renewer := NewRenewer(RenewerConfig{
		Attestors: []Attestor{
			&mockAttestor{
				name:      "k8s-sa",
				available: true,
				result: &AttestationResult{
					Source:     "k8s-sa",
					Credential: []byte("test-token"),
					CredType:   "urn:ietf:params:oauth:token-type:jwt",
				},
			},
		},
		Client:       client,
		Server:       tokenSrv,
		RefreshRatio: 0.8,
		AgentVersion: "test",
		Metrics:      metrics,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = renewer.Run(ctx)

	mfs, _ := metrics.registry.Gather()
	var foundRefresh bool
	for _, mf := range mfs {
		if mf.GetName() == "starfly_agent_token_refreshes_total" {
			for _, m := range mf.GetMetric() {
				if m.GetCounter().GetValue() > 0 {
					foundRefresh = true
				}
			}
		}
	}
	if !foundRefresh {
		t.Error("expected TokenRefreshesTotal to be incremented")
	}
}

func TestRenewer_RunExchangeErrorThenCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server_error"}`))
	}))
	defer server.Close()

	client, _ := NewExchangeClient(ExchangeClientConfig{
		ServerURL: server.URL,
		Audience:  "test",
	})

	metrics := NewMetrics()
	tokenSrv := NewFileTokenServer(t.TempDir() + "/token")
	_ = tokenSrv.Start(context.Background())

	renewer := NewRenewer(RenewerConfig{
		Attestors: []Attestor{
			&mockAttestor{
				name:      "k8s-sa",
				available: true,
				result: &AttestationResult{
					Source:     "k8s-sa",
					Credential: []byte("test-token"),
					CredType:   "urn:ietf:params:oauth:token-type:jwt",
				},
			},
		},
		Client:        client,
		Server:        tokenSrv,
		RefreshRatio:  0.8,
		AgentVersion:  "test",
		Metrics:       metrics,
		BackoffDelays: []time.Duration{10 * time.Millisecond},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = renewer.Run(ctx)
}

func TestRenewer_AttestationFailureIncrementsMetric(t *testing.T) {
	client, _ := NewExchangeClient(ExchangeClientConfig{
		ServerURL: "http://127.0.0.1:1",
		Audience:  "test",
	})

	metrics := NewMetrics()

	renewer := NewRenewer(RenewerConfig{
		Attestors: []Attestor{
			// All attestors unavailable — BundleAttestations will fail.
			&mockAttestor{name: "k8s-sa", available: false},
		},
		Client:       client,
		Server:       NewFileTokenServer(t.TempDir() + "/token"),
		RefreshRatio: 0.8,
		AgentVersion: "test",
		Metrics:      metrics,
	})

	// exchangeOnce should fail with attestation error and increment counter.
	_, err := renewer.exchangeOnce(context.Background())
	if err == nil {
		t.Fatal("expected attestation error")
	}

	// Verify the AttestationFailures counter was incremented.
	// We can't easily read a prometheus CounterVec value directly,
	// but we can verify the metric was collected without panicking.
	ch := make(chan struct{})
	go func() {
		mfs, _ := metrics.registry.Gather()
		for _, mf := range mfs {
			if mf.GetName() == "starfly_agent_attestation_failures_total" {
				for _, m := range mf.GetMetric() {
					if m.GetCounter().GetValue() > 0 {
						close(ch)
						return
					}
				}
			}
		}
	}()

	select {
	case <-ch:
		// Counter was incremented.
	case <-time.After(time.Second):
		t.Error("AttestationFailures counter was not incremented")
	}
}
