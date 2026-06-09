package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewWithAttestors(t *testing.T) {
	agent, err := NewWithAttestors(Config{
		Server:       "http://localhost:9999",
		Audience:     "test-audience",
		TokenPath:    t.TempDir() + "/token",
		Scope:        "read",
		RefreshRatio: 0.8,
		MetricsAddr:  ":0",
		Version:      "v0.1.0-test",
	}, []Attestor{
		&mockAttestor{name: "k8s-sa", available: true},
	})
	if err != nil {
		t.Fatalf("NewWithAttestors() error: %v", err)
	}
	if agent == nil {
		t.Fatal("expected non-nil agent")
	}
	if agent.config.Audience != "test-audience" {
		t.Errorf("audience = %q, want test-audience", agent.config.Audience)
	}
	if len(agent.attestors) != 1 {
		t.Errorf("attestors count = %d, want 1", len(agent.attestors))
	}
}

func TestNewWithAttestors_BadCACert(t *testing.T) {
	_, err := NewWithAttestors(Config{
		Server:     "http://localhost:9999",
		Audience:   "test",
		TokenPath:  t.TempDir() + "/token",
		CACertPath: "/nonexistent/ca.pem",
	}, nil)
	if err == nil {
		t.Fatal("expected error for bad CA cert path")
	}
}

func TestNew(t *testing.T) {
	agent, err := New(Config{
		Server:       "http://localhost:9999",
		Audience:     "test-audience",
		TokenPath:    t.TempDir() + "/token",
		RefreshRatio: 0.8,
		MetricsAddr:  ":0",
		Version:      "v0.1.0-test",
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if agent == nil {
		t.Fatal("expected non-nil agent")
	}
	if len(agent.attestors) != 5 {
		t.Errorf("expected 5 auto-discovered attestors, got %d", len(agent.attestors))
	}
}

func TestNew_BadCACert(t *testing.T) {
	_, err := New(Config{
		Server:     "http://localhost:9999",
		Audience:   "test",
		TokenPath:  t.TempDir() + "/token",
		CACertPath: "/nonexistent/ca.pem",
	})
	if err == nil {
		t.Fatal("expected error for bad CA cert path")
	}
}

func TestAgent_Run_ContextCancellation(t *testing.T) {
	exchangeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenExchangeResponse{
			AccessToken: "test-token",
			ExpiresIn:   300,
			TokenType:   "Bearer",
		})
	}))
	defer exchangeServer.Close()

	agent, err := NewWithAttestors(Config{
		Server:       exchangeServer.URL,
		Audience:     "test",
		TokenPath:    t.TempDir() + "/token",
		RefreshRatio: 0.8,
		MetricsAddr:  "127.0.0.1:0",
		Version:      "test",
	}, []Attestor{
		&mockAttestor{
			name:      "k8s-sa",
			available: true,
			result: &AttestationResult{
				Source:     "k8s-sa",
				Credential: []byte("fake-token"),
				CredType:   "urn:ietf:params:oauth:token-type:jwt",
			},
		},
		&mockAttestor{name: "binary-self", available: false},
	})
	if err != nil {
		t.Fatalf("NewWithAttestors() error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- agent.Run(ctx)
	}()

	time.Sleep(300 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run() returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not shut down within 5s")
	}
}

func TestAgent_Run_TokenServerStartError(t *testing.T) {
	agent, err := NewWithAttestors(Config{
		Server:      "http://localhost:9999",
		Audience:    "test",
		TokenPath:   "/dev/null/impossible/path/token",
		MetricsAddr: "127.0.0.1:0",
		Version:     "test",
	}, []Attestor{
		&mockAttestor{name: "k8s-sa", available: true},
	})
	if err != nil {
		t.Fatalf("NewWithAttestors() error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	runErr := agent.Run(ctx)
	if runErr == nil {
		t.Fatal("expected error from Run when token server start fails")
	}
}
