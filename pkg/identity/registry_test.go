package identity

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// ── Mock provider for registry tests ────────────────────────────────

type stubProvider struct {
	credType string
	err      error
}

func (s *stubProvider) ValidateWorkload(_ context.Context, _ string, credType string) (*core.WorkloadIdentity, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &core.WorkloadIdentity{
		ID:          "test-id-" + credType,
		TrustDomain: "example.com",
		Attestation: &core.AttestationEvidence{Method: credType},
	}, nil
}

// ── Tests ───────────────────────────────────────────────────────────

func TestRegistry_DispatchToCorrectProvider(t *testing.T) {
	reg := NewRegistry()
	reg.Register("k8s-sa", &stubProvider{credType: "k8s-sa"})
	reg.Register("spiffe-svid", &stubProvider{credType: "spiffe-svid"})
	reg.Register("oidc", &stubProvider{credType: "oidc"})

	tests := []struct {
		credType string
		wantID   string
	}{
		{"k8s-sa", "test-id-k8s-sa"},
		{"spiffe-svid", "test-id-spiffe-svid"},
		{"oidc", "test-id-oidc"},
	}

	for _, tt := range tests {
		t.Run(tt.credType, func(t *testing.T) {
			id, err := reg.ValidateWorkload(context.Background(), "some-cred", tt.credType)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if id.ID != tt.wantID {
				t.Errorf("ID = %q, want %q", id.ID, tt.wantID)
			}
			if id.Attestation.Method != tt.credType {
				t.Errorf("Method = %q, want %q", id.Attestation.Method, tt.credType)
			}
		})
	}
}

func TestRegistry_UnknownCredType(t *testing.T) {
	reg := NewRegistry()
	reg.Register("k8s-sa", &stubProvider{credType: "k8s-sa"})
	reg.Register("oidc", &stubProvider{credType: "oidc"})

	_, err := reg.ValidateWorkload(context.Background(), "some-cred", "kerberos")
	if err == nil {
		t.Fatal("expected error for unknown credential type")
	}

	// Error should list supported types.
	if !strings.Contains(err.Error(), "k8s-sa") {
		t.Errorf("error should list supported types, got: %v", err)
	}
	if !strings.Contains(err.Error(), "oidc") {
		t.Errorf("error should list supported types, got: %v", err)
	}
}

func TestRegistry_ProviderError(t *testing.T) {
	reg := NewRegistry()
	reg.Register("failing", &stubProvider{err: errors.New("validation failed")})

	_, err := reg.ValidateWorkload(context.Background(), "bad-cred", "failing")
	if err == nil {
		t.Fatal("expected error from provider")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("expected provider error, got: %v", err)
	}
}

func TestRegistry_OverwriteProvider(t *testing.T) {
	reg := NewRegistry()
	reg.Register("k8s-sa", &stubProvider{err: errors.New("old provider")})
	reg.Register("k8s-sa", &stubProvider{credType: "k8s-sa"}) // overwrite

	id, err := reg.ValidateWorkload(context.Background(), "cred", "k8s-sa")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.ID != "test-id-k8s-sa" {
		t.Errorf("ID = %q, want %q", id.ID, "test-id-k8s-sa")
	}
}

func TestRegistry_EmptyRegistry(t *testing.T) {
	reg := NewRegistry()

	_, err := reg.ValidateWorkload(context.Background(), "cred", "anything")
	if err == nil {
		t.Fatal("expected error from empty registry")
	}
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	reg := NewRegistry()
	var wg sync.WaitGroup

	// Concurrent registrations.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			credType := strings.Repeat("x", n%5+1) // varied keys
			reg.Register(credType, &stubProvider{credType: credType})
		}(i)
	}

	// Concurrent reads while registering.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// May or may not find it — just must not panic or race.
			_, _ = reg.ValidateWorkload(context.Background(), "cred", "xx")
		}()
	}

	wg.Wait()
}

func TestRegistry_SupportedTypesAreSorted(t *testing.T) {
	reg := NewRegistry()
	reg.Register("oidc", &stubProvider{})
	reg.Register("k8s-sa", &stubProvider{})
	reg.Register("spiffe-svid", &stubProvider{})

	_, err := reg.ValidateWorkload(context.Background(), "cred", "unknown")
	if err == nil {
		t.Fatal("expected error")
	}

	// Supported types should be alphabetically sorted.
	errMsg := err.Error()
	k8sIdx := strings.Index(errMsg, "k8s-sa")
	oidcIdx := strings.Index(errMsg, "oidc")
	spiffeIdx := strings.Index(errMsg, "spiffe-svid")

	if k8sIdx > oidcIdx || oidcIdx > spiffeIdx {
		t.Errorf("supported types not sorted: %v", errMsg)
	}
}

func TestRegistry_Unregister(t *testing.T) {
	reg := NewRegistry()
	reg.Register("k8s-sa", &stubProvider{credType: "k8s-sa"})
	reg.Register("oidc", &stubProvider{credType: "oidc"})

	if reg.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", reg.Len())
	}

	// Unregister existing.
	if !reg.Unregister("k8s-sa") {
		t.Error("Unregister(k8s-sa) should return true")
	}
	if reg.Len() != 1 {
		t.Errorf("Len() = %d after unregister, want 1", reg.Len())
	}

	// Unregister non-existent.
	if reg.Unregister("k8s-sa") {
		t.Error("second Unregister(k8s-sa) should return false")
	}

	// Validate the removed provider is gone.
	_, err := reg.ValidateWorkload(context.Background(), "cred", "k8s-sa")
	if err == nil {
		t.Fatal("expected error after unregistering provider")
	}
}

func TestRegistry_List(t *testing.T) {
	reg := NewRegistry()
	reg.Register("oidc", &stubProvider{})
	reg.Register("k8s-sa", &stubProvider{})
	reg.Register("spiffe-svid", &stubProvider{})

	types := reg.List()
	if len(types) != 3 {
		t.Fatalf("List() returned %d types, want 3", len(types))
	}
	// Should be sorted.
	if types[0] != "k8s-sa" || types[1] != "oidc" || types[2] != "spiffe-svid" {
		t.Errorf("List() = %v, want [k8s-sa oidc spiffe-svid]", types)
	}
}

func TestRegistry_Len(t *testing.T) {
	reg := NewRegistry()
	if reg.Len() != 0 {
		t.Errorf("Len() = %d for empty registry, want 0", reg.Len())
	}
	reg.Register("a", &stubProvider{})
	reg.Register("b", &stubProvider{})
	if reg.Len() != 2 {
		t.Errorf("Len() = %d, want 2", reg.Len())
	}
}
