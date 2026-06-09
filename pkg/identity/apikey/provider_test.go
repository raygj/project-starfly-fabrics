package apikey

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// hashKey returns the hex-encoded SHA-256 hash of key.
func hashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

func TestDevMode_HappyPath(t *testing.T) {
	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), "any-key-value", credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantPrefix := hashKey("any-key-value")[:8]
	wantID := fmt.Sprintf("wimse://dev.local/apikey/%s", wantPrefix)
	if identity.ID != wantID {
		t.Errorf("ID = %q, want %q", identity.ID, wantID)
	}
	if identity.TrustDomain != "dev.local" {
		t.Errorf("TrustDomain = %q, want %q", identity.TrustDomain, "dev.local")
	}
	if identity.Attestation == nil || identity.Attestation.Method != credType {
		t.Errorf("Attestation method = %v, want %q", identity.Attestation, credType)
	}
}

func TestProdMode_HappyPath(t *testing.T) {
	rawKey := "sk-prod-abc123"
	h := hashKey(rawKey)

	p, err := NewProvider(WithKeys(map[string]*KeyIdentity{
		h: {
			WorkloadID:  "wimse://prod.example.com/apikey/legacy-svc",
			TrustDomain: "prod.example.com",
			Claims:      map[string]string{"team": "platform"},
		},
	}))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), rawKey, credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if identity.ID != "wimse://prod.example.com/apikey/legacy-svc" {
		t.Errorf("ID = %q, want %q", identity.ID, "wimse://prod.example.com/apikey/legacy-svc")
	}
	if identity.TrustDomain != "prod.example.com" {
		t.Errorf("TrustDomain = %q, want %q", identity.TrustDomain, "prod.example.com")
	}
	if identity.Attestation == nil || identity.Attestation.Method != credType {
		t.Errorf("Attestation method = %v, want %q", identity.Attestation, credType)
	}
	if v, ok := identity.Claims["team"]; !ok || v != "platform" {
		t.Errorf("claim[team] = %v, want %q", v, "platform")
	}
}

func TestProdMode_UnknownKey(t *testing.T) {
	p, err := NewProvider() // empty registry
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), "unknown-key", credType)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !contains(err.Error(), "unknown API key") {
		t.Errorf("error = %q, want containing %q", err.Error(), "unknown API key")
	}
}

func TestProdMode_ExpiredKey(t *testing.T) {
	rawKey := "sk-expired-key"
	h := hashKey(rawKey)

	p, err := NewProvider(WithKeys(map[string]*KeyIdentity{
		h: {
			WorkloadID:  "wimse://prod.example.com/apikey/old-svc",
			TrustDomain: "prod.example.com",
			ExpiresAt:   time.Now().Add(-1 * time.Hour), // expired 1 hour ago
		},
	}))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), rawKey, credType)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !contains(err.Error(), "expired") {
		t.Errorf("error = %q, want containing %q", err.Error(), "expired")
	}
}

func TestProdMode_NoExpiry(t *testing.T) {
	rawKey := "sk-no-expiry"
	h := hashKey(rawKey)

	p, err := NewProvider(WithKeys(map[string]*KeyIdentity{
		h: {
			WorkloadID:  "wimse://prod.example.com/apikey/evergreen-svc",
			TrustDomain: "prod.example.com",
			// ExpiresAt is zero value — no expiry
		},
	}))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), rawKey, credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.ID != "wimse://prod.example.com/apikey/evergreen-svc" {
		t.Errorf("ID = %q, want %q", identity.ID, "wimse://prod.example.com/apikey/evergreen-svc")
	}
}

func TestEmptyKey(t *testing.T) {
	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), "", credType)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !contains(err.Error(), "empty") {
		t.Errorf("error = %q, want containing %q", err.Error(), "empty")
	}
}

func TestWrongCredType(t *testing.T) {
	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), "some-key", "jwt")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !contains(err.Error(), "unsupported credential type") {
		t.Errorf("error = %q, want containing %q", err.Error(), "unsupported credential type")
	}
}

func TestClaimsIncludePrefix(t *testing.T) {
	rawKey := "sk-claims-test"
	h := hashKey(rawKey)
	wantPrefix := h[:8]

	p, err := NewProvider(WithKeys(map[string]*KeyIdentity{
		h: {
			WorkloadID:  "wimse://test.local/apikey/claims-svc",
			TrustDomain: "test.local",
			Claims:      map[string]string{"env": "staging"},
		},
	}))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), rawKey, credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if v, ok := identity.Claims["key_prefix"]; !ok || v != wantPrefix {
		t.Errorf("claim[key_prefix] = %v, want %q", v, wantPrefix)
	}
	if v, ok := identity.Claims["migration_path"]; !ok || v != "true" {
		t.Errorf("claim[migration_path] = %v, want %q", v, "true")
	}
	if v, ok := identity.Claims["env"]; !ok || v != "staging" {
		t.Errorf("claim[env] = %v, want %q", v, "staging")
	}
}

func TestInterfaceAssertion(t *testing.T) {
	var _ core.IdentityProvider = (*Provider)(nil)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
