package exchange

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func testJWK(t *testing.T, kid string) jwk.Key {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.Import(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		t.Fatal(err)
	}
	if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestKeyring_NewKeyring(t *testing.T) {
	key := testJWK(t, "k1")
	kr, err := NewKeyring(key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kr.ActiveKid() != "k1" {
		t.Errorf("active kid = %q, want k1", kr.ActiveKid())
	}
	if kr.Len() != 1 {
		t.Errorf("len = %d, want 1", kr.Len())
	}
}

func TestKeyring_NewKeyring_NoKid(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	key, _ := jwk.Import(priv)
	// No kid set.
	_, err := NewKeyring(key)
	if err == nil {
		t.Fatal("expected error for key without kid")
	}
}

func TestKeyring_AddAndActivate(t *testing.T) {
	kr, _ := NewKeyring(testJWK(t, "k1"))

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if err := kr.AddKey("k2", priv, &priv.PublicKey); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	if kr.Len() != 2 {
		t.Errorf("len = %d, want 2", kr.Len())
	}

	// k1 should still be active.
	if kr.ActiveKid() != "k1" {
		t.Errorf("active kid = %q, want k1", kr.ActiveKid())
	}

	// Activate k2.
	if err := kr.ActivateKey("k2"); err != nil {
		t.Fatalf("ActivateKey: %v", err)
	}
	if kr.ActiveKid() != "k2" {
		t.Errorf("active kid = %q, want k2", kr.ActiveKid())
	}
}

func TestKeyring_ActivateKey_NotFound(t *testing.T) {
	kr, _ := NewKeyring(testJWK(t, "k1"))
	if err := kr.ActivateKey("nonexistent"); err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

func TestKeyring_RemoveKey(t *testing.T) {
	kr, _ := NewKeyring(testJWK(t, "k1"))
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	_ = kr.AddKey("k2", priv, &priv.PublicKey)

	if err := kr.RemoveKey("k2"); err != nil {
		t.Fatalf("RemoveKey: %v", err)
	}
	if kr.Len() != 1 {
		t.Errorf("len = %d, want 1", kr.Len())
	}
}

func TestKeyring_RemoveActiveKey(t *testing.T) {
	kr, _ := NewKeyring(testJWK(t, "k1"))
	if err := kr.RemoveKey("k1"); err == nil {
		t.Fatal("expected error when removing active key")
	}
}

func TestKeyring_PublicKeySet(t *testing.T) {
	kr, _ := NewKeyring(testJWK(t, "k1"))
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	_ = kr.AddKey("k2", priv, &priv.PublicKey)

	set, err := kr.PublicKeySet()
	if err != nil {
		t.Fatalf("PublicKeySet: %v", err)
	}
	if set.Len() != 2 {
		t.Errorf("set len = %d, want 2", set.Len())
	}
}

func TestKeyring_ActiveKey(t *testing.T) {
	key := testJWK(t, "k1")
	kr, _ := NewKeyring(key)

	active := kr.ActiveKey()
	if active == nil {
		t.Fatal("ActiveKey returned nil")
	}
	kid, _ := active.KeyID()
	if kid != "k1" {
		t.Errorf("active key kid = %q, want k1", kid)
	}
}

func TestKeyring_AddKey_ECDSA(t *testing.T) {
	kr, _ := NewKeyring(testJWK(t, "rsa-key"))

	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := kr.AddKey("ec-key", ecPriv, &ecPriv.PublicKey); err != nil {
		t.Fatalf("AddKey ECDSA: %v", err)
	}
	if kr.Len() != 2 {
		t.Errorf("len = %d, want 2", kr.Len())
	}
}

func TestKeyring_AddKey_NilSigner(t *testing.T) {
	kr, _ := NewKeyring(testJWK(t, "k1"))
	err := kr.AddKey("bad", nil, nil)
	if err == nil {
		t.Fatal("expected error for nil signer")
	}
}

func TestKeyring_RotationFlow(t *testing.T) {
	// Simulate the full rotation saga: add → activate → remove old.
	kr, _ := NewKeyring(testJWK(t, "old"))

	// Step 1: Generate and add new key.
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if err := kr.AddKey("new", priv, &priv.PublicKey); err != nil {
		t.Fatal(err)
	}

	// Both keys should be in JWKS.
	set, _ := kr.PublicKeySet()
	if set.Len() != 2 {
		t.Fatalf("expected 2 keys in JWKS during rotation, got %d", set.Len())
	}

	// Step 2: Activate new key.
	if err := kr.ActivateKey("new"); err != nil {
		t.Fatal(err)
	}
	if kr.ActiveKid() != "new" {
		t.Fatalf("active kid = %q, want new", kr.ActiveKid())
	}

	// Step 3: Remove old key.
	if err := kr.RemoveKey("old"); err != nil {
		t.Fatal(err)
	}
	if kr.Len() != 1 {
		t.Fatalf("expected 1 key after rotation, got %d", kr.Len())
	}

	// JWKS should only have the new key.
	set, _ = kr.PublicKeySet()
	if set.Len() != 1 {
		t.Fatalf("expected 1 key in JWKS after rotation, got %d", set.Len())
	}
}
