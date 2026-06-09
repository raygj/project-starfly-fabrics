package secrets

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func testPubKey(t *testing.T) jwk.Key {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	pub, err := jwk.Import(privKey.Public())
	if err != nil {
		t.Fatalf("importing key: %v", err)
	}
	return pub
}

func TestInMemoryKeyStore_RegisterAndGet(t *testing.T) {
	store := NewInMemoryKeyStore()
	ctx := context.Background()
	key := testPubKey(t)

	if err := store.Register(ctx, "wimse://example.com/sa/app", key); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, err := store.Get(ctx, "wimse://example.com/sa/app")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestInMemoryKeyStore_Overwrite(t *testing.T) {
	store := NewInMemoryKeyStore()
	ctx := context.Background()
	key1 := testPubKey(t)
	key2 := testPubKey(t)

	if err := store.Register(ctx, "wid-1", key1); err != nil {
		t.Fatalf("Register 1: %v", err)
	}
	if err := store.Register(ctx, "wid-1", key2); err != nil {
		t.Fatalf("Register 2: %v", err)
	}

	got, err := store.Get(ctx, "wid-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Should be key2 (the overwrite).
	if got == nil {
		t.Fatal("expected non-nil key after overwrite")
	}
}

func TestInMemoryKeyStore_NotFound(t *testing.T) {
	store := NewInMemoryKeyStore()
	ctx := context.Background()

	_, err := store.Get(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for missing key")
	}
}

func TestInMemoryKeyStore_Validation(t *testing.T) {
	store := NewInMemoryKeyStore()
	ctx := context.Background()

	if err := store.Register(ctx, "", testPubKey(t)); err == nil {
		t.Error("expected error for empty workload ID")
	}
	if err := store.Register(ctx, "wid", nil); err == nil {
		t.Error("expected error for nil key")
	}
}
