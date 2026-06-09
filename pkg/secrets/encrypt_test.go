package secrets

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func generateECKeyPair(t *testing.T) (jwk.Key, jwk.Key) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key: %v", err)
	}
	priv, err := jwk.Import(privKey)
	if err != nil {
		t.Fatalf("importing private key: %v", err)
	}
	pub, err := jwk.Import(privKey.Public())
	if err != nil {
		t.Fatalf("importing public key: %v", err)
	}
	return priv, pub
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	priv, pub := generateECKeyPair(t)

	bundle := &SecretBundle{
		Claims: map[string]string{
			"db_password": "s3cret",
			"api_key":     "key-123",
		},
	}

	encrypted, err := EncryptSecretBundle(bundle, pub)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if encrypted == "" {
		t.Fatal("encrypted string is empty")
	}

	claims, err := DecryptSecretBundle(encrypted, priv)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if claims["db_password"] != "s3cret" {
		t.Errorf("db_password = %q, want s3cret", claims["db_password"])
	}
	if claims["api_key"] != "key-123" {
		t.Errorf("api_key = %q, want key-123", claims["api_key"])
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	_, pub := generateECKeyPair(t)
	wrongPriv, _ := generateECKeyPair(t)

	bundle := &SecretBundle{
		Claims: map[string]string{"secret": "value"},
	}

	encrypted, err := EncryptSecretBundle(bundle, pub)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	_, err = DecryptSecretBundle(encrypted, wrongPriv)
	if err == nil {
		t.Error("expected decryption to fail with wrong key")
	}
}

func TestDecrypt_InvalidJWE(t *testing.T) {
	priv, _ := generateECKeyPair(t)

	_, err := DecryptSecretBundle("not-a-valid-jwe", priv)
	if err == nil {
		t.Error("expected decryption to fail with invalid JWE")
	}
}

func TestEncrypt_EmptyBundle(t *testing.T) {
	_, pub := generateECKeyPair(t)

	_, err := EncryptSecretBundle(&SecretBundle{Claims: map[string]string{}}, pub)
	if err == nil {
		t.Error("expected error for empty bundle")
	}

	_, err = EncryptSecretBundle(nil, pub)
	if err == nil {
		t.Error("expected error for nil bundle")
	}
}
