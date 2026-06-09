package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/util"
	"github.com/starfly-fabrics/starfly/pkg/core"
)

// generateTestKeyPair returns PEM-encoded ECDSA private and public keys.
func generateTestKeyPair(t *testing.T) (privPEM, pubPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}
	privDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling private key: %v", err)
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return privPEM, pubPEM
}

// hashFileContent computes the OPA bundle hash for a file, handling
// structured (JSON) vs unstructured (rego) documents correctly.
func hashFileContent(t *testing.T, name string, data []byte) string {
	t.Helper()
	hasher, err := bundle.NewSignatureHasher(bundle.SHA256)
	if err != nil {
		t.Fatalf("creating hasher: %v", err)
	}

	var value any
	if bundle.IsStructuredDoc(name) {
		if err := util.Unmarshal(data, &value); err != nil {
			t.Fatalf("unmarshaling %s: %v", name, err)
		}
	} else {
		value = data
	}

	bs, err := hasher.HashFile(value)
	if err != nil {
		t.Fatalf("hashing %s: %v", name, err)
	}
	return hex.EncodeToString(bs)
}

// signTestBundle generates a .signatures.json in bundlePath using the given
// private key PEM. It signs all .rego and data.json files in the directory.
func signTestBundle(t *testing.T, bundlePath string, privPEM []byte, keyID string) {
	t.Helper()

	var files []bundle.FileInfo
	entries, err := os.ReadDir(bundlePath)
	if err != nil {
		t.Fatalf("reading bundle dir: %v", err)
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if filepath.Ext(name) != ".rego" && name != "data.json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(bundlePath, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		hash := hashFileContent(t, name, data)
		files = append(files, bundle.NewFile(name, hash, "SHA-256"))
	}

	sc := bundle.NewSigningConfig(string(privPEM), "ES256", "")
	token, err := bundle.GenerateSignedToken(files, sc, keyID)
	if err != nil {
		t.Fatalf("generating signed token: %v", err)
	}

	sigConfig := bundle.SignaturesConfig{
		Signatures: []string{token},
	}
	sigData, err := json.Marshal(sigConfig)
	if err != nil {
		t.Fatalf("marshaling signatures: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundlePath, ".signatures.json"), sigData, 0644); err != nil {
		t.Fatalf("writing .signatures.json: %v", err)
	}
}

func TestVerifyBundle_NoKeyConfigured(t *testing.T) {
	cfg := core.PolicyConfig{
		BundlePath:    "/unused",
		SigningKeyFile: "",
	}
	if err := VerifyBundle("/unused", cfg); err != nil {
		t.Fatalf("expected nil error when no key configured, got: %v", err)
	}
}

func TestVerifyBundle_ValidSignature(t *testing.T) {
	dir := t.TempDir()
	writePolicyBundle(t, dir)

	privPEM, pubPEM := generateTestKeyPair(t)
	keyFile := filepath.Join(dir, "key.pub")
	if err := os.WriteFile(keyFile, pubPEM, 0644); err != nil {
		t.Fatal(err)
	}

	signTestBundle(t, dir, privPEM, "starfly")

	cfg := core.PolicyConfig{
		BundlePath:    dir,
		SigningKeyFile: keyFile,
		SigningKeyID:   "starfly",
	}
	if err := VerifyBundle(dir, cfg); err != nil {
		t.Fatalf("expected valid signature to pass, got: %v", err)
	}
}

func TestVerifyBundle_TamperedFile(t *testing.T) {
	dir := t.TempDir()
	writePolicyBundle(t, dir)

	privPEM, pubPEM := generateTestKeyPair(t)
	keyFile := filepath.Join(dir, "key.pub")
	if err := os.WriteFile(keyFile, pubPEM, 0644); err != nil {
		t.Fatal(err)
	}

	signTestBundle(t, dir, privPEM, "starfly")

	// Tamper with a rego file after signing.
	if err := os.WriteFile(filepath.Join(dir, "exchange.rego"), []byte("package starfly.exchange\ndefault allow := true\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := core.PolicyConfig{
		BundlePath:    dir,
		SigningKeyFile: keyFile,
		SigningKeyID:   "starfly",
	}
	err := VerifyBundle(dir, cfg)
	if err == nil {
		t.Fatal("expected error for tampered file")
	}
}

func TestVerifyBundle_MissingSignaturesFile(t *testing.T) {
	dir := t.TempDir()
	writePolicyBundle(t, dir)

	_, pubPEM := generateTestKeyPair(t)
	keyFile := filepath.Join(dir, "key.pub")
	if err := os.WriteFile(keyFile, pubPEM, 0644); err != nil {
		t.Fatal(err)
	}

	// No .signatures.json written.
	cfg := core.PolicyConfig{
		BundlePath:    dir,
		SigningKeyFile: keyFile,
		SigningKeyID:   "starfly",
	}
	err := VerifyBundle(dir, cfg)
	if err == nil {
		t.Fatal("expected error for missing .signatures.json")
	}
}

func TestVerifyBundle_InvalidKey(t *testing.T) {
	dir := t.TempDir()
	writePolicyBundle(t, dir)

	keyFile := filepath.Join(dir, "bad.pub")
	if err := os.WriteFile(keyFile, []byte("not-a-pem-key"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := core.PolicyConfig{
		BundlePath:    dir,
		SigningKeyFile: keyFile,
		SigningKeyID:   "starfly",
	}
	err := VerifyBundle(dir, cfg)
	if err == nil {
		t.Fatal("expected error for invalid key")
	}
}

func TestVerifyBundle_WrongKey(t *testing.T) {
	dir := t.TempDir()
	writePolicyBundle(t, dir)

	// Sign with key A.
	privA, _ := generateTestKeyPair(t)
	signTestBundle(t, dir, privA, "starfly")

	// Verify with key B.
	_, pubB := generateTestKeyPair(t)
	keyFile := filepath.Join(dir, "keyB.pub")
	if err := os.WriteFile(keyFile, pubB, 0644); err != nil {
		t.Fatal(err)
	}

	cfg := core.PolicyConfig{
		BundlePath:    dir,
		SigningKeyFile: keyFile,
		SigningKeyID:   "starfly",
	}
	err := VerifyBundle(dir, cfg)
	if err == nil {
		t.Fatal("expected error when verifying with wrong key")
	}
}

func TestDetectKeyAlgorithm_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	alg, err := detectKeyAlgorithm(pubPEM)
	if err != nil {
		t.Fatalf("detectKeyAlgorithm: %v", err)
	}
	if alg != "RS256" {
		t.Errorf("alg = %q, want RS256", alg)
	}
}

func TestDetectKeyAlgorithm_P384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	alg, err := detectKeyAlgorithm(pubPEM)
	if err != nil {
		t.Fatalf("detectKeyAlgorithm: %v", err)
	}
	if alg != "ES384" {
		t.Errorf("alg = %q, want ES384", alg)
	}
}

func TestDetectKeyAlgorithm_NoPEM(t *testing.T) {
	_, err := detectKeyAlgorithm([]byte("not-pem-data"))
	if err == nil {
		t.Fatal("expected error for non-PEM input")
	}
}

func TestDetectKeyAlgorithm_InvalidDER(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("invalid")})
	_, err := detectKeyAlgorithm(block)
	if err == nil {
		t.Fatal("expected error for invalid DER data")
	}
}

func TestVerifyBundle_DefaultKeyID(t *testing.T) {
	dir := t.TempDir()
	writePolicyBundle(t, dir)

	privPEM, pubPEM := generateTestKeyPair(t)
	keyFile := filepath.Join(dir, "key.pub")
	if err := os.WriteFile(keyFile, pubPEM, 0644); err != nil {
		t.Fatal(err)
	}

	// Sign with key ID "starfly" (the default).
	signTestBundle(t, dir, privPEM, "starfly")

	// Verify with empty SigningKeyID — should default to "starfly".
	cfg := core.PolicyConfig{
		BundlePath:    dir,
		SigningKeyFile: keyFile,
		SigningKeyID:   "",
	}
	if err := VerifyBundle(dir, cfg); err != nil {
		t.Fatalf("expected default keyID to work, got: %v", err)
	}
}
