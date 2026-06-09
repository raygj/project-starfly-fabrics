package api

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/starfly-fabrics/starfly/pkg/secrets"
)

// importKeyViaJSON converts a raw crypto key into a jwk.Key by serialising
// through JSON. This matches what jwk.ParseKey does on the wire, ensuring
// curve fields are stored as strings (which key.Get("crv", &s) expects).
func importKeyViaJSON(t *testing.T, raw any) jwk.Key {
	t.Helper()
	jwkRaw, err := jwk.Import(raw)
	if err != nil {
		t.Fatalf("jwk.Import: %v", err)
	}
	data, err := json.Marshal(jwkRaw)
	if err != nil {
		t.Fatalf("marshal JWK: %v", err)
	}
	key, err := jwk.ParseKey(data)
	if err != nil {
		t.Fatalf("jwk.ParseKey: %v", err)
	}
	return key
}

// buildSignedJWT generates an ephemeral EC P-256 key pair, signs a JWT with
// the given subject using a JWK-aware signer (so the kid is in the JWT
// header), and returns the token string plus a mockJWKS holding the public key.
func buildSignedJWT(t *testing.T, subject string) (tokenStr string, jwksProvider *mockJWKS) {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}

	// Build and round-trip the private JWK through JSON so all fields are
	// in canonical string form. Set kid so it appears in the JWT header.
	privJWK := importKeyViaJSON(t, privKey)
	_ = privJWK.Set(jwk.KeyIDKey, "test-kid")
	_ = privJWK.Set(jwk.AlgorithmKey, jwa.ES256())

	// Get the public counterpart, also in canonical string form.
	pubJWK, err := jwk.PublicKeyOf(privJWK)
	if err != nil {
		t.Fatalf("jwk.PublicKeyOf: %v", err)
	}
	// Round-trip through JSON to ensure string-type fields.
	pubData, _ := json.Marshal(pubJWK)
	pubJWK, err = jwk.ParseKey(pubData)
	if err != nil {
		t.Fatalf("parsing public JWK: %v", err)
	}

	set := jwk.NewSet()
	if err := set.AddKey(pubJWK); err != nil {
		t.Fatalf("adding key to set: %v", err)
	}

	// Sign with the JWK so kid is embedded in the JWT header.
	tok, err := jwt.NewBuilder().Issuer("test").Subject(subject).Build()
	if err != nil {
		t.Fatalf("building JWT: %v", err)
	}
	tokenBytes, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), privJWK))
	if err != nil {
		t.Fatalf("signing JWT: %v", err)
	}

	return string(tokenBytes), &mockJWKS{set: set}
}

// ── validateEncryptionJWK unit tests ────────────────────────────────────────

func TestValidateEncryptionJWK_EC(t *testing.T) {
	cases := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}
	for _, tc := range cases {
		t.Run("valid "+tc.name, func(t *testing.T) {
			privKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("generating key: %v", err)
			}
			key := importKeyViaJSON(t, privKey.PublicKey)
			if err := validateEncryptionJWK(key); err != nil {
				t.Errorf("validateEncryptionJWK(%s) = %v, want nil", tc.name, err)
			}
		})
	}
}

func TestValidateEncryptionJWK_OKP(t *testing.T) {
	t.Run("valid Ed25519", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generating Ed25519 key: %v", err)
		}
		key := importKeyViaJSON(t, pubKey)
		if err := validateEncryptionJWK(key); err != nil {
			t.Errorf("validateEncryptionJWK(Ed25519) = %v, want nil", err)
		}
	})

	t.Run("valid X25519", func(t *testing.T) {
		privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generating X25519 key: %v", err)
		}
		key := importKeyViaJSON(t, privKey.PublicKey())
		if err := validateEncryptionJWK(key); err != nil {
			t.Errorf("validateEncryptionJWK(X25519) = %v, want nil", err)
		}
	})
}

func TestValidateEncryptionJWK_RSA_Rejected(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	key := importKeyViaJSON(t, privKey.PublicKey)
	if err := validateEncryptionJWK(key); err == nil {
		t.Error("validateEncryptionJWK(RSA) = nil, want error")
	} else if !strings.Contains(err.Error(), "unsupported key type") {
		t.Errorf("error = %q, want 'unsupported key type'", err.Error())
	}
}

// ── handleEncryptionKeyRegister — paths requiring a valid JWT ────────────────

func TestHandleEncryptionKeyRegister_ValidJWT_InvalidBody(t *testing.T) {
	tokenStr, jwksProvider := buildSignedJWT(t, "spiffe://example.com/workload/a")
	s := &Server{
		encryptionKeyStore: secrets.NewInMemoryKeyStore(),
		jwks:               jwksProvider,
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/identity/agent/encryption-key",
		strings.NewReader("not-valid-json"))
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	s.handleEncryptionKeyRegister(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestHandleEncryptionKeyRegister_ValidJWT_InvalidJWK(t *testing.T) {
	tokenStr, jwksProvider := buildSignedJWT(t, "spiffe://example.com/workload/b")
	s := &Server{
		encryptionKeyStore: secrets.NewInMemoryKeyStore(),
		jwks:               jwksProvider,
	}

	// Body parses as JSON but JWK is not valid.
	body, _ := json.Marshal(map[string]interface{}{
		"public_key": map[string]string{"kty": "broken"},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/identity/agent/encryption-key",
		bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	s.handleEncryptionKeyRegister(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestHandleEncryptionKeyRegister_ValidJWT_UnsupportedKeyType(t *testing.T) {
	tokenStr, jwksProvider := buildSignedJWT(t, "spiffe://example.com/workload/c")
	s := &Server{
		encryptionKeyStore: secrets.NewInMemoryKeyStore(),
		jwks:               jwksProvider,
	}

	// RSA public key — rejected by validateEncryptionJWK.
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaJWK := importKeyViaJSON(t, rsaPriv.PublicKey)
	rsaJWKJSON, _ := json.Marshal(rsaJWK)

	body, _ := json.Marshal(map[string]json.RawMessage{
		"public_key": rsaJWKJSON,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/identity/agent/encryption-key",
		bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	s.handleEncryptionKeyRegister(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestHandleEncryptionKeyRegister_ValidJWT_EmptySubject(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privJWK := importKeyViaJSON(t, privKey)
	_ = privJWK.Set(jwk.KeyIDKey, "k1")
	_ = privJWK.Set(jwk.AlgorithmKey, jwa.ES256())

	pubJWK, _ := jwk.PublicKeyOf(privJWK)
	pubData, _ := json.Marshal(pubJWK)
	pubJWK, _ = jwk.ParseKey(pubData)

	set := jwk.NewSet()
	_ = set.AddKey(pubJWK)

	// Build token without Subject.
	tok, _ := jwt.NewBuilder().Issuer("test").Build()
	tokenBytes, _ := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), privJWK))

	s := &Server{
		encryptionKeyStore: secrets.NewInMemoryKeyStore(),
		jwks:               &mockJWKS{set: set},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/identity/agent/encryption-key",
		strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+string(tokenBytes))
	rec := httptest.NewRecorder()
	s.handleEncryptionKeyRegister(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestHandleEncryptionKeyRegister_Success(t *testing.T) {
	tokenStr, jwksProvider := buildSignedJWT(t, "spiffe://example.com/workload/ok")
	s := &Server{
		encryptionKeyStore: secrets.NewInMemoryKeyStore(),
		jwks:               jwksProvider,
	}

	// Use a valid EC P-256 public key as the encryption key.
	encPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	encPubJWK := importKeyViaJSON(t, encPriv.PublicKey)
	encPubJSON, _ := json.Marshal(encPubJWK)

	body, _ := json.Marshal(map[string]json.RawMessage{
		"public_key": encPubJSON,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/identity/agent/encryption-key",
		bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	s.handleEncryptionKeyRegister(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	// Verify the key was stored.
	stored, err := s.encryptionKeyStore.Get(context.Background(), "spiffe://example.com/workload/ok")
	if err != nil {
		t.Fatalf("key not stored: %v", err)
	}
	if stored == nil {
		t.Error("stored key is nil")
	}
}

// ── requireBearerAuth ────────────────────────────────────────────────────────

func TestRequireBearerAuth_NoJWKS(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	if !s.requireBearerAuth(rec, req) {
		t.Error("requireBearerAuth with no JWKS should return true (open)")
	}
}

func TestRequireBearerAuth_MissingHeader(t *testing.T) {
	s := &Server{jwks: &mockJWKS{set: jwk.NewSet()}}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	if s.requireBearerAuth(rec, req) {
		t.Error("requireBearerAuth with missing header should return false")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRequireBearerAuth_JWKSError(t *testing.T) {
	s := &Server{jwks: &mockJWKS{err: &testBearerError{"keyset failure"}}}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rec := httptest.NewRecorder()
	if s.requireBearerAuth(rec, req) {
		t.Error("requireBearerAuth with JWKS error should return false")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestRequireBearerAuth_InvalidToken(t *testing.T) {
	s := &Server{jwks: &mockJWKS{set: jwk.NewSet()}}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	rec := httptest.NewRecorder()
	if s.requireBearerAuth(rec, req) {
		t.Error("requireBearerAuth with invalid token should return false")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRequireBearerAuth_ValidToken(t *testing.T) {
	tokenStr, jwksProvider := buildSignedJWT(t, "test-sub")
	s := &Server{jwks: jwksProvider}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	if !s.requireBearerAuth(rec, req) {
		t.Errorf("requireBearerAuth with valid token should return true (body: %s)", rec.Body.String())
	}
}

// testBearerError is a minimal error type used in bearer auth tests.
type testBearerError struct{ msg string }

func (e *testBearerError) Error() string { return e.msg }
