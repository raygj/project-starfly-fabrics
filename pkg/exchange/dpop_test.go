package exchange

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Ensure context is used (integration tests need it).
var _ = context.Background

// buildDPoPProof creates a valid DPoP proof JWT signed with the given key.
func buildDPoPProof(t *testing.T, key *ecdsa.PrivateKey, opts ...func(*dpopProofOpts)) string {
	t.Helper()

	o := &dpopProofOpts{
		iat: time.Now().UTC(),
		jti: "test-jti-001",
		typ: "dpop+jwt",
	}
	for _, fn := range opts {
		fn(o)
	}

	jwkKey, err := jwk.Import(key.Public())
	if err != nil {
		t.Fatal(err)
	}

	privJWK, err := jwk.Import(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := privJWK.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}

	builder := jwt.NewBuilder().
		IssuedAt(o.iat).
		JwtID(o.jti)
	token, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	hdrs := jws.NewHeaders()
	_ = hdrs.Set("typ", o.typ)
	_ = hdrs.Set("jwk", jwkKey)

	signed, err := jwt.Sign(token,
		jwt.WithKey(jwa.ES256(), privJWK, jws.WithProtectedHeaders(hdrs)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

type dpopProofOpts struct {
	iat time.Time
	jti string
	typ string
}

func withExpiredIAT() func(*dpopProofOpts) {
	return func(o *dpopProofOpts) {
		o.iat = time.Now().Add(-10 * time.Minute)
	}
}

func withEmptyJTI() func(*dpopProofOpts) {
	return func(o *dpopProofOpts) {
		o.jti = ""
	}
}

func withBadType() func(*dpopProofOpts) {
	return func(o *dpopProofOpts) {
		o.typ = "JWT"
	}
}

func genTestECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// ── DPoP unit tests ──────────────────────────────────────────────────

func TestValidateDPoP_Valid(t *testing.T) {
	key := genTestECKey(t)
	proof := buildDPoPProof(t, key)

	result, err := validateDPoP(proof)
	if err != nil {
		t.Fatalf("validateDPoP: %v", err)
	}
	if result.Thumbprint == "" {
		t.Fatal("expected non-empty thumbprint")
	}
}

func TestValidateDPoP_ExpiredIAT(t *testing.T) {
	key := genTestECKey(t)
	proof := buildDPoPProof(t, key, withExpiredIAT())

	_, err := validateDPoP(proof)
	if err == nil {
		t.Fatal("expected error for expired iat")
	}
	if !errors.Is(err, ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}

func TestValidateDPoP_MissingJTI(t *testing.T) {
	key := genTestECKey(t)
	proof := buildDPoPProof(t, key, withEmptyJTI())

	_, err := validateDPoP(proof)
	if err == nil {
		t.Fatal("expected error for missing jti")
	}
	if !errors.Is(err, ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}

func TestValidateDPoP_WrongType(t *testing.T) {
	key := genTestECKey(t)
	proof := buildDPoPProof(t, key, withBadType())

	_, err := validateDPoP(proof)
	if err == nil {
		t.Fatal("expected error for wrong typ")
	}
	if !errors.Is(err, ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}

func TestValidateDPoP_GarbageInput(t *testing.T) {
	_, err := validateDPoP("not-a-jwt")
	if err == nil {
		t.Fatal("expected error for garbage input")
	}
	if !errors.Is(err, ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}

func TestValidateDPoP_ConsistentThumbprint(t *testing.T) {
	key := genTestECKey(t)
	proof1 := buildDPoPProof(t, key)
	proof2 := buildDPoPProof(t, key)

	r1, err := validateDPoP(proof1)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := validateDPoP(proof2)
	if err != nil {
		t.Fatal(err)
	}

	if r1.Thumbprint != r2.Thumbprint {
		t.Errorf("same key should produce same thumbprint: %q vs %q", r1.Thumbprint, r2.Thumbprint)
	}
}

func TestValidateDPoP_DifferentKeysProduceDifferentThumbprints(t *testing.T) {
	key1 := genTestECKey(t)
	key2 := genTestECKey(t)

	r1, err := validateDPoP(buildDPoPProof(t, key1))
	if err != nil {
		t.Fatal(err)
	}
	r2, err := validateDPoP(buildDPoPProof(t, key2))
	if err != nil {
		t.Fatal(err)
	}

	if r1.Thumbprint == r2.Thumbprint {
		t.Error("different keys should produce different thumbprints")
	}
}

func TestValidateDPoP_MissingIAT(t *testing.T) {
	key := genTestECKey(t)
	jwkPub, _ := jwk.Import(key.Public())
	privJWK, _ := jwk.Import(key)
	_ = privJWK.Set(jwk.AlgorithmKey, jwa.ES256())

	builder := jwt.NewBuilder().
		JwtID("test-jti-no-iat")
	token, _ := builder.Build()

	hdrs := jws.NewHeaders()
	_ = hdrs.Set("typ", "dpop+jwt")
	_ = hdrs.Set("jwk", jwkPub)

	signed, err := jwt.Sign(token,
		jwt.WithKey(jwa.ES256(), privJWK, jws.WithProtectedHeaders(hdrs)),
	)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	_, err = validateDPoP(string(signed))
	if err == nil {
		t.Fatal("expected error for missing iat")
	}
	if !errors.Is(err, ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}

func TestValidateDPoP_SignatureMismatch(t *testing.T) {
	signingKey := genTestECKey(t)
	differentKey := genTestECKey(t)

	wrongPubJWK, _ := jwk.Import(differentKey.Public())
	privJWK, _ := jwk.Import(signingKey)
	_ = privJWK.Set(jwk.AlgorithmKey, jwa.ES256())

	builder := jwt.NewBuilder().
		IssuedAt(time.Now().UTC()).
		JwtID("test-jti-mismatch")
	token, _ := builder.Build()

	hdrs := jws.NewHeaders()
	_ = hdrs.Set("typ", "dpop+jwt")
	_ = hdrs.Set("jwk", wrongPubJWK)

	signed, err := jwt.Sign(token,
		jwt.WithKey(jwa.ES256(), privJWK, jws.WithProtectedHeaders(hdrs)),
	)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	_, err = validateDPoP(string(signed))
	if err == nil {
		t.Fatal("expected error for signature mismatch")
	}
	if !errors.Is(err, ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}

// ── Exchange integration with DPoP ───────────────────────────────────

func TestExchange_WithDPoP_AddsCnfClaim(t *testing.T) {
	key := genTestECKey(t)
	proof := buildDPoPProof(t, key)

	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	req := validRequest()
	req.DPoPProof = proof

	resp, err := engine.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	// Parse the issued JWT and check for cnf claim.
	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	var cnf map[string]interface{}
	if err := token.Get("cnf", &cnf); err != nil {
		t.Fatalf("getting cnf claim: %v", err)
	}

	jkt, ok := cnf["jkt"].(string)
	if !ok || jkt == "" {
		t.Fatal("cnf.jkt should be a non-empty string")
	}
}

func TestExchange_WithoutDPoP_NoCnfClaim(t *testing.T) {
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	resp, err := engine.Exchange(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	var cnf map[string]interface{}
	err = token.Get("cnf", &cnf)
	if err == nil && cnf != nil {
		t.Error("cnf claim should not be present when no DPoP proof is provided")
	}
}

func TestExchange_WithInvalidDPoP_ReturnsError(t *testing.T) {
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	req := validRequest()
	req.DPoPProof = "invalid-proof"

	_, err = engine.Exchange(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for invalid DPoP proof")
	}
	if !errors.Is(err, ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}

func TestExchange_WithExpiredDPoP_ReturnsError(t *testing.T) {
	key := genTestECKey(t)
	proof := buildDPoPProof(t, key, withExpiredIAT())

	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	req := validRequest()
	req.DPoPProof = proof

	_, err = engine.Exchange(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for expired DPoP proof")
	}
	if !errors.Is(err, ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}

// ── computeJWKThumbprint edge case tests ─────────────────────────

func TestComputeJWKThumbprint_RSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.Import(priv.Public())
	if err != nil {
		t.Fatal(err)
	}

	tp, err := computeJWKThumbprint(key)
	if err != nil {
		t.Fatalf("computeJWKThumbprint RSA: %v", err)
	}
	if tp == "" {
		t.Error("expected non-empty thumbprint")
	}

	tp2, err := computeJWKThumbprint(key)
	if err != nil {
		t.Fatal(err)
	}
	if tp != tp2 {
		t.Errorf("same key should produce same thumbprint: %q vs %q", tp, tp2)
	}
}

func TestComputeJWKThumbprint_EC(t *testing.T) {
	ecKey := genTestECKey(t)
	pub, err := jwk.Import(ecKey.Public())
	if err != nil {
		t.Fatal(err)
	}

	tp, err := computeJWKThumbprint(pub)
	if err != nil {
		t.Fatalf("computeJWKThumbprint EC: %v", err)
	}
	if tp == "" {
		t.Error("expected non-empty thumbprint")
	}
}

func TestComputeJWKThumbprint_OKP(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.Import(pub)
	if err != nil {
		t.Fatal(err)
	}

	tp, err := computeJWKThumbprint(key)
	if err != nil {
		t.Fatalf("computeJWKThumbprint OKP: %v", err)
	}
	if tp == "" {
		t.Error("expected non-empty thumbprint")
	}
}

func TestComputeJWKThumbprint_UnsupportedKeyType(t *testing.T) {
	key, err := jwk.Import([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("importing symmetric key: %v", err)
	}

	_, err = computeJWKThumbprint(key)
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
	if !strings.Contains(err.Error(), "unsupported key type") {
		t.Errorf("error = %q, want containing 'unsupported key type'", err.Error())
	}
}

func TestValidateDPoP_SymmetricJWKNotPublicKey(t *testing.T) {
	raw := []byte("0123456789abcdef0123456789abcdef")
	symKey, err := jwk.Import(raw)
	if err != nil {
		t.Fatal(err)
	}

	token, err := jwt.NewBuilder().
		IssuedAt(time.Now().UTC()).
		JwtID("test-jti-sym").
		Build()
	if err != nil {
		t.Fatal(err)
	}

	hdrs := jws.NewHeaders()
	_ = hdrs.Set("typ", "dpop+jwt")
	_ = hdrs.Set("jwk", symKey)

	signed, err := jwt.Sign(token,
		jwt.WithKey(jwa.HS256(), raw, jws.WithProtectedHeaders(hdrs)),
	)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	_, err = validateDPoP(string(signed))
	if err == nil {
		t.Fatal("expected error for symmetric JWK")
	}
	if !errors.Is(err, ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}

func b64url(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func TestComputeJWKThumbprint_MissingRequiredMember(t *testing.T) {
	ecKey := genTestECKey(t)
	pub, err := jwk.Import(ecKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Remove("y"); err != nil {
		t.Skipf("cannot remove key field: %v", err)
	}

	_, err = computeJWKThumbprint(pub)
	if err == nil {
		t.Fatal("expected error for missing required member")
	}
	if !strings.Contains(err.Error(), "missing required member") {
		t.Errorf("error = %q, want containing 'missing required member'", err.Error())
	}
}

func TestValidateDPoP_HandCraftedNoAlg(t *testing.T) {
	key := genTestECKey(t)
	pub, _ := jwk.Import(key.Public())
	pubJSON, _ := json.Marshal(pub)

	hdr := fmt.Sprintf(`{"typ":"dpop+jwt","jwk":%s}`, pubJSON)
	proof := b64url(hdr) + "." + b64url(`{}`) + "." + b64url("sig")
	_, err := validateDPoP(proof)
	if err == nil {
		t.Fatal("expected error for missing alg header")
	}
	if !errors.Is(err, ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}
