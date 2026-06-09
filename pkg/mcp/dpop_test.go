package mcp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func genECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func buildProof(t *testing.T, key *ecdsa.PrivateKey, iat time.Time, jti string, typ string) string {
	t.Helper()
	pubJWK, err := jwk.Import(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	privJWK, err := jwk.Import(key)
	if err != nil {
		t.Fatal(err)
	}
	_ = privJWK.Set(jwk.AlgorithmKey, jwa.ES256())

	builder := jwt.NewBuilder().IssuedAt(iat)
	if jti != "" {
		builder = builder.JwtID(jti)
	}
	token, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	hdrs := jws.NewHeaders()
	_ = hdrs.Set("typ", typ)
	_ = hdrs.Set("jwk", pubJWK)

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), privJWK, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func TestValidateDPoPProof_Valid(t *testing.T) {
	key := genECKey(t)
	proof := buildProof(t, key, time.Now().UTC(), "jti-001", "dpop+jwt")

	tp, err := validateDPoPProof(proof)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tp == "" {
		t.Fatal("expected non-empty thumbprint")
	}
}

func TestValidateDPoPProof_Expired(t *testing.T) {
	key := genECKey(t)
	proof := buildProof(t, key, time.Now().Add(-10*time.Minute), "jti-002", "dpop+jwt")

	_, err := validateDPoPProof(proof)
	if err == nil {
		t.Fatal("expected error for expired proof")
	}
	if !errors.Is(err, ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}

func TestValidateDPoPProof_WrongType(t *testing.T) {
	key := genECKey(t)
	proof := buildProof(t, key, time.Now().UTC(), "jti-003", "JWT")

	_, err := validateDPoPProof(proof)
	if err == nil {
		t.Fatal("expected error for wrong typ")
	}
}

func TestValidateDPoPProof_Garbage(t *testing.T) {
	_, err := validateDPoPProof("not.a.jwt")
	if err == nil {
		t.Fatal("expected error for garbage input")
	}
	if !errors.Is(err, ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}

func TestVerifyDPoP_DevModeSkips(t *testing.T) {
	claims := &VerifiedClaims{CNFThumbprint: "some-jkt"}
	opts := &VerifyOptions{DPoPProof: "garbage"}
	cfg := Config{DevMode: true}

	// devMode: always skip, even with cnf.jkt + garbage proof.
	if err := verifyDPoP(cfg, claims, opts); err != nil {
		t.Fatalf("devMode should skip DPoP, got: %v", err)
	}
}

func TestVerifyDPoP_NoCnfNoProof_Skips(t *testing.T) {
	claims := &VerifiedClaims{}
	if err := verifyDPoP(Config{}, claims, nil); err != nil {
		t.Fatalf("no cnf.jkt + no proof should skip, got: %v", err)
	}
}

func TestVerifyDPoP_CnfWithoutProof_Denied(t *testing.T) {
	claims := &VerifiedClaims{CNFThumbprint: "some-jkt"}
	err := verifyDPoP(Config{}, claims, nil)
	if err == nil {
		t.Fatal("expected denial when cnf.jkt present but no proof")
	}
	if !errors.Is(err, ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}

func TestVerifyDPoP_ValidProofBindingMatch(t *testing.T) {
	key := genECKey(t)
	proof := buildProof(t, key, time.Now().UTC(), "jti-bind", "dpop+jwt")

	// Compute the expected thumbprint.
	tp, err := validateDPoPProof(proof)
	if err != nil {
		t.Fatal(err)
	}

	claims := &VerifiedClaims{CNFThumbprint: tp}
	opts := &VerifyOptions{DPoPProof: proof}

	if err := verifyDPoP(Config{}, claims, opts); err != nil {
		t.Fatalf("valid proof + matching cnf.jkt should pass, got: %v", err)
	}
}

func TestVerifyDPoP_ValidProofBindingMismatch(t *testing.T) {
	key := genECKey(t)
	proof := buildProof(t, key, time.Now().UTC(), "jti-mismatch", "dpop+jwt")

	claims := &VerifiedClaims{CNFThumbprint: "wrong-thumbprint"}
	opts := &VerifyOptions{DPoPProof: proof}

	err := verifyDPoP(Config{}, claims, opts)
	if err == nil {
		t.Fatal("expected denial on thumbprint mismatch")
	}
	if !errors.Is(err, ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}

func TestVerifyDPoP_ExpiredProofNoCnf_Denied(t *testing.T) {
	key := genECKey(t)
	proof := buildProof(t, key, time.Now().Add(-10*time.Minute), "jti-exp", "dpop+jwt")

	claims := &VerifiedClaims{} // no cnf.jkt
	opts := &VerifyOptions{DPoPProof: proof}

	err := verifyDPoP(Config{}, claims, opts)
	if err == nil {
		t.Fatal("expected denial for expired proof even without cnf.jkt binding")
	}
	if !errors.Is(err, ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}
