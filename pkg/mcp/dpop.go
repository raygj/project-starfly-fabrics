package mcp

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// dpopMaxAge is the maximum freshness window for a DPoP proof before it is rejected.
const dpopMaxAge = 5 * time.Minute

// verifyDPoP validates the DPoP proof (if present) and checks its binding to the
// WIMSE token's cnf.jkt claim per RFC 9449.
//
// Rules:
//   - devMode: skip entirely (dev tokens have no cnf.jkt)
//   - token has cnf.jkt, no proof → deny (proof is mandatory when token is DPoP-bound)
//   - proof present → validate structure + signature always; if cnf.jkt set, verify thumbprint binding
//   - no proof, no cnf.jkt → skip (token was minted without DPoP)
func verifyDPoP(cfg Config, claims *VerifiedClaims, opts *VerifyOptions) error {
	if cfg.DevMode {
		return nil
	}

	proof := ""
	if opts != nil {
		proof = opts.DPoPProof
	}

	if claims.CNFThumbprint == "" && proof == "" {
		return nil
	}

	if claims.CNFThumbprint != "" && proof == "" {
		return fmt.Errorf("%w: token is DPoP-bound (cnf.jkt present) but no DPoP proof provided", ErrDPoPInvalid)
	}

	thumbprint, err := validateDPoPProof(proof)
	if err != nil {
		return err
	}

	if claims.CNFThumbprint != "" && thumbprint != claims.CNFThumbprint {
		return fmt.Errorf("%w: proof key thumbprint %q does not match token cnf.jkt %q",
			ErrDPoPInvalid, thumbprint, claims.CNFThumbprint)
	}

	claims.CNFThumbprint = thumbprint
	return nil
}

// validateDPoPProof validates a DPoP proof JWT per RFC 9449 and returns the JWK thumbprint.
//
// Checks: typ=dpop+jwt, embedded public key, valid signature, iat freshness, jti present.
// All errors are wrapped with ErrDPoPInvalid.
func validateDPoPProof(proof string) (string, error) {
	wrap := func(format string, args ...interface{}) (string, error) {
		return "", fmt.Errorf("%w: "+format, append([]interface{}{ErrDPoPInvalid}, args...)...)
	}

	msg, err := jws.Parse([]byte(proof))
	if err != nil {
		return wrap("parsing JWS: %v", err)
	}

	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return wrap("no signatures")
	}

	headers := sigs[0].ProtectedHeaders()

	typ, ok := headers.Type()
	if !ok || typ != "dpop+jwt" {
		return wrap("typ must be dpop+jwt, got %q", typ)
	}

	jwkKey, ok := headers.JWK()
	if !ok {
		return wrap("missing jwk header")
	}

	var rawKey interface{}
	if err := jwk.Export(jwkKey, &rawKey); err != nil {
		return wrap("exporting jwk: %v", err)
	}
	if _, ok := rawKey.(crypto.PublicKey); !ok {
		return wrap("jwk must be a public key (not private)")
	}

	alg, ok := headers.Algorithm()
	if !ok {
		return wrap("missing alg header")
	}
	token, err := jwt.Parse([]byte(proof), jwt.WithKey(alg, jwkKey))
	if err != nil {
		return wrap("signature verification: %v", err)
	}

	iat, ok := token.IssuedAt()
	if !ok {
		return wrap("missing iat claim")
	}
	if age := time.Since(iat); age > dpopMaxAge {
		return wrap("proof too old (%v > %v)", age.Round(time.Second), dpopMaxAge)
	}

	jti, ok := token.JwtID()
	if !ok || jti == "" {
		return wrap("missing jti claim")
	}

	tp, err := computeJWKThumbprint(jwkKey)
	if err != nil {
		return wrap("computing thumbprint: %v", err)
	}
	return tp, nil
}

// computeJWKThumbprint computes the JWK Thumbprint per RFC 7638.
// The required members for each key type are fixed by the spec and sorted lexicographically.
func computeJWKThumbprint(key jwk.Key) (string, error) {
	data, err := json.Marshal(key)
	if err != nil {
		return "", fmt.Errorf("marshaling key: %w", err)
	}

	var keyMap map[string]interface{}
	if err := json.Unmarshal(data, &keyMap); err != nil {
		return "", fmt.Errorf("unmarshaling key: %w", err)
	}

	kty := key.KeyType()
	var required []string
	switch kty.String() {
	case "RSA":
		required = []string{"e", "kty", "n"}
	case "EC":
		required = []string{"crv", "kty", "x", "y"}
	case "OKP":
		required = []string{"crv", "kty", "x"}
	default:
		return "", fmt.Errorf("unsupported key type: %s", kty)
	}
	sort.Strings(required)

	canonical := make(map[string]interface{}, len(required))
	for _, m := range required {
		v, ok := keyMap[m]
		if !ok {
			return "", fmt.Errorf("missing required JWK member %q", m)
		}
		canonical[m] = v
	}

	canonicalJSON, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("marshaling canonical form: %w", err)
	}

	hash := sha256.Sum256(canonicalJSON)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}
