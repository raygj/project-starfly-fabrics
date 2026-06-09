package exchange

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

// DPoPMaxAge is the maximum age of a DPoP proof before it is rejected.
const DPoPMaxAge = 5 * time.Minute

// ErrDPoPInvalid is returned when a DPoP proof fails validation.
var ErrDPoPInvalid = fmt.Errorf("invalid DPoP proof")

// dpopResult holds the validated result of a DPoP proof.
type dpopResult struct {
	// Thumbprint is the JWK Thumbprint (RFC 7638) of the client's public key.
	// This goes into the cnf.jkt claim of the issued token.
	Thumbprint string
}

// validateDPoP validates a DPoP proof JWT per RFC 9449.
//
// Checks:
//  1. The proof is a valid JWT with typ=dpop+jwt
//  2. The jwk header contains a public key
//  3. The proof is signed by that public key
//  4. The iat is within DPoPMaxAge
//  5. A jti claim is present (uniqueness tracking is out of scope here)
//
// Returns the JWK Thumbprint for binding via cnf.jkt.
func validateDPoP(proof string) (*dpopResult, error) {
	// Parse the JWS to inspect headers before verification.
	msg, err := jws.Parse([]byte(proof))
	if err != nil {
		return nil, fmt.Errorf("%w: parsing JWS: %v", ErrDPoPInvalid, err)
	}

	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return nil, fmt.Errorf("%w: no signatures", ErrDPoPInvalid)
	}

	headers := sigs[0].ProtectedHeaders()

	// 1. Check typ = dpop+jwt.
	typ, ok := headers.Type()
	if !ok || typ != "dpop+jwt" {
		return nil, fmt.Errorf("%w: typ must be dpop+jwt, got %q", ErrDPoPInvalid, typ)
	}

	// 2. Extract the public key from the jwk header.
	jwkKey, ok := headers.JWK()
	if !ok {
		return nil, fmt.Errorf("%w: missing jwk header", ErrDPoPInvalid)
	}

	// Ensure it's a public key (no private components).
	var rawKey interface{}
	if err := jwk.Export(jwkKey, &rawKey); err != nil {
		return nil, fmt.Errorf("%w: exporting jwk: %v", ErrDPoPInvalid, err)
	}
	if _, ok := rawKey.(crypto.PublicKey); !ok {
		return nil, fmt.Errorf("%w: jwk must be a public key", ErrDPoPInvalid)
	}

	// 3. Verify the signature using the embedded public key.
	alg, ok := headers.Algorithm()
	if !ok {
		return nil, fmt.Errorf("%w: missing alg header", ErrDPoPInvalid)
	}
	token, err := jwt.Parse([]byte(proof), jwt.WithKey(alg, jwkKey))
	if err != nil {
		return nil, fmt.Errorf("%w: signature verification failed: %v", ErrDPoPInvalid, err)
	}

	// 4. Check iat is within DPoPMaxAge.
	iat, ok := token.IssuedAt()
	if !ok {
		return nil, fmt.Errorf("%w: missing iat claim", ErrDPoPInvalid)
	}
	if time.Since(iat) > DPoPMaxAge {
		return nil, fmt.Errorf("%w: proof too old (iat: %v)", ErrDPoPInvalid, iat)
	}

	// 5. Check jti is present.
	jti, ok := token.JwtID()
	if !ok || jti == "" {
		return nil, fmt.Errorf("%w: missing jti claim", ErrDPoPInvalid)
	}

	// 6. Compute JWK Thumbprint (RFC 7638).
	thumbprint, err := computeJWKThumbprint(jwkKey)
	if err != nil {
		return nil, fmt.Errorf("%w: computing thumbprint: %v", ErrDPoPInvalid, err)
	}

	return &dpopResult{Thumbprint: thumbprint}, nil
}

// computeJWKThumbprint computes the JWK Thumbprint per RFC 7638.
// It builds the canonical JSON representation of the required members
// and computes SHA-256 over it.
func computeJWKThumbprint(key jwk.Key) (string, error) {
	// Export to a map to get the JWK members.
	data, err := json.Marshal(key)
	if err != nil {
		return "", fmt.Errorf("marshaling key: %w", err)
	}

	var keyMap map[string]interface{}
	if err := json.Unmarshal(data, &keyMap); err != nil {
		return "", fmt.Errorf("unmarshaling key: %w", err)
	}

	// RFC 7638: include only required members for the key type.
	kty := key.KeyType()
	var requiredMembers []string

	switch kty.String() {
	case "RSA":
		requiredMembers = []string{"e", "kty", "n"}
	case "EC":
		requiredMembers = []string{"crv", "kty", "x", "y"}
	case "OKP":
		requiredMembers = []string{"crv", "kty", "x"}
	default:
		return "", fmt.Errorf("unsupported key type: %s", kty)
	}

	// Build the canonical JSON with sorted keys.
	sort.Strings(requiredMembers)
	canonical := make(map[string]interface{})
	for _, member := range requiredMembers {
		v, ok := keyMap[member]
		if !ok {
			return "", fmt.Errorf("missing required member %q", member)
		}
		canonical[member] = v
	}

	// JSON marshal with sorted keys is guaranteed by iterating in order.
	canonicalJSON, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("marshaling canonical form: %w", err)
	}

	hash := sha256.Sum256(canonicalJSON)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}
