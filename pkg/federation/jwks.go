package federation

import (
	"crypto"
	"fmt"
	"io"
	"net/http"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// maxJWKSResponseSize limits the JWKS response body to prevent DoS.
const maxJWKSResponseSize = 1 << 20 // 1 MiB

// maxKeysPerPeer limits the number of keys cached per peer.
const maxKeysPerPeer = 50

// parseJWKSResponse reads and parses a JWKS response into a kid→public key map.
func parseJWKSResponse(resp *http.Response) (map[string]crypto.PublicKey, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSResponseSize))
	if err != nil {
		return nil, fmt.Errorf("reading JWKS response: %w", err)
	}

	set, err := jwk.ParseString(string(body))
	if err != nil {
		return nil, fmt.Errorf("parsing JWKS: %w", err)
	}

	keys := make(map[string]crypto.PublicKey)
	for i := 0; i < set.Len() && i < maxKeysPerPeer; i++ {
		key, ok := set.Key(i)
		if !ok {
			continue
		}

		kid, ok := key.KeyID()
		if !ok || kid == "" {
			continue // skip keys without kid
		}

		var rawKey crypto.PublicKey
		if err := jwk.Export(key, &rawKey); err != nil {
			continue // skip keys that can't be exported
		}

		keys[kid] = rawKey
	}

	return keys, nil
}
