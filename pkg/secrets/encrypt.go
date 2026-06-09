package secrets

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// EncryptSecretBundle encrypts a SecretBundle's claims as a JWE compact
// serialization using ECDH-ES+A256KW key agreement and A256GCM content
// encryption, targeted at the recipient's public key.
func EncryptSecretBundle(bundle *SecretBundle, recipientKey jwk.Key) (string, error) {
	if bundle == nil || len(bundle.Claims) == 0 {
		return "", fmt.Errorf("empty secret bundle")
	}

	plaintext, err := json.Marshal(bundle.Claims)
	if err != nil {
		return "", fmt.Errorf("marshaling secret claims: %w", err)
	}

	encrypted, err := jwe.Encrypt(
		plaintext,
		jwe.WithKey(jwa.ECDH_ES_A256KW(), recipientKey),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		return "", fmt.Errorf("encrypting secret bundle: %w", err)
	}

	return string(encrypted), nil
}

// DecryptSecretBundle decrypts a JWE compact serialization back to a
// claims map using the recipient's private key.
func DecryptSecretBundle(jweCompact string, privateKey jwk.Key) (map[string]string, error) {
	plaintext, err := jwe.Decrypt(
		[]byte(jweCompact),
		jwe.WithKey(jwa.ECDH_ES_A256KW(), privateKey),
	)
	if err != nil {
		return nil, fmt.Errorf("decrypting secret bundle: %w", err)
	}

	var claims map[string]string
	if err := json.Unmarshal(plaintext, &claims); err != nil {
		return nil, fmt.Errorf("unmarshaling secret claims: %w", err)
	}

	return claims, nil
}
