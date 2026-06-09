package exchange

import (
	"crypto"
	"fmt"
	"log/slog"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/starfly-fabrics/starfly/pkg/lifecycle"
)

// Keyring manages multiple signing keys with atomic activation.
// It implements lifecycle.SigningKeyManager so the rotation workflow
// can add, activate, and remove keys without restarting the engine.
type Keyring struct {
	mu        sync.RWMutex
	activeKid string
	keys      map[string]jwk.Key // kid -> JWK (private key)
}

var _ lifecycle.SigningKeyManager = (*Keyring)(nil)

// NewKeyring creates a keyring with an initial active key.
func NewKeyring(initialKey jwk.Key) (*Keyring, error) {
	kid, ok := initialKey.KeyID()
	if !ok || kid == "" {
		return nil, fmt.Errorf("keyring: initial key must have a kid")
	}

	return &Keyring{
		activeKid: kid,
		keys:      map[string]jwk.Key{kid: initialKey},
	}, nil
}

// ActiveKid returns the key ID of the current signing key.
func (kr *Keyring) ActiveKid() string {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return kr.activeKid
}

// ActiveKey returns the current active signing key (JWK).
func (kr *Keyring) ActiveKey() jwk.Key {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return kr.keys[kr.activeKid]
}

// AddKey adds a key pair to the keyring. The key is available for
// verification but not signing until ActivateKey is called.
func (kr *Keyring) AddKey(kid string, privateKey crypto.Signer, publicKey crypto.PublicKey) error {
	key, err := jwk.Import(privateKey)
	if err != nil {
		return fmt.Errorf("keyring: importing private key: %w", err)
	}
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return fmt.Errorf("keyring: setting kid: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		return fmt.Errorf("keyring: setting alg: %w", err)
	}
	if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return fmt.Errorf("keyring: setting use: %w", err)
	}

	kr.mu.Lock()
	defer kr.mu.Unlock()
	kr.keys[kid] = key
	slog.Info("keyring: key added", "kid", kid)
	return nil
}

// ActivateKey promotes a key to the active signing key.
func (kr *Keyring) ActivateKey(kid string) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	if _, ok := kr.keys[kid]; !ok {
		return fmt.Errorf("keyring: key %q not found", kid)
	}
	old := kr.activeKid
	kr.activeKid = kid
	slog.Info("keyring: active key changed", "old_kid", old, "new_kid", kid)
	return nil
}

// RemoveKey removes a key from the keyring. Cannot remove the active key.
func (kr *Keyring) RemoveKey(kid string) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	if kid == kr.activeKid {
		return fmt.Errorf("keyring: cannot remove active key %q", kid)
	}
	delete(kr.keys, kid)
	slog.Info("keyring: key removed", "kid", kid)
	return nil
}

// PublicKeySet returns a JWK Set containing ALL public keys in the keyring.
// This is served at the JWKS endpoint — both old and new keys are included
// so tokens signed with either key can be verified during rotation.
func (kr *Keyring) PublicKeySet() (jwk.Set, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	set := jwk.NewSet()
	for _, key := range kr.keys {
		pub, err := key.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("keyring: extracting public key: %w", err)
		}
		if err := set.AddKey(pub); err != nil {
			return nil, fmt.Errorf("keyring: adding key to set: %w", err)
		}
	}
	return set, nil
}

// Len returns the number of keys in the keyring.
func (kr *Keyring) Len() int {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return len(kr.keys)
}
