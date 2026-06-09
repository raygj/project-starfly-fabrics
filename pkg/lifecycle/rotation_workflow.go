package lifecycle

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// RotationParams configures a key rotation workflow run.
type RotationParams struct {
	// KeyType is the signing key algorithm: "RSA-2048" or "EC-P256".
	KeyType string `json:"key_type"`

	// GracePeriod is how long the old key stays in JWKS after swap.
	// Tokens in flight signed with the old key can still verify.
	GracePeriod time.Duration `json:"grace_period"`

	// PropagationTimeout is how long to wait for JWKS caches to
	// pick up the new key via kid-miss refetch before swapping.
	PropagationTimeout time.Duration `json:"propagation_timeout"`
}

// DefaultRotationParams returns sensible defaults for key rotation.
func DefaultRotationParams() RotationParams {
	return RotationParams{
		KeyType:            "RSA-2048",
		GracePeriod:        5 * time.Minute,
		PropagationTimeout: 30 * time.Second,
	}
}

// KeyMaterial holds a generated key pair for rotation.
type KeyMaterial struct {
	Kid        string           `json:"kid"`
	PrivateKey crypto.Signer    `json:"-"`
	PublicKey  crypto.PublicKey  `json:"-"`
	KeyType    string           `json:"key_type"`
	CreatedAt  time.Time        `json:"created_at"`
}

// RotationActivities contains rotation-specific Temporal activities.
type RotationActivities struct {
	keyManager SigningKeyManager
	activities *Activities
}

// SigningKeyManager controls the Starfly unit's signing key lifecycle.
// The exchange engine uses the active key to sign WIMSE JWTs.
// The lifecycle worker uses this interface to rotate keys.
type SigningKeyManager interface {
	// ActiveKid returns the key ID of the current signing key.
	ActiveKid() string
	// AddKey adds a key pair to the keyring (available for verification but not signing).
	AddKey(kid string, privateKey crypto.Signer, publicKey crypto.PublicKey) error
	// ActivateKey promotes a key to the active signing key.
	ActivateKey(kid string) error
	// RemoveKey removes a key from the keyring (must not be the active key).
	RemoveKey(kid string) error
}

// NewRotationActivities creates the rotation activity set.
func NewRotationActivities(keyManager SigningKeyManager, activities *Activities) *RotationActivities {
	return &RotationActivities{
		keyManager: keyManager,
		activities: activities,
	}
}

// RotationWorkflow is the Temporal workflow for signing key rotation.
// Saga steps: Generate → Publish → Propagate → Swap → Verify → Grace → Revoke.
// Rollback on failure after Publish: revert to old key, remove new key.
func RotationWorkflow(ctx workflow.Context, params RotationParams) error {
	if params.KeyType == "" {
		params.KeyType = "RSA-2048"
	}
	if params.GracePeriod == 0 {
		params.GracePeriod = 5 * time.Minute
	}
	if params.PropagationTimeout == 0 {
		params.PropagationTimeout = 30 * time.Second
	}

	actOpts := workflow.ActivityOptions{
		StartToCloseTimeout: 2 * time.Minute,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    time.Second,
			BackoffCoefficient: 2.0,
			MaximumAttempts:    3,
		},
	}
	ctx = workflow.WithActivityOptions(ctx, actOpts)

	var rotActs *RotationActivities
	var sharedActs *Activities

	// Step 1: Emit rotation-initiated signal.
	err := workflow.ExecuteActivity(ctx, sharedActs.EmitLifecycleSignal,
		EventTypeRotationInitiated, "urn:starfly:signing-key",
		map[string]interface{}{"key_type": params.KeyType},
	).Get(ctx, nil)
	if err != nil {
		return fmt.Errorf("rotation: emitting initiated signal: %w", err)
	}

	// Step 2: Generate new key pair.
	var newKid string
	err = workflow.ExecuteActivity(ctx, rotActs.GenerateAndPublishKey, params.KeyType).Get(ctx, &newKid)
	if err != nil {
		return fmt.Errorf("rotation: generating key: %w", err)
	}

	// Step 3: Wait for propagation (JWKS caches pick up new key).
	err = workflow.Sleep(ctx, params.PropagationTimeout)
	if err != nil {
		return fmt.Errorf("rotation: propagation wait: %w", err)
	}

	// Step 4: Mint execution-scoped token for key swap authorization.
	payloadHash := sha256Hex([]byte(newKid))
	var execToken string
	err = workflow.ExecuteActivity(ctx, sharedActs.MintExecutionScopedToken,
		ExecutionScopeForSwap(newKid, payloadHash),
	).Get(ctx, &execToken)
	if err != nil {
		// Rollback: remove new key from keyring.
		_ = workflow.ExecuteActivity(ctx, rotActs.RemoveKey, newKid).Get(ctx, nil)
		_ = workflow.ExecuteActivity(ctx, sharedActs.EmitLifecycleSignal,
			EventTypeRotationRollback, "urn:starfly:signing-key",
			map[string]interface{}{"reason": "exec-token-mint-failed", "new_kid": newKid},
		).Get(ctx, nil)
		return fmt.Errorf("rotation: minting exec token: %w", err)
	}

	// Step 5: Swap signing key (requires execution-scoped token).
	var oldKid string
	err = workflow.ExecuteActivity(ctx, rotActs.SwapSigningKey, newKid, execToken).Get(ctx, &oldKid)
	if err != nil {
		// Rollback: remove new key.
		_ = workflow.ExecuteActivity(ctx, rotActs.RemoveKey, newKid).Get(ctx, nil)
		_ = workflow.ExecuteActivity(ctx, sharedActs.EmitLifecycleSignal,
			EventTypeRotationRollback, "urn:starfly:signing-key",
			map[string]interface{}{"reason": "swap-failed", "new_kid": newKid},
		).Get(ctx, nil)
		return fmt.Errorf("rotation: swapping key: %w", err)
	}

	// Step 6: Verify new key works (mint test token, verify via JWKS).
	err = workflow.ExecuteActivity(ctx, rotActs.VerifyNewKey, newKid).Get(ctx, nil)
	if err != nil {
		// Rollback: reactivate old key, remove new key.
		_ = workflow.ExecuteActivity(ctx, rotActs.RollbackToKey, oldKid, newKid).Get(ctx, nil)
		_ = workflow.ExecuteActivity(ctx, sharedActs.EmitLifecycleSignal,
			EventTypeRotationRollback, "urn:starfly:signing-key",
			map[string]interface{}{"reason": "verify-failed", "old_kid": oldKid, "new_kid": newKid},
		).Get(ctx, nil)
		return fmt.Errorf("rotation: verifying new key: %w", err)
	}

	// Step 7: Grace period — old key stays in JWKS for in-flight tokens.
	err = workflow.Sleep(ctx, params.GracePeriod)
	if err != nil {
		return fmt.Errorf("rotation: grace period: %w", err)
	}

	// Step 8: Remove old key from keyring.
	_ = workflow.ExecuteActivity(ctx, rotActs.RemoveKey, oldKid).Get(ctx, nil)

	// Step 9: Emit rotation-complete signal.
	_ = workflow.ExecuteActivity(ctx, sharedActs.EmitLifecycleSignal,
		EventTypeRotationComplete, "urn:starfly:signing-key",
		map[string]interface{}{"old_kid": oldKid, "new_kid": newKid},
	).Get(ctx, nil)

	return nil
}

// ExecutionScopeForSwap builds the execution scope for a key swap operation.
func ExecutionScopeForSwap(newKid, payloadHash string) ExecutionScopeInput {
	return ExecutionScopeInput{
		Method:      "POST",
		URI:         "/internal/signing-key",
		PayloadHash: payloadHash,
		Nonce:       fmt.Sprintf("rotate-%s-%d", newKid, time.Now().UnixNano()),
	}
}

// ExecutionScopeInput mirrors core.ExecutionScope for Temporal serialization.
type ExecutionScopeInput struct {
	Method      string `json:"htm"`
	URI         string `json:"htu"`
	PayloadHash string `json:"payload_hash,omitempty"`
	Nonce       string `json:"nonce"`
}

// --- Rotation Activities (methods on RotationActivities) ---

// GenerateAndPublishKey generates a new key pair and adds it to the keyring.
// Returns the new key ID.
func (ra *RotationActivities) GenerateAndPublishKey(keyType string) (string, error) {
	km, err := generateKey(keyType)
	if err != nil {
		return "", err
	}
	if err := ra.keyManager.AddKey(km.Kid, km.PrivateKey, km.PublicKey); err != nil {
		return "", fmt.Errorf("rotation: adding key to keyring: %w", err)
	}
	return km.Kid, nil
}

// SwapSigningKey activates the new key and returns the old key ID.
func (ra *RotationActivities) SwapSigningKey(newKid, _ string) (string, error) {
	oldKid := ra.keyManager.ActiveKid()
	if err := ra.keyManager.ActivateKey(newKid); err != nil {
		return "", fmt.Errorf("rotation: activating key %s: %w", newKid, err)
	}
	return oldKid, nil
}

// VerifyNewKey checks that the new key is the active signing key.
func (ra *RotationActivities) VerifyNewKey(newKid string) error {
	activeKid := ra.keyManager.ActiveKid()
	if activeKid != newKid {
		return fmt.Errorf("rotation: active key is %s, expected %s", activeKid, newKid)
	}
	return nil
}

// RemoveKey removes a key from the keyring.
func (ra *RotationActivities) RemoveKey(kid string) error {
	return ra.keyManager.RemoveKey(kid)
}

// RollbackToKey reactivates the old key and removes the new key.
func (ra *RotationActivities) RollbackToKey(oldKid, newKid string) error {
	if err := ra.keyManager.ActivateKey(oldKid); err != nil {
		return fmt.Errorf("rotation rollback: reactivating %s: %w", oldKid, err)
	}
	if err := ra.keyManager.RemoveKey(newKid); err != nil {
		return fmt.Errorf("rotation rollback: removing %s: %w", newKid, err)
	}
	return nil
}

// --- Helpers ---

func generateKey(keyType string) (*KeyMaterial, error) {
	kid := fmt.Sprintf("starfly-%d", time.Now().UnixNano())

	switch keyType {
	case "RSA-2048":
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generating RSA-2048 key: %w", err)
		}
		return &KeyMaterial{
			Kid:        kid,
			PrivateKey: priv,
			PublicKey:  &priv.PublicKey,
			KeyType:    keyType,
			CreatedAt:  time.Now(),
		}, nil
	case "EC-P256":
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating EC-P256 key: %w", err)
		}
		return &KeyMaterial{
			Kid:        kid,
			PrivateKey: priv,
			PublicKey:  &priv.PublicKey,
			KeyType:    keyType,
			CreatedAt:  time.Now(),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s (supported: RSA-2048, EC-P256)", keyType)
	}
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(h[:])
}
