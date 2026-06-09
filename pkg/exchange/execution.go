package exchange

import (
	"fmt"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/starfly-fabrics/starfly/pkg/core"
)

// ExecutionScopeTTL is the TTL for execution-scoped tokens.
// Short-lived by design — these tokens authorize a single action.
const ExecutionScopeTTL = 30 * time.Second

// ErrExecutionScopeInvalid is returned when execution scope validation fails.
var ErrExecutionScopeInvalid = fmt.Errorf("execution scope validation failed")

// ErrNonceReplay is returned when a nonce has already been used.
var ErrNonceReplay = fmt.Errorf("nonce already used")

// nonceHighWaterMark triggers a forced cleanup when the nonce map exceeds this size.
// Nonce tracking is per-instance — distributed deployments need shared nonce
// tracking (e.g., Redis) to prevent cross-instance replay.
const nonceHighWaterMark = 10000

// nonceTracker tracks used nonces for replay protection.
// Entries auto-expire based on ExecutionScopeTTL.
type nonceTracker struct {
	mu      sync.Mutex
	seen    map[string]time.Time
	maxAge  time.Duration
	ops     uint64
}

func newNonceTracker() *nonceTracker {
	return &nonceTracker{
		seen:   make(map[string]time.Time),
		maxAge: ExecutionScopeTTL * 2, // keep nonces 2x TTL for safety
	}
}

// cleanupInterval controls how often opportunistic cleanup runs.
const cleanupInterval = 100

// check returns an error if the nonce has been seen before.
// Records the nonce if it's new.
func (n *nonceTracker) check(nonce string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	now := time.Now()

	// Opportunistic cleanup: every N calls or when high-water mark is exceeded.
	n.ops++
	if len(n.seen) >= nonceHighWaterMark || n.ops%cleanupInterval == 0 {
		n.cleanupLocked(now)
	}

	if _, exists := n.seen[nonce]; exists {
		return fmt.Errorf("%w: %s", ErrNonceReplay, nonce)
	}
	n.seen[nonce] = now
	return nil
}

// size returns the current number of tracked nonces.
func (n *nonceTracker) size() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.seen)
}

// cleanupLocked removes expired entries. Caller must hold n.mu.
func (n *nonceTracker) cleanupLocked(now time.Time) {
	for k, ts := range n.seen {
		if now.Sub(ts) > n.maxAge {
			delete(n.seen, k)
		}
	}
}

// validateExecutionScope checks that a request's execution scope is well-formed.
func validateExecutionScope(scope *core.ExecutionScope) error {
	if scope.Method == "" {
		return fmt.Errorf("%w: htm (method) is required", ErrExecutionScopeInvalid)
	}
	if scope.URI == "" {
		return fmt.Errorf("%w: htu (URI) is required", ErrExecutionScopeInvalid)
	}
	if scope.Nonce == "" {
		return fmt.Errorf("%w: nonce is required", ErrExecutionScopeInvalid)
	}
	return nil
}

// VerifyExecutionScope checks that a token's execution claims match the
// presented action. Used by resource servers to verify that the token
// authorizes THIS specific request.
func VerifyExecutionScope(token jwt.Token, scope *core.ExecutionScope) error {
	// Check htm claim matches.
	var htm string
	if err := token.Get("htm", &htm); err != nil {
		return fmt.Errorf("%w: token missing htm claim", ErrExecutionScopeInvalid)
	}
	if htm != scope.Method {
		return fmt.Errorf("%w: htm mismatch: token=%q, request=%q", ErrExecutionScopeInvalid, htm, scope.Method)
	}

	// Check htu claim matches.
	var htu string
	if err := token.Get("htu", &htu); err != nil {
		return fmt.Errorf("%w: token missing htu claim", ErrExecutionScopeInvalid)
	}
	if htu != scope.URI {
		return fmt.Errorf("%w: htu mismatch: token=%q, request=%q", ErrExecutionScopeInvalid, htu, scope.URI)
	}

	// Check input hash (inp_hash, ECT-aligned).
	// Falls back to payload_hash for backward compatibility.
	wantHash := scope.InputHash
	if wantHash == "" {
		wantHash = scope.PayloadHash
	}
	if wantHash != "" {
		var tokenHash string
		if err := token.Get("inp_hash", &tokenHash); err != nil {
			// Fallback to legacy claim name.
			if err2 := token.Get("payload_hash", &tokenHash); err2 != nil {
				return fmt.Errorf("%w: token missing inp_hash claim", ErrExecutionScopeInvalid)
			}
		}
		if tokenHash != wantHash {
			return fmt.Errorf("%w: inp_hash mismatch", ErrExecutionScopeInvalid)
		}
	}

	return nil
}
