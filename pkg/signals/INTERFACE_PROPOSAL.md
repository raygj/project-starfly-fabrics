# P4-001: SignalEngine Interface Proposal — v2

**Status:** GATE_CHECK (v2 — refactored per architecture review)
**For:** Jim to apply to `pkg/core/interfaces.go`
**Date:** 2026-03-07
**Review:** `architecture/P4-001-interface-review.md` — Conditional Pass, all findings addressed below

---

## Changes from v1

| Finding | Severity | Resolution |
|---------|----------|------------|
| F-001: Split interface | High | `SignalEngine` composed from `SignalTransmitter` + `SignalReceiver` + `SignalDiscovery` |
| F-002: RevocationIndex scaling | High | `IsRevoked` returns `*RevocationEntry` (not bool), performance contract in godoc |
| F-003: ReceiveEvent routing | Medium | Routing table added as godoc |
| F-004: TransmitEvent matching | Medium | Matching contract added as godoc |
| F-005: NATSConfig location | Low | Removed from proposal — stays in `pkg/sync/` |

---

## What to Add

Replace the Phase 2 placeholder comment (lines ~116-118) with the composed interfaces.

### Interface Definitions

```go
// ─────────────────────────────────────────────────────────────────────
// SHARED SIGNALS
// SSF/CAEP: receive security events, evaluate policy, propagate.
// Interfaces are split by responsibility following io.Reader/Writer:
//   - SignalTransmitter: outbound stream management + event delivery
//   - SignalReceiver: inbound event validation + routing
//   - SignalDiscovery: SSF configuration document
//   - SignalEngine: composed interface for full Starfly units
// ─────────────────────────────────────────────────────────────────────

// SignalTransmitter manages outbound SSF streams and event delivery.
// At scale, a transmitter may serve thousands of streams across hundreds
// of trust domains. Implementations MUST index streams by event type
// for O(1) matching — linear scans are not acceptable at scale.
type SignalTransmitter interface {
	// CreateStream creates a new SSF stream for a receiver.
	// Returns the stream with events_supported populated.
	// The actual events delivered are the intersection of
	// events_requested and events_supported.
	CreateStream(ctx context.Context, cfg *StreamConfig) (*Stream, error)

	// DeleteStream removes a stream and stops event delivery.
	DeleteStream(ctx context.Context, streamID string) error

	// TransmitEvent signs the event as a SET (RFC 8417) and delivers
	// to all streams where:
	//   1. The stream's events_requested includes this event type
	//   2. The stream status is "enabled"
	//
	// Delivery method is per-stream:
	//   - Internal streams: NATS publish (per ADR-0001)
	//   - External streams: HTTP push to stream endpoint
	//
	// Failed deliveries are retried with exponential backoff.
	// Permanently failed streams are marked "paused" after max retries.
	// Every transmission produces an audit event.
	TransmitEvent(ctx context.Context, event *SecurityEvent) error

	// GetStreamStatus returns the current status of a stream.
	GetStreamStatus(ctx context.Context, streamID string) (*StreamStatus, error)
}

// SignalReceiver processes inbound security events.
// A compliance aggregator or SIEM connector only needs this interface —
// it never transmits, so it should not be forced to implement transmitter methods.
type SignalReceiver interface {
	// ReceiveEvent validates an incoming SET (RFC 8417), evaluates
	// OPA policy, and routes based on event type:
	//
	// Routing table:
	//   credential-change         → RevocationIndex.Revoke() if change_type is "revoke"
	//   session-revoked           → RevocationIndex.Revoke()
	//   device-compliance-change  → evaluate compliance policy, conditionally revoke
	//   account-disabled          → RevocationIndex.Revoke() for all subject tokens
	//   token-claims-change       → revoke tokens exceeding new capability ceiling
	//   agent-credential-revoked  → RevocationIndex.Revoke() + cascade delegation chain
	//   agent-delegation-revoked  → revoke from the severed link downward
	//   agent-capability-reduced  → revoke tokens exceeding new capability ceiling
	//   agent-blast-radius-reduced → revoke tokens exceeding new blast radius
	//   agent-attestation-failed  → revoke all tokens for subject, quarantine
	//
	// Events for subjects not in this unit's trust domain are
	// forwarded via NATS to units that serve that domain.
	// Events that fail OPA policy evaluation are logged and dropped.
	// Every received event produces an audit event regardless of outcome.
	ReceiveEvent(ctx context.Context, event *SecurityEvent) error
}

// SignalDiscovery serves the SSF configuration document.
type SignalDiscovery interface {
	// Configuration returns the SSF discovery document for this unit.
	// Built from static config at startup — no runtime failure mode.
	Configuration() *SSFConfiguration
}

// SignalEngine is the composed interface for Starfly units that both
// transmit and receive security events. Most Starfly units implement this.
// Receive-only consumers (compliance aggregators, SIEM connectors)
// implement SignalReceiver alone. Transmit-only sources (notification
// gateways) implement SignalTransmitter alone.
type SignalEngine interface {
	SignalTransmitter
	SignalReceiver
	SignalDiscovery
}
```

### RevocationIndex Interface

```go
// RevocationIndex tracks revoked tokens and identities.
// The exchange engine calls IsRevoked on EVERY token exchange —
// treat it accordingly.
//
// Performance contract:
//   - IsRevoked MUST be O(1) or O(log n) — this is hot path (<15ms p99 budget)
//   - Revoke MUST be safe for concurrent calls (cascade bursts of 500+ writes)
//   - Entries MUST auto-expire based on expiresAt (not dependent on Cleanup)
//   - Cleanup is advisory — removes already-expired entries to free memory
//   - All methods MUST be safe for concurrent use by multiple goroutines
type RevocationIndex interface {
	// Revoke marks a subject as revoked.
	Revoke(ctx context.Context, subjectID string, reason string, expiresAt time.Time) error

	// IsRevoked checks whether a subject is currently revoked.
	// Returns the RevocationEntry if revoked, nil if not revoked.
	// Returning the entry (not bool) enables audit trails that explain
	// WHY an exchange was denied — "session-revoked" vs "delegation-chain-revoked"
	// vs "blast-radius-exceeded".
	IsRevoked(ctx context.Context, subjectID string) (*RevocationEntry, error)

	// Cleanup removes expired revocation entries to free memory.
	// Advisory — callers should run periodically but correctness does not
	// depend on it (IsRevoked checks expiry inline).
	Cleanup(ctx context.Context) (int, error)
}

// RevocationEntry contains details about a revoked subject.
// Returned by IsRevoked when the subject IS revoked. Nil when not revoked.
type RevocationEntry struct {
	SubjectID string    `json:"subject_id"`
	Reason    string    `json:"reason"`
	RevokedAt time.Time `json:"revoked_at"`
	ExpiresAt time.Time `json:"expires_at"`
	EventJTI  string    `json:"event_jti,omitempty"` // links back to the triggering SecurityEvent
}
```

### Additional Type Changes

Add `EventsDelivered` field to `StreamConfig`:

```go
// StreamConfig — add field:
EventsDelivered []string `json:"events_delivered,omitempty"` // actual events being delivered (subset of requested)
```

### New Constants

Add to the attestation method constants section:

```go
// Attestation method constants for source credential types.
const (
	AttestMethodSPIFFE   = "spiffe-svid"
	AttestMethodOIDC     = "oidc"
	AttestMethodKerberos = "kerberos"
	AttestMethodSAML     = "saml"
)
```

---

## What NOT to Add

**NATSConfig** stays in `pkg/sync/` where it belongs (F-005). The interface layer should never know about NATS, Kafka, or any specific transport.

---

## Why This Design

1. **Composable interfaces** (`SignalTransmitter` / `SignalReceiver` / `SignalDiscovery`) follow the `io.Reader` / `io.Writer` / `io.ReadWriter` pattern. A compliance aggregator implements `SignalReceiver`. A notification gateway implements `SignalTransmitter`. A full Starfly unit implements `SignalEngine`. 30 minutes of refactoring now saves a breaking change when the first enterprise customer wants a receive-only connector.

2. **`RevocationEntry` return** from `IsRevoked` (not `bool`) enables audit trails that explain WHY an exchange was denied. "Compromised key" vs "delegation chain revoked" vs "capability reduction" — that's the difference between a useful audit trail and a useless one.

3. **Performance contract in godoc** makes `IsRevoked`'s hot-path nature explicit. Implementers know this is O(1) or O(log n), concurrent, and in the <15ms p99 budget. No surprises at 200 trust domains.

4. **Routing contract in godoc** tells implementers what `ReceiveEvent` actually does without reading the implementation. Phase 6 agent event types are included because Phase 4 is the implementation layer for Phase 6's revocation story.

5. **Stream types** (`StreamConfig`, `Stream`, `StreamStatus`, `SSFConfiguration`) already exist in interfaces.go. Only interfaces and `RevocationEntry` are new.

6. **Interim adapter** — until `RevocationIndex` lands in `pkg/core/interfaces.go`, the exchange engine uses a minimal `RevocationChecker` interface with `(bool, error)` returns. `signals.NewRevocationChecker(idx)` adapts the richer `*RevocationEntry` return to the simpler `bool`. When you apply the core interface, this adapter becomes unnecessary and callers pass the index directly.
