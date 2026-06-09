package sync

// Signal type constants define the taxonomy of signals on the NATS bus.
// Signals are published to subjects of the form: starfly.{trust_domain}.{type}
//
// Example: starfly.prod.acme.com.identity.minted
const (
	// Identity signals — credential lifecycle events.
	SignalIdentityMinted  = "identity.minted"  // New WIMSE JWT issued
	SignalIdentityRevoked = "identity.revoked"  // Credential revoked (CAEP)
	SignalIdentityExpired = "identity.expired"  // Credential expired (TTL)

	// Fabric signals — infrastructure state events.
	SignalFabricRotation = "fabric.rotation" // Signing key rotation event
	SignalFabricSoul     = "fabric.soul"     // Soul manifest snapshot written
	SignalFabricSOS      = "fabric.sos"      // Autonomic scaling signal (overwhelmed)
	SignalFabricHealth   = "fabric.health"   // Periodic health flash

	// Policy signals — policy state changes.
	SignalPolicyUpdated = "policy.updated" // OPA policy bundle reloaded

	// CAEP signals — security event cascades.
	SignalCAEPSessionRevoked    = "caep.session_revoked"    // OpenID CAEP session revoked
	SignalCAEPCredentialChange  = "caep.credential_change"  // OpenID CAEP credential change
	SignalCAEPTokenClaimsChange = "caep.token_claims_change" // OpenID CAEP token claims change
)
