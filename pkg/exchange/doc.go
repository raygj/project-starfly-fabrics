// Package exchange implements the Starfly token exchange engine.
//
// Phase 1 scope: accepts an RFC 8693 token exchange request, validates
// the source K8s ServiceAccount JWT via the identity provider, evaluates
// OPA policy, mints a WIMSE-compliant JWT signed with an ephemeral dev
// key, and logs an audit event. KMS-backed signing and additional
// credential types are deferred to Phase 2+.
//
// Seed code: Justin's OIDC Token Exchanger Vault plugin.
package exchange
