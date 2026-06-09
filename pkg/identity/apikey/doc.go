// Package apikey validates static API keys against a local registry.
// This is a migration path for legacy systems — keys are stored as
// SHA-256 hashes, never in plaintext. OPA policies should apply stricter
// constraints to credentials with migration_path=true.
package apikey
