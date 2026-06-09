// Package identity manages workload and agent identity operations.
//
// Phase 1 implements K8s ServiceAccount validation via OIDC/JWKS.
// A K8s workload presents its ServiceAccount JWT; the provider
// validates the signature against the cluster's JWKS endpoint,
// checks standard claims (exp, aud, iss), and returns a
// WorkloadIdentity with a WIMSE URI for downstream consumption.
package identity
