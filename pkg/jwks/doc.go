// Package jwks implements a cached JWKS resolver for cross-domain key
// resolution. It provides cache-with-TTL, kid-miss refetch, stale-while-
// revalidate, and prefetch-on-boot per ADR-0003.
package jwks
