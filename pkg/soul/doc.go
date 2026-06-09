// Package soul implements the Soul Manifest — the minimal state that makes
// a Starfly fabric recoverable, upgradeable, and portable across clusters.
//
// The Soul Manifest captures signing key references, trust domain config,
// revocation index snapshots, SSF stream registrations, and audit buffer state.
// It is written to an external anchor (S3, filesystem) on interval and on
// significant events. On boot with empty state, the recovery sequence reads
// the manifest and reconstructs a fully operational fabric.
//
// The same manifest that enables cluster-death recovery also enables
// deterministic upgrades: commit a new manifest to git, the fabric converges.
package soul
