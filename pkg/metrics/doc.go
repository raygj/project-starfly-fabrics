// Package metrics provides Prometheus instrumentation for Starfly Fabrics.
//
// Phase 1 scope: counters and histograms for exchange requests, policy
// evaluations, store operations, and audit events. A unit_info gauge
// exports build metadata. All metrics are registered on a custom
// prometheus.Registry exposed via Handler().
//
// Seed code reference: P1-010 in PHASE-1-BACKLOG.md.
package metrics
