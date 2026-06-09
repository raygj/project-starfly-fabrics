// Package sync implements the Firefly Protocol — inter-unit signal flashing over NATS.
//
// In dev/embedded mode an in-process nats-server starts with JetStream enabled
// and DontListen: true (no TCP port). In production mode the bus connects to an
// external NATS cluster. All signals are published to the STARFLY_SIGNALS
// JetStream stream with 72-hour retention.
//
// Subject convention: starfly.{trust_domain}.{signal_type}
// e.g. starfly.production.example.com.identity_event
package sync
