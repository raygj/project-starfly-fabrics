// Package api provides the HTTP API server for Starfly Fabrics.
//
// The server exposes REST endpoints for token exchange, shared signals,
// agent identity, and system health. All routes are prefixed with /v1/.
//
// When TLS is enabled, a dual-port architecture is used:
//   - Port 8693 (plaintext): public endpoints (health, JWKS, metrics)
//   - Port 8694 (mTLS): protected endpoints (exchange, signals, identity/agent)
//
// Middleware provides request ID tracking and structured logging via slog.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/mcp"
	"github.com/starfly-fabrics/starfly/pkg/metrics"
	"github.com/starfly-fabrics/starfly/pkg/secrets"
	"github.com/starfly-fabrics/starfly/pkg/toolcall"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// Server is the Starfly HTTP API server.
type Server struct {
	httpServer *http.Server
	router     *http.ServeMux
	mtlsServer *http.Server
	mtlsRouter *http.ServeMux
	tlsEnabled bool
	version    string
	unitID     string
	exchanger  core.TokenExchanger
	jwks       JWKSProvider
	agentIdentity     core.AgentIdentityProvider
	signalReceiver    SignalReceiver
	signalTransmitter SignalTransmitter
	devMode           bool
	metrics       *metrics.Metrics
	tlsCfg        core.TLSConfig
	openapiSpec      []byte
	broadcaster      *EventBroadcaster
	revocationIndex    FederationRevocationIndex
	certReloader       *certReloader
	mcpRegistry        *mcp.Registry
	mcpJWKSResolver    core.JWKSResolver
	mcpRevocationIndex core.RevocationIndex
	mcpPolicy          core.PolicyEngine
	mcpAuditor         core.Auditor
	encryptionKeyStore   secrets.EncryptionKeyStore
	toolRegistry         *toolcall.Registry
	federationPeerSecret string // HARDEN-008: optional shared secret for federation endpoints
	trustDomains         []core.TrustDomain
}

// New creates a new API server with routes and middleware configured.
func New(cfg *core.Config, version string, exchanger core.TokenExchanger, opts ...ServerOption) *Server {
	publicMux := http.NewServeMux()

	s := &Server{
		router:      publicMux,
		version:     version,
		unitID:      core.GenerateUnitID(),
		exchanger:   exchanger,
		devMode:     cfg.DevMode,
		tlsEnabled:  cfg.TLS.Enabled,
		tlsCfg:      cfg.TLS,
		broadcaster: NewEventBroadcaster(),
	}
	for _, opt := range opts {
		opt(s)
	}

	// Derive primary trust domain for the info gauge.
	trustDomain := ""
	if len(cfg.TrustDomains) > 0 {
		trustDomain = cfg.TrustDomains[0].Name
	}
	m := metrics.New(version, s.unitID, trustDomain)
	s.metrics = m

	// Public endpoints — always on the plaintext port.
	publicMux.HandleFunc("GET /v1/sys/health", s.handleHealth)
	publicMux.HandleFunc("GET /v1/sys/trust-domains", s.handleTrustDomains)
	publicMux.HandleFunc("GET /v1/identity/jwks", s.handleJWKS)
	publicMux.Handle("GET /metrics", m.Handler())
	publicMux.HandleFunc("GET /openapi.yaml", s.handleOpenAPI)
	publicMux.HandleFunc("GET /v1/events", s.HandleEvents)

	if s.tlsEnabled {
		// Protected endpoints go on the mTLS mux.
		mtlsMux := http.NewServeMux()
		s.mtlsRouter = mtlsMux

		mtlsMux.HandleFunc("POST /v1/exchange/token", s.handleExchangeToken)
		mtlsMux.HandleFunc("GET /.well-known/ssf-configuration", s.handleSSFConfiguration)
		mtlsMux.HandleFunc("POST /v1/signals/events", s.handleSignalEvent)
		mtlsMux.HandleFunc("POST /v1/signals/stream", s.handleStreamConfig)
		mtlsMux.HandleFunc("DELETE /v1/signals/stream", s.handleStreamConfig)
		mtlsMux.HandleFunc("GET /v1/signals/status", s.handleStreamStatus)
		mtlsMux.HandleFunc("POST /v1/identity/agent", s.handleAgentIdentity)
		mtlsMux.HandleFunc("GET /v1/federation/revocation-hash", s.handleFederationRevocationHash)
		mtlsMux.HandleFunc("GET /v1/federation/revocation-export", s.handleFederationRevocationExport)
		mtlsMux.HandleFunc("GET /v1/mcp/tools", s.handleMCPToolList)
		mtlsMux.HandleFunc("POST /v1/mcp/tools", s.handleMCPToolRegister)
		mtlsMux.HandleFunc("DELETE /v1/mcp/tools", s.handleMCPToolDeregister)
		mtlsMux.HandleFunc("POST /v1/mcp/verify", s.handleMCPVerify)
		mtlsMux.HandleFunc("POST /v1/identity/agent/encryption-key", s.handleEncryptionKeyRegister)
		// Universal tool endpoints (UTC-008).
		mtlsMux.HandleFunc("GET /v1/tools", s.handleToolList)
		mtlsMux.HandleFunc("POST /v1/tools", s.handleToolRegister)
		mtlsMux.HandleFunc("GET /v1/tools/{tool_id}", s.handleToolGet)
		mtlsMux.HandleFunc("DELETE /v1/tools/{tool_id}", s.handleToolDeregister)
		mtlsMux.HandleFunc("GET /v1/tools/{tool_id}/audit", s.handleToolAudit)

		mtlsHandler := otelhttp.NewMiddleware("starfly-mtls")(
			requestIDMiddleware(
				rateLimitMiddleware(
					mtlsMiddleware(mtlsMux),
					cfg.RateLimit, cfg.DevMode, m,
				),
			),
		)

		tlsConfig, reloader, err := buildMTLSConfigWithReloader(cfg.TLS)
		if err != nil {
			slog.Error("failed to build mTLS config", "error", err)
		} else {
			s.certReloader = reloader
			s.mtlsServer = &http.Server{
				Addr:      cfg.TLS.ListenAddr,
				Handler:   mtlsHandler,
				TLSConfig: tlsConfig,
			}
		}
	} else {
		// Dev mode / no TLS: all endpoints on the plaintext port.
		publicMux.HandleFunc("POST /v1/exchange/token", s.handleExchangeToken)
		publicMux.HandleFunc("POST /v1/signals/events", s.handleSignalEvent)
		publicMux.HandleFunc("POST /v1/signals/stream", s.handleStreamConfig)
		publicMux.HandleFunc("DELETE /v1/signals/stream", s.handleStreamConfig)
		publicMux.HandleFunc("GET /v1/signals/status", s.handleStreamStatus)
		publicMux.HandleFunc("GET /.well-known/ssf-configuration", s.handleSSFConfiguration)
		publicMux.HandleFunc("POST /v1/identity/agent", s.handleAgentIdentity)
		publicMux.HandleFunc("GET /v1/federation/revocation-hash", s.handleFederationRevocationHash)
		publicMux.HandleFunc("GET /v1/federation/revocation-export", s.handleFederationRevocationExport)
		publicMux.HandleFunc("GET /v1/mcp/tools", s.handleMCPToolList)
		publicMux.HandleFunc("POST /v1/mcp/tools", s.handleMCPToolRegister)
		publicMux.HandleFunc("DELETE /v1/mcp/tools", s.handleMCPToolDeregister)
		publicMux.HandleFunc("POST /v1/mcp/verify", s.handleMCPVerify)
		publicMux.HandleFunc("POST /v1/identity/agent/encryption-key", s.handleEncryptionKeyRegister)
		// Universal tool endpoints (UTC-008).
		publicMux.HandleFunc("GET /v1/tools", s.handleToolList)
		publicMux.HandleFunc("POST /v1/tools", s.handleToolRegister)
		publicMux.HandleFunc("GET /v1/tools/{tool_id}", s.handleToolGet)
		publicMux.HandleFunc("DELETE /v1/tools/{tool_id}", s.handleToolDeregister)
		publicMux.HandleFunc("GET /v1/tools/{tool_id}/audit", s.handleToolAudit)
	}

	s.httpServer = &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: otelhttp.NewMiddleware("starfly")(requestIDMiddleware(rateLimitMiddleware(publicMux, cfg.RateLimit, cfg.DevMode, m))),
	}

	// Set initial TLS cert expiry metric if TLS is active.
	s.updateTLSCertExpiryMetric()

	slog.Info("api server configured",
		"listen_addr", cfg.ListenAddr,
		"tls_enabled", s.tlsEnabled,
		"unit_id", s.unitID,
	)

	return s
}

// ListenAndServe starts the plaintext HTTP server.
func (s *Server) ListenAndServe() error {
	return s.httpServer.ListenAndServe()
}

// ListenAndServeTLS starts the mTLS listener. It returns nil immediately
// if TLS is not enabled or the mTLS server was not initialized.
func (s *Server) ListenAndServeTLS() error {
	if s.mtlsServer == nil {
		return nil
	}
	// TLS config is already set on the server; use empty cert/key paths
	// because certs are loaded in the TLSConfig directly.
	return s.mtlsServer.ListenAndServeTLS("", "")
}

// Shutdown gracefully shuts down the plaintext HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// ShutdownMTLS gracefully shuts down the mTLS server.
// Returns nil if the mTLS server was not started.
func (s *Server) ShutdownMTLS(ctx context.Context) error {
	if s.mtlsServer == nil {
		return nil
	}
	return s.mtlsServer.Shutdown(ctx)
}

// TLSEnabled reports whether the mTLS listener is configured.
func (s *Server) TLSEnabled() bool {
	return s.tlsEnabled
}

// Metrics returns the server's Prometheus metrics instance so that
// subsystems initialised outside the API layer can record observations.
func (s *Server) Metrics() *metrics.Metrics {
	return s.metrics
}

// Broadcaster returns the server's event broadcaster so that external
// subsystems can publish FabricEvents to connected SSE clients.
func (s *Server) Broadcaster() *EventBroadcaster {
	return s.broadcaster
}

// writeJSON marshals v as JSON and writes it with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to write JSON response", "error", err)
	}
}

// ServerOption configures optional Server dependencies.
type ServerOption func(*Server)

// WithJWKS sets the JWKS provider for the /v1/identity/jwks endpoint.
func WithJWKS(j JWKSProvider) ServerOption {
	return func(s *Server) { s.jwks = j }
}

// WithUnitID sets the unit ID instead of generating a new one.
// This allows sharing one ID across the API server and sync bus.
func WithUnitID(id string) ServerOption {
	return func(s *Server) { s.unitID = id }
}

// WithAgentIdentity sets the agent identity provider for the
// POST /v1/identity/agent endpoint.
func WithAgentIdentity(p core.AgentIdentityProvider) ServerOption {
	return func(s *Server) { s.agentIdentity = p }
}

// WithSignalReceiver sets the SSF signal receiver for POST /v1/signals/events.
func WithSignalReceiver(rx SignalReceiver) ServerOption {
	return func(s *Server) { s.signalReceiver = rx }
}

// WithSignalTransmitter sets the SSF transmitter for stream management.
func WithSignalTransmitter(tx SignalTransmitter) ServerOption {
	return func(s *Server) { s.signalTransmitter = tx }
}

// WithOpenAPISpec sets the raw OpenAPI spec content served at GET /openapi.yaml.
func WithOpenAPISpec(spec []byte) ServerOption {
	return func(s *Server) { s.openapiSpec = spec }
}

// WithRevocationIndex sets the revocation index for the federation
// sync endpoints (GET /v1/federation/revocation-hash and revocation-export).
func WithRevocationIndex(idx FederationRevocationIndex) ServerOption {
	return func(s *Server) { s.revocationIndex = idx }
}

// WithMCPRegistry sets the MCP tool registry for the /v1/mcp/* endpoints.
func WithMCPRegistry(r *mcp.Registry) ServerOption {
	return func(s *Server) { s.mcpRegistry = r }
}

// WithFederationPeerSecret sets an optional shared secret that federation peers
// must present as "Authorization: Bearer <secret>" on the revocation endpoints.
// In mTLS mode the client certificate is the primary gate; this option adds
// defence-in-depth for dev/lab deployments without mTLS (HARDEN-008).
// If the secret is empty the check is skipped (backwards-compatible).
func WithFederationPeerSecret(secret string) ServerOption {
	return func(s *Server) { s.federationPeerSecret = secret }
}

// WithToolRegistry sets the universal tool registry for the /v1/tools/* endpoints.
func WithToolRegistry(r *toolcall.Registry) ServerOption {
	return func(s *Server) { s.toolRegistry = r }
}

// WithEncryptionKeyStore sets the encryption key store for the
// POST /v1/identity/agent/encryption-key endpoint (ADR-0014).
func WithEncryptionKeyStore(ks secrets.EncryptionKeyStore) ServerOption {
	return func(s *Server) { s.encryptionKeyStore = ks }
}

// WithMCPDeps sets the MCP middleware dependencies: JWKS resolver for JWT
// verification, revocation index for revocation checks, policy engine for
// OPA evaluation, and auditor for security audit logging.
func WithMCPDeps(jwks core.JWKSResolver, rev core.RevocationIndex, policy core.PolicyEngine, auditor core.Auditor) ServerOption {
	return func(s *Server) {
		s.mcpJWKSResolver = jwks
		s.mcpRevocationIndex = rev
		s.mcpPolicy = policy
		s.mcpAuditor = auditor
	}
}

// WithTrustDomains sets the trust domain list for the /v1/sys/trust-domains endpoint.
func WithTrustDomains(domains []core.TrustDomain) ServerOption {
	return func(s *Server) { s.trustDomains = domains }
}
