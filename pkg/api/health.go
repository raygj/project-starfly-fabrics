package api

import (
	"net/http"
	"time"
)

// healthResponse is the JSON body returned by the health endpoint.
type healthResponse struct {
	Initialized    bool    `json:"initialized"`
	Locked         bool    `json:"locked"`
	Version        string  `json:"version"`
	UnitID         string  `json:"unit_id"`
	TLSCertExpiry  *string `json:"tls_cert_expiry,omitempty"`
}

// handleHealth returns the current health status of the Starfly unit.
// In Phase 1 with the dev lock, initialized is always true and locked
// is always false.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Refresh the TLS cert expiry metric on each health check (called by
	// liveness/readiness probes, so it stays up to date after cert rotation).
	s.updateTLSCertExpiryMetric()

	resp := healthResponse{
		Initialized: true,
		Locked:      false,
		Version:     s.version,
		UnitID:      s.unitID,
	}

	if s.certReloader != nil {
		expiry := s.certReloader.CertExpiry()
		if !expiry.IsZero() {
			formatted := expiry.UTC().Format(time.RFC3339)
			resp.TLSCertExpiry = &formatted
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

type trustDomainResponse struct {
	Name    string `json:"name"`
	Issuer  string `json:"issuer"`
	JWKSURL string `json:"jwks_url,omitempty"`
	Enabled bool   `json:"enabled"`
}

type trustDomainsResponse struct {
	Count        int                   `json:"count"`
	TrustDomains []trustDomainResponse `json:"trust_domains"`
}

// handleTrustDomains returns the configured trust domains for this fabric unit.
func (s *Server) handleTrustDomains(w http.ResponseWriter, r *http.Request) {
	domains := make([]trustDomainResponse, 0, len(s.trustDomains))
	for _, td := range s.trustDomains {
		domains = append(domains, trustDomainResponse{
			Name:    td.Name,
			Issuer:  td.Issuer,
			JWKSURL: td.JWKSURL,
			Enabled: td.Enabled,
		})
	}
	writeJSON(w, http.StatusOK, trustDomainsResponse{
		Count:        len(domains),
		TrustDomains: domains,
	})
}

// updateTLSCertExpiryMetric sets the starfly_tls_cert_expiry_seconds gauge
// to the number of seconds until the TLS certificate expires.
func (s *Server) updateTLSCertExpiryMetric() {
	if s.certReloader == nil || s.metrics == nil {
		return
	}
	expiry := s.certReloader.CertExpiry()
	if expiry.IsZero() {
		return
	}
	s.metrics.TLSCertExpirySeconds.Set(time.Until(expiry).Seconds())
}

// handleOpenAPI serves the OpenAPI 3.1 specification.
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	if len(s.openapiSpec) == 0 {
		http.Error(w, "OpenAPI spec not configured", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.openapiSpec)
}
