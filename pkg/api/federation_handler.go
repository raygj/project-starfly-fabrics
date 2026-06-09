package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// FederationRevocationIndex is the interface the federation handlers depend on.
// It mirrors the Hash/Export subset of core.RevocationIndex needed for
// hash-based revocation sync (P13-005).
type FederationRevocationIndex interface {
	Hash() string
	Export() ([]byte, error)
}

// revocationHashResponse is the JSON body returned by GET /v1/federation/revocation-hash.
type revocationHashResponse struct {
	Hash      string `json:"hash"`
	Count     int    `json:"count"`
	Timestamp string `json:"timestamp"`
}

// handleFederationRevocationHash returns the local revocation index hash.
// Peers call this to check whether their revocation state matches before
// doing a full sync via the export endpoint.
func (s *Server) handleFederationRevocationHash(w http.ResponseWriter, r *http.Request) {
	if !s.requireFederationPeerAuth(w, r) {
		return
	}
	if s.revocationIndex == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{
			Error:            "service_unavailable",
			ErrorDescription: "revocation index not configured",
		})
		return
	}

	hash := s.revocationIndex.Hash()

	// Extract count from the export to include in the response.
	// We parse the export JSON to get the count rather than coupling
	// to the concrete type's Len() method.
	count := 0
	if data, err := s.revocationIndex.Export(); err == nil {
		var snapshot core.RevocationSnapshot
		if jsonErr := json.Unmarshal(data, &snapshot); jsonErr == nil {
			count = snapshot.Count
		}
	}

	writeJSON(w, http.StatusOK, revocationHashResponse{
		Hash:      hash,
		Count:     count,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// requireFederationPeerAuth checks the optional shared secret on federation
// revocation endpoints (HARDEN-008). When no secret is configured the check
// is skipped (backwards-compatible). Returns false after writing a 401 when
// the secret is required but missing or wrong.
func (s *Server) requireFederationPeerAuth(w http.ResponseWriter, r *http.Request) bool {
	if s.federationPeerSecret == "" {
		return true
	}
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, errorResponse{
			Error:            "unauthorized",
			ErrorDescription: "federation peer secret required",
		})
		return false
	}
	if strings.TrimPrefix(authHeader, "Bearer ") != s.federationPeerSecret {
		writeJSON(w, http.StatusUnauthorized, errorResponse{
			Error:            "unauthorized",
			ErrorDescription: "invalid federation peer secret",
		})
		return false
	}
	return true
}

// handleFederationRevocationExport returns the full revocation index export.
// This is the heavier endpoint — peers only call it when their local hash
// differs from the hash returned by /v1/federation/revocation-hash.
func (s *Server) handleFederationRevocationExport(w http.ResponseWriter, r *http.Request) {
	if !s.requireFederationPeerAuth(w, r) {
		return
	}
	if s.revocationIndex == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{
			Error:            "service_unavailable",
			ErrorDescription: "revocation index not configured",
		})
		return
	}

	data, err := s.revocationIndex.Export()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{
			Error:            "server_error",
			ErrorDescription: "failed to export revocation index",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// Write the pre-serialized JSON directly — no double-encoding.
	_, _ = w.Write(data)
}
