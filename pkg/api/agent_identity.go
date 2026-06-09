package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/starfly-fabrics/starfly/pkg/core"
	agentpkg "github.com/starfly-fabrics/starfly/pkg/identity/agent"
)

// handleAgentIdentity handles POST /v1/identity/agent.
func (s *Server) handleAgentIdentity(w http.ResponseWriter, r *http.Request) {
	if !s.requireBearerAuth(w, r) {
		return
	}
	if s.agentIdentity == nil {
		writeJSON(w, http.StatusNotImplemented, errorResponse{
			Error:            "not_implemented",
			ErrorDescription: "agent identity provider not configured",
		})
		return
	}

	var req core.AgentIdentityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{
			Error:            "invalid_request",
			ErrorDescription: "malformed request body",
		})
		return
	}

	identity, err := s.agentIdentity.IssueAgentIdentity(r.Context(), &req)
	if err != nil {
		switch {
		case errors.Is(err, agentpkg.ErrMissingAgentName),
			errors.Is(err, agentpkg.ErrInvalidPlatform),
			errors.Is(err, agentpkg.ErrEmptyCapabilities):
			writeJSON(w, http.StatusBadRequest, errorResponse{
				Error:            "invalid_request",
				ErrorDescription: err.Error(),
			})
		default:
			writeJSON(w, http.StatusInternalServerError, errorResponse{
				Error:            "server_error",
				ErrorDescription: err.Error(),
			})
		}
		return
	}

	writeJSON(w, http.StatusOK, identity)
}
