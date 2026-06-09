package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/mcp"
)

// handleMCPToolList handles GET /v1/mcp/tools — list all registered tools.
func (s *Server) handleMCPToolList(w http.ResponseWriter, r *http.Request) {
	if s.mcpRegistry == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{
			Error:            "mcp_not_configured",
			ErrorDescription: "MCP tool registry is not configured",
		})
		return
	}

	tools := s.mcpRegistry.List()
	s.metrics.MCPRegisteredTools.Set(float64(len(tools)))
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tools": tools,
		"count": len(tools),
	})
}

// handleMCPToolRegister handles POST /v1/mcp/tools — register a new tool.
func (s *Server) handleMCPToolRegister(w http.ResponseWriter, r *http.Request) {
	if !s.devMode && !s.requireBearerAuth(w, r) {
		return
	}
	if s.mcpRegistry == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{
			Error:            "mcp_not_configured",
			ErrorDescription: "MCP tool registry is not configured",
		})
		return
	}

	var entry mcp.ToolEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{
			Error:            "invalid_request",
			ErrorDescription: "invalid JSON body: " + err.Error(),
		})
		return
	}

	if entry.ToolID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{
			Error:            "invalid_request",
			ErrorDescription: "tool_id is required",
		})
		return
	}

	if err := s.mcpRegistry.Register(&entry); err != nil {
		writeJSON(w, http.StatusConflict, errorResponse{
			Error:            "tool_exists",
			ErrorDescription: err.Error(),
		})
		return
	}

	s.metrics.MCPRegisteredTools.Set(float64(s.mcpRegistry.Count()))
	slog.Info("mcp: tool registered", "tool_id", entry.ToolID, "name", entry.Name)
	writeJSON(w, http.StatusCreated, entry)
}

// handleMCPToolDeregister handles DELETE /v1/mcp/tools — deregister a tool.
func (s *Server) handleMCPToolDeregister(w http.ResponseWriter, r *http.Request) {
	if !s.devMode && !s.requireBearerAuth(w, r) {
		return
	}
	if s.mcpRegistry == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{
			Error:            "mcp_not_configured",
			ErrorDescription: "MCP tool registry is not configured",
		})
		return
	}

	toolID := r.URL.Query().Get("tool_id")
	if toolID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{
			Error:            "invalid_request",
			ErrorDescription: "tool_id query parameter is required",
		})
		return
	}

	if err := s.mcpRegistry.Deregister(toolID); err != nil {
		writeJSON(w, http.StatusNotFound, errorResponse{
			Error:            "tool_not_found",
			ErrorDescription: err.Error(),
		})
		return
	}

	s.metrics.MCPRegisteredTools.Set(float64(s.mcpRegistry.Count()))
	slog.Info("mcp: tool deregistered", "tool_id", toolID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deregistered", "tool_id": toolID})
}

// mcpVerifyRequest is the request body for the verify endpoint.
type mcpVerifyRequest struct {
	Token     string `json:"token"`
	ToolID    string `json:"tool_id"`
	DPoPProof string `json:"dpop_proof,omitempty"` // RFC 9449 DPoP proof JWT (also accepted via DPoP HTTP header)
}

// handleMCPVerify handles POST /v1/mcp/verify — verify a token for an MCP tool call.
// This is a standalone verification endpoint for external MCP servers that want
// to delegate JWT verification to Starfly instead of running the middleware inline.
func (s *Server) handleMCPVerify(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	var req mcpVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.metrics.MCPToolCallsTotal.WithLabelValues("", "error").Inc()
		writeJSON(w, http.StatusBadRequest, errorResponse{
			Error:            "invalid_request",
			ErrorDescription: "invalid JSON body: " + err.Error(),
		})
		return
	}

	if req.Token == "" {
		s.metrics.MCPToolCallsTotal.WithLabelValues(req.ToolID, "error").Inc()
		writeJSON(w, http.StatusBadRequest, errorResponse{
			Error:            "invalid_request",
			ErrorDescription: "token is required",
		})
		return
	}

	cfg := mcp.Config{
		JWKSResolver:      s.mcpJWKSResolver,
		Registry:          s.mcpRegistry,
		RevocationChecker: s.mcpRevocationIndex,
		Policy:            s.mcpPolicy,
		Auditor:           s.mcpAuditor,
		UnitID:            s.unitID,
		DevMode:           s.devMode,
	}

	// DPoP proof: prefer DPoP HTTP header (RFC 9449 §4.1), fall back to JSON body field.
	dpopProof := r.Header.Get("DPoP")
	if dpopProof == "" {
		dpopProof = req.DPoPProof
	}

	claims, err := mcp.VerifyToolCall(r.Context(), cfg, req.Token, req.ToolID, &mcp.VerifyOptions{DPoPProof: dpopProof})
	duration := time.Since(start).Seconds()
	s.metrics.MCPVerifyDurationSeconds.WithLabelValues().Observe(duration)

	if err != nil {
		s.metrics.MCPToolCallsTotal.WithLabelValues(req.ToolID, "denied").Inc()
		s.metrics.MCPCheckDenialsTotal.WithLabelValues(mcpCheckName(err)).Inc()
		writeJSON(w, http.StatusForbidden, errorResponse{
			Error:            "verification_failed",
			ErrorDescription: err.Error(),
		})
		return
	}

	s.metrics.MCPToolCallsTotal.WithLabelValues(req.ToolID, "allowed").Inc()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"verified": true,
		"claims":   claims,
	})
}

// mcpCheckName maps an MCP verification error to its pipeline check name.
func mcpCheckName(err error) string {
	switch {
	case errors.Is(err, mcp.ErrInvalidToken), errors.Is(err, mcp.ErrMissingToken):
		return "signature"
	case errors.Is(err, mcp.ErrDPoPInvalid):
		return "dpop"
	case errors.Is(err, mcp.ErrAudienceMismatch):
		return "audience"
	case errors.Is(err, mcp.ErrBlastRadiusExceeded):
		return "blast_radius"
	case errors.Is(err, mcp.ErrTokenRevoked):
		return "revocation"
	case errors.Is(err, mcp.ErrPolicyDenied), errors.Is(err, mcp.ErrCapabilityDenied):
		return "policy"
	case errors.Is(err, mcp.ErrExecOpMismatch):
		return "exec_act"
	case errors.Is(err, mcp.ErrExecPayloadMismatch), errors.Is(err, mcp.ErrExecPayloadMissing):
		return "inp_hash"
	case errors.Is(err, mcp.ErrExecTargetMismatch):
		return "target"
	case errors.Is(err, mcp.ErrToolNotRegistered):
		return "registration"
	default:
		return "unknown"
	}
}
