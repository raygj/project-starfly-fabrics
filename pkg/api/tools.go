package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/starfly-fabrics/starfly/pkg/metrics"
	"github.com/starfly-fabrics/starfly/pkg/toolcall"
)

// NewToolCallMiddlewareMetrics builds a toolcall.MiddlewareMetrics that records
// into the given Metrics instance. Returns nil if m is nil.
func NewToolCallMiddlewareMetrics(m *metrics.Metrics) *toolcall.MiddlewareMetrics {
	if m == nil {
		return nil
	}
	return &toolcall.MiddlewareMetrics{
		RecordCall: func(protocol, decision string) {
			m.ToolCallTotal.WithLabelValues(protocol, decision).Inc()
		},
		ObserveDuration: func(protocol string, seconds float64) {
			m.ToolCallDurationSeconds.WithLabelValues(protocol).Observe(seconds)
		},
		IncTie: func() {
			m.ToolCallProtocolTiesTotal.Inc()
		},
	}
}

// toolRegistryReady returns false and writes a 503 if the universal tool registry
// is not configured.
func (s *Server) toolRegistryReady(w http.ResponseWriter) bool {
	if s.toolRegistry == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{
			Error:            "registry_not_configured",
			ErrorDescription: "universal tool registry is not configured",
		})
		return false
	}
	return true
}

// handleToolList handles GET /v1/tools — list registered tools, optionally
// filtered by ?protocol=mcp|http|a2a.
func (s *Server) handleToolList(w http.ResponseWriter, r *http.Request) {
	if !s.toolRegistryReady(w) {
		return
	}

	var filter *toolcall.Protocol
	if p := r.URL.Query().Get("protocol"); p != "" {
		proto := toolcall.Protocol(p)
		filter = &proto
	}

	tools := s.toolRegistry.List(filter)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tools": tools,
		"count": len(tools),
	})
}

// handleToolRegister handles POST /v1/tools — register a new tool for any protocol.
func (s *Server) handleToolRegister(w http.ResponseWriter, r *http.Request) {
	if !s.devMode && !s.requireBearerAuth(w, r) {
		return
	}
	if !s.toolRegistryReady(w) {
		return
	}

	var entry toolcall.ToolEntry
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

	if err := s.toolRegistry.Register(&entry); err != nil {
		writeJSON(w, http.StatusConflict, errorResponse{
			Error:            "tool_exists",
			ErrorDescription: err.Error(),
		})
		return
	}

	slog.Info("toolcall: tool registered", "tool_id", entry.ToolID, "protocols", entry.Protocols)
	writeJSON(w, http.StatusCreated, entry)
}

// handleToolGet handles GET /v1/tools/{tool_id} — get a single tool's details.
func (s *Server) handleToolGet(w http.ResponseWriter, r *http.Request) {
	if !s.toolRegistryReady(w) {
		return
	}

	toolID := r.PathValue("tool_id")
	entry, ok := s.toolRegistry.Get(toolID)
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{
			Error:            "tool_not_found",
			ErrorDescription: "tool " + toolID + " is not registered",
		})
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

// handleToolDeregister handles DELETE /v1/tools/{tool_id} — remove a tool.
func (s *Server) handleToolDeregister(w http.ResponseWriter, r *http.Request) {
	if !s.devMode && !s.requireBearerAuth(w, r) {
		return
	}
	if !s.toolRegistryReady(w) {
		return
	}

	toolID := r.PathValue("tool_id")
	if err := s.toolRegistry.Deregister(toolID); err != nil {
		writeJSON(w, http.StatusNotFound, errorResponse{
			Error:            "tool_not_found",
			ErrorDescription: err.Error(),
		})
		return
	}

	slog.Info("toolcall: tool deregistered", "tool_id", toolID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deregistered", "tool_id": toolID})
}

// handleToolAudit handles GET /v1/tools/{tool_id}/audit — returns cross-protocol
// audit trail for a tool. Currently returns an empty trail; audit persistence is
// wired via the Auditor in a future ticket.
func (s *Server) handleToolAudit(w http.ResponseWriter, r *http.Request) {
	if !s.toolRegistryReady(w) {
		return
	}

	toolID := r.PathValue("tool_id")
	if _, ok := s.toolRegistry.Get(toolID); !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{
			Error:            "tool_not_found",
			ErrorDescription: "tool " + toolID + " is not registered",
		})
		return
	}

	// Audit persistence is delivered in a subsequent ticket.
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tool_id": toolID,
		"events":  []interface{}{},
		"count":   0,
	})
}
