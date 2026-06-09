package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/exchange"
)

// errorResponse is the RFC 8693 error body returned on exchange failures.
type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

const maxExchangeBodyBytes = 1 << 20 // 1 MB

// handleExchangeToken performs an RFC 8693 token exchange via the exchange engine.
func (s *Server) handleExchangeToken(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	r.Body = http.MaxBytesReader(w, r.Body, maxExchangeBodyBytes)
	var req core.TokenExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.metrics.ExchangeRequestsTotal.WithLabelValues("error", "unknown", "").Inc()
		if err.Error() == "http: request body too large" {
			writeJSON(w, http.StatusRequestEntityTooLarge, errorResponse{
				Error:            "invalid_request",
				ErrorDescription: "request body too large",
			})
			return
		}
		writeJSON(w, http.StatusBadRequest, errorResponse{
			Error:            "invalid_request",
			ErrorDescription: "malformed JSON body",
		})
		return
	}

	// Extract X-Starfly-Attestation header (ADR-0013).
	if attestHeader := r.Header.Get(exchange.AttestationHeaderName); attestHeader != "" {
		att, err := exchange.ParseAttestationHeader(attestHeader)
		if err != nil {
			s.metrics.ExchangeRequestsTotal.WithLabelValues("error", req.SubjectTokenType, req.Audience).Inc()
			writeJSON(w, http.StatusBadRequest, errorResponse{
				Error:            "invalid_request",
				ErrorDescription: err.Error(),
			})
			return
		}
		req.Attestation = att
	}

	resp, err := s.exchanger.Exchange(r.Context(), &req)

	duration := time.Since(start).Seconds()
	s.metrics.ExchangeDurationSeconds.WithLabelValues().Observe(duration)

	if resp != nil && resp.DelegationDepth > 0 {
		depth := strconv.Itoa(resp.DelegationDepth)
		s.metrics.DelegationActive.WithLabelValues(depth).Inc()
		s.metrics.DelegationDepthMax.Set(float64(resp.DelegationDepth))
	}

	if err != nil {
		status := "error"
		if errors.Is(err, exchange.ErrPolicyDenied) || errors.Is(err, exchange.ErrSubjectRevoked) {
			status = "denied"
		}
		s.metrics.ExchangeRequestsTotal.WithLabelValues(status, req.SubjectTokenType, req.Audience).Inc()

		switch {
		case errors.Is(err, exchange.ErrInvalidGrantType):
			writeJSON(w, http.StatusBadRequest, errorResponse{
				Error:            "unsupported_grant_type",
				ErrorDescription: err.Error(),
			})
		case errors.Is(err, exchange.ErrUnsupportedToken), errors.Is(err, exchange.ErrInvalidSubject):
			writeJSON(w, http.StatusBadRequest, errorResponse{
				Error:            "invalid_request",
				ErrorDescription: err.Error(),
			})
		case errors.Is(err, exchange.ErrWorkloadValidation), errors.Is(err, exchange.ErrActorTokenInvalid):
			writeJSON(w, http.StatusUnauthorized, errorResponse{
				Error:            "invalid_client",
				ErrorDescription: "subject token validation failed",
			})
		case errors.Is(err, exchange.ErrDelegationDenied):
			s.metrics.BlastRadiusDenialsTotal.WithLabelValues("denied").Inc()
			writeJSON(w, http.StatusForbidden, errorResponse{
				Error:            "access_denied",
				ErrorDescription: "exchange not permitted",
			})
		case errors.Is(err, exchange.ErrNonceReplay):
			writeJSON(w, http.StatusBadRequest, errorResponse{
				Error:            "invalid_request",
				ErrorDescription: "invalid request parameters",
			})
		case errors.Is(err, exchange.ErrStaleAttestation):
			writeJSON(w, http.StatusBadRequest, errorResponse{
				Error:            "invalid_request",
				ErrorDescription: "invalid request parameters",
			})
		case errors.Is(err, exchange.ErrPolicyDenied), errors.Is(err, exchange.ErrSubjectRevoked):
			writeJSON(w, http.StatusForbidden, errorResponse{
				Error:            "access_denied",
				ErrorDescription: "exchange not permitted",
			})
		default:
			writeJSON(w, http.StatusInternalServerError, errorResponse{
				Error:            "server_error",
				ErrorDescription: "internal error",
			})
		}
		return
	}

	s.metrics.ExchangeRequestsTotal.WithLabelValues("success", req.SubjectTokenType, req.Audience).Inc()
	writeJSON(w, http.StatusOK, resp)
}
