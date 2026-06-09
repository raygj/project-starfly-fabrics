package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/signals"
)

const maxSignalBodyBytes = 1 << 20 // 1 MB

// SignalReceiver is the interface the handler depends on.
type SignalReceiver interface {
	ReceiveEvent(ctx context.Context, event *core.SecurityEvent) error
	// ReceiveSET validates a raw signed JWT (SET) before processing.
	// Required in non-dev mode (HARDEN-002).
	ReceiveSET(ctx context.Context, rawSET []byte) error
}

// SignalTransmitter is the interface for stream management.
type SignalTransmitter interface {
	CreateStream(ctx context.Context, cfg *core.StreamConfig) (*core.Stream, error)
	DeleteStream(ctx context.Context, streamID string) error
	GetStreamStatus(ctx context.Context, streamID string) (*core.StreamStatus, error)
}

func (s *Server) handleSignalEvent(w http.ResponseWriter, r *http.Request) {
	if s.signalReceiver == nil {
		writeJSON(w, http.StatusNotImplemented, errorResponse{
			Error:            "not_implemented",
			ErrorDescription: "signal receiver not configured",
		})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxSignalBodyBytes)

	// HARDEN-002: in non-dev mode require a signed SET (application/secevent+jwt).
	// Dev mode continues to accept raw JSON for local testing.
	if !s.devMode {
		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "application/secevent+jwt") {
			writeJSON(w, http.StatusUnsupportedMediaType, errorResponse{
				Error:            "invalid_request",
				ErrorDescription: "Content-Type must be application/secevent+jwt",
			})
			return
		}
		rawSET, err := io.ReadAll(r.Body)
		if err != nil {
			if err.Error() == "http: request body too large" {
				writeJSON(w, http.StatusRequestEntityTooLarge, errorResponse{
					Error:            "invalid_request",
					ErrorDescription: "request body too large",
				})
				return
			}
			writeJSON(w, http.StatusBadRequest, errorResponse{
				Error:            "invalid_request",
				ErrorDescription: "invalid request parameters",
			})
			return
		}
		if err := s.signalReceiver.ReceiveSET(r.Context(), rawSET); err != nil {
			switch {
			case errors.Is(err, signals.ErrDuplicateJTI):
				writeJSON(w, http.StatusConflict, errorResponse{Error: "invalid_request", ErrorDescription: "duplicate event"})
			case errors.Is(err, signals.ErrInvalidSET), errors.Is(err, signals.ErrUnknownIssuer):
				writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request", ErrorDescription: "invalid request parameters"})
			case errors.Is(err, signals.ErrSignalDenied):
				writeJSON(w, http.StatusForbidden, errorResponse{Error: "access_denied", ErrorDescription: "exchange not permitted"})
			default:
				writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "server_error", ErrorDescription: "internal error"})
			}
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
		return
	}

	// Dev mode: accept raw JSON SecurityEvent.
	var event core.SecurityEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		if err.Error() == "http: request body too large" {
			writeJSON(w, http.StatusRequestEntityTooLarge, errorResponse{
				Error:            "invalid_request",
				ErrorDescription: "request body too large",
			})
			return
		}
		writeJSON(w, http.StatusBadRequest, errorResponse{
			Error:            "invalid_request",
			ErrorDescription: "malformed request body",
		})
		return
	}

	if err := s.signalReceiver.ReceiveEvent(r.Context(), &event); err != nil {
		switch {
		case errors.Is(err, signals.ErrDuplicateJTI):
			writeJSON(w, http.StatusConflict, errorResponse{
				Error:            "invalid_request",
				ErrorDescription: "duplicate event",
			})
		case errors.Is(err, signals.ErrInvalidSET):
			writeJSON(w, http.StatusBadRequest, errorResponse{
				Error:            "invalid_request",
				ErrorDescription: "invalid request parameters",
			})
		case errors.Is(err, signals.ErrSignalDenied):
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

	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (s *Server) handleSSFConfiguration(w http.ResponseWriter, r *http.Request) {
	cfg := core.SSFConfiguration{
		Issuer:                    "starfly",
		JWKsURI:                  schemeHost(r) + "/v1/identity/jwks",
		DeliveryMethodsSupported: []string{"https://schemas.openid.net/secevent/risc/delivery-method/push"},
		ConfigurationEndpoint:    schemeHost(r) + "/v1/signals/stream",
		StatusEndpoint:           schemeHost(r) + "/v1/signals/status",
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleStreamConfig(w http.ResponseWriter, r *http.Request) {
	if s.signalTransmitter == nil {
		writeJSON(w, http.StatusNotImplemented, errorResponse{
			Error:            "not_implemented",
			ErrorDescription: "signal transmitter not configured",
		})
		return
	}

	switch r.Method {
	case http.MethodPost:
		var cfg core.StreamConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{
				Error:            "invalid_request",
				ErrorDescription: "malformed request body",
			})
			return
		}
		stream, err := s.signalTransmitter.CreateStream(r.Context(), &cfg)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResponse{
				Error:            "server_error",
				ErrorDescription: err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusCreated, stream)

	case http.MethodDelete:
		streamID := r.URL.Query().Get("stream_id")
		if streamID == "" {
			writeJSON(w, http.StatusBadRequest, errorResponse{
				Error:            "invalid_request",
				ErrorDescription: "stream_id query parameter required",
			})
			return
		}
		if err := s.signalTransmitter.DeleteStream(r.Context(), streamID); err != nil {
			writeJSON(w, http.StatusNotFound, errorResponse{
				Error:            "not_found",
				ErrorDescription: err.Error(),
			})
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{
			Error: "method_not_allowed",
		})
	}
}

func (s *Server) handleStreamStatus(w http.ResponseWriter, r *http.Request) {
	if s.signalTransmitter == nil {
		writeJSON(w, http.StatusNotImplemented, errorResponse{
			Error:            "not_implemented",
			ErrorDescription: "signal transmitter not configured",
		})
		return
	}

	streamID := r.URL.Query().Get("stream_id")
	if streamID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{
			Error:            "invalid_request",
			ErrorDescription: "stream_id query parameter required",
		})
		return
	}

	status, err := s.signalTransmitter.GetStreamStatus(r.Context(), streamID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errorResponse{
			Error:            "not_found",
			ErrorDescription: err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, status)
}

func schemeHost(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}
