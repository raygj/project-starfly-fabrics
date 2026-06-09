package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/signals"
)

// ── Mock signal receiver ─────────────────────────────────────────────

type mockSignalReceiver struct {
	err error
}

func (m *mockSignalReceiver) ReceiveEvent(_ context.Context, _ *core.SecurityEvent) error {
	return m.err
}

func (m *mockSignalReceiver) ReceiveSET(_ context.Context, _ []byte) error {
	return m.err
}

// ── Mock signal transmitter ──────────────────────────────────────────

type mockSignalTransmitter struct {
	createStream func(ctx context.Context, cfg *core.StreamConfig) (*core.Stream, error)
	deleteStream func(ctx context.Context, streamID string) error
	getStatus    func(ctx context.Context, streamID string) (*core.StreamStatus, error)
}

func (m *mockSignalTransmitter) CreateStream(ctx context.Context, cfg *core.StreamConfig) (*core.Stream, error) {
	return m.createStream(ctx, cfg)
}

func (m *mockSignalTransmitter) DeleteStream(ctx context.Context, streamID string) error {
	return m.deleteStream(ctx, streamID)
}

func (m *mockSignalTransmitter) GetStreamStatus(ctx context.Context, streamID string) (*core.StreamStatus, error) {
	return m.getStatus(ctx, streamID)
}

// ── Signal event handler tests ───────────────────────────────────────

func TestHandleSignalEvent(t *testing.T) {
	validEvent := core.SecurityEvent{
		Issuer:   "starfly",
		JTI:      "test-jti-1",
		Audience: "test-aud",
		Events: map[string]map[string]interface{}{
			"https://schemas.openid.net/secevent/caep/event-type/session-revoked": {},
		},
	}

	tests := []struct {
		name       string
		receiver   SignalReceiver
		body       interface{}
		wantStatus int
		wantError  string
	}{
		{
			name:       "receiver not configured returns 501",
			receiver:   nil,
			body:       validEvent,
			wantStatus: http.StatusNotImplemented,
			wantError:  "not_implemented",
		},
		{
			name:       "valid event returns 202",
			receiver:   &mockSignalReceiver{},
			body:       validEvent,
			wantStatus: http.StatusAccepted,
		},
		{
			name:       "malformed JSON returns 400",
			receiver:   &mockSignalReceiver{},
			body:       "not json",
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request",
		},
		{
			name:       "invalid SET returns 400",
			receiver:   &mockSignalReceiver{err: fmt.Errorf("%w: no events", signals.ErrInvalidSET)},
			body:       validEvent,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request",
		},
		{
			name:       "policy denial returns 403",
			receiver:   &mockSignalReceiver{err: fmt.Errorf("%w: blocked", signals.ErrSignalDenied)},
			body:       validEvent,
			wantStatus: http.StatusForbidden,
			wantError:  "access_denied",
		},
		{
			name:       "internal error returns 500",
			receiver:   &mockSignalReceiver{err: fmt.Errorf("database timeout")},
			body:       validEvent,
			wantStatus: http.StatusInternalServerError,
			wantError:  "server_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{signalReceiver: tt.receiver, devMode: true} // JSON path requires dev mode

			var body []byte
			switch v := tt.body.(type) {
			case string:
				body = []byte(v)
			default:
				body, _ = json.Marshal(v)
			}

			req := httptest.NewRequest(http.MethodPost, "/v1/signals/events", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			s.handleSignalEvent(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			if tt.wantError != "" {
				var resp errorResponse
				if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
					t.Fatalf("decoding response: %v", err)
				}
				if resp.Error != tt.wantError {
					t.Errorf("error = %q, want %q", resp.Error, tt.wantError)
				}
			}
		})
	}
}

// ── HARDEN-002: signed SET required in non-dev mode ──────────────────

func TestHandleSignalEvent_ProdMode_RequiresSignedSET(t *testing.T) {
	rx := &mockSignalReceiver{}
	s := &Server{signalReceiver: rx, devMode: false}

	t.Run("missing Content-Type returns 415", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"jti": "x"})
		req := httptest.NewRequest(http.MethodPost, "/v1/signals/events", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.handleSignalEvent(rec, req)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("status = %d, want 415", rec.Code)
		}
	})

	t.Run("application/secevent+jwt accepted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/signals/events", bytes.NewReader([]byte("fake.jwt.token")))
		req.Header.Set("Content-Type", "application/secevent+jwt")
		rec := httptest.NewRecorder()
		s.handleSignalEvent(rec, req)
		// mockSignalReceiver.ReceiveSET returns nil → 202
		if rec.Code != http.StatusAccepted {
			t.Errorf("status = %d, want 202", rec.Code)
		}
	})
}

// ── SSF configuration endpoint tests ─────────────────────────────────

func TestHandleSSFConfiguration(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/.well-known/ssf-configuration", nil)
	req.Host = "starfly.example.com"
	rec := httptest.NewRecorder()

	s.handleSSFConfiguration(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var cfg core.SSFConfiguration
	if err := json.NewDecoder(rec.Body).Decode(&cfg); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	if cfg.Issuer != "starfly" {
		t.Errorf("issuer = %q, want %q", cfg.Issuer, "starfly")
	}
	if cfg.JWKsURI != "http://starfly.example.com/v1/identity/jwks" {
		t.Errorf("jwks_uri = %q, want http://starfly.example.com/v1/identity/jwks", cfg.JWKsURI)
	}
	if len(cfg.DeliveryMethodsSupported) != 1 {
		t.Errorf("delivery methods = %d, want 1", len(cfg.DeliveryMethodsSupported))
	}
	if cfg.ConfigurationEndpoint == "" {
		t.Error("configuration_endpoint is empty")
	}
	if cfg.StatusEndpoint == "" {
		t.Error("status_endpoint is empty")
	}
}

// ── Stream management handler tests ──────────────────────────────────

func TestHandleStreamConfig(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		tx          SignalTransmitter
		body        interface{}
		query       string
		wantStatus  int
		wantError   string
	}{
		{
			name:       "transmitter not configured returns 501",
			method:     http.MethodPost,
			tx:         nil,
			body:       core.StreamConfig{Audience: "test"},
			wantStatus: http.StatusNotImplemented,
			wantError:  "not_implemented",
		},
		{
			name:   "create stream returns 201",
			method: http.MethodPost,
			tx: &mockSignalTransmitter{
				createStream: func(_ context.Context, _ *core.StreamConfig) (*core.Stream, error) {
					return &core.Stream{ID: "stream-1", Issuer: "starfly", Status: "enabled"}, nil
				},
			},
			body:       core.StreamConfig{Audience: "test-aud", DeliveryMethod: "push"},
			wantStatus: http.StatusCreated,
		},
		{
			name:   "create stream malformed body returns 400",
			method: http.MethodPost,
			tx: &mockSignalTransmitter{
				createStream: func(_ context.Context, _ *core.StreamConfig) (*core.Stream, error) {
					return nil, nil
				},
			},
			body:       "broken",
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request",
		},
		{
			name:   "create stream server error returns 500",
			method: http.MethodPost,
			tx: &mockSignalTransmitter{
				createStream: func(_ context.Context, _ *core.StreamConfig) (*core.Stream, error) {
					return nil, fmt.Errorf("audience required")
				},
			},
			body:       core.StreamConfig{},
			wantStatus: http.StatusInternalServerError,
			wantError:  "server_error",
		},
		{
			name:   "delete stream returns 204",
			method: http.MethodDelete,
			tx: &mockSignalTransmitter{
				deleteStream: func(_ context.Context, _ string) error { return nil },
			},
			query:      "stream_id=stream-1",
			wantStatus: http.StatusNoContent,
		},
		{
			name:   "delete stream missing id returns 400",
			method: http.MethodDelete,
			tx: &mockSignalTransmitter{
				deleteStream: func(_ context.Context, _ string) error { return nil },
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request",
		},
		{
			name:   "delete stream not found returns 404",
			method: http.MethodDelete,
			tx: &mockSignalTransmitter{
				deleteStream: func(_ context.Context, _ string) error {
					return fmt.Errorf("stream not found: xyz")
				},
			},
			query:      "stream_id=xyz",
			wantStatus: http.StatusNotFound,
			wantError:  "not_found",
		},
		{
			name:   "unsupported method returns 405",
			method: http.MethodPatch,
			tx: &mockSignalTransmitter{
				createStream: func(_ context.Context, _ *core.StreamConfig) (*core.Stream, error) {
					return nil, nil
				},
			},
			wantStatus: http.StatusMethodNotAllowed,
			wantError:  "method_not_allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{signalTransmitter: tt.tx}

			var body []byte
			switch v := tt.body.(type) {
			case string:
				body = []byte(v)
			default:
				if tt.body != nil {
					body, _ = json.Marshal(v)
				}
			}

			target := "/v1/signals/stream"
			if tt.query != "" {
				target += "?" + tt.query
			}

			req := httptest.NewRequest(tt.method, target, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			s.handleStreamConfig(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			if tt.wantError != "" {
				var resp errorResponse
				if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
					t.Fatalf("decoding response: %v", err)
				}
				if resp.Error != tt.wantError {
					t.Errorf("error = %q, want %q", resp.Error, tt.wantError)
				}
			}
		})
	}
}

// ── Stream status handler tests ──────────────────────────────────────

func TestHandleStreamStatus(t *testing.T) {
	tests := []struct {
		name       string
		tx         SignalTransmitter
		query      string
		wantStatus int
		wantError  string
	}{
		{
			name:       "transmitter not configured returns 501",
			tx:         nil,
			query:      "stream_id=s1",
			wantStatus: http.StatusNotImplemented,
			wantError:  "not_implemented",
		},
		{
			name:       "missing stream_id returns 400",
			tx:         &mockSignalTransmitter{},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request",
		},
		{
			name: "stream found returns 200",
			tx: &mockSignalTransmitter{
				getStatus: func(_ context.Context, id string) (*core.StreamStatus, error) {
					return &core.StreamStatus{StreamID: id, Status: "enabled"}, nil
				},
			},
			query:      "stream_id=s1",
			wantStatus: http.StatusOK,
		},
		{
			name: "stream not found returns 404",
			tx: &mockSignalTransmitter{
				getStatus: func(_ context.Context, _ string) (*core.StreamStatus, error) {
					return nil, fmt.Errorf("stream not found: xyz")
				},
			},
			query:      "stream_id=xyz",
			wantStatus: http.StatusNotFound,
			wantError:  "not_found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{signalTransmitter: tt.tx}

			target := "/v1/signals/status"
			if tt.query != "" {
				target += "?" + tt.query
			}

			req := httptest.NewRequest(http.MethodGet, target, nil)
			rec := httptest.NewRecorder()

			s.handleStreamStatus(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			if tt.wantError != "" {
				var resp errorResponse
				if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
					t.Fatalf("decoding response: %v", err)
				}
				if resp.Error != tt.wantError {
					t.Errorf("error = %q, want %q", resp.Error, tt.wantError)
				}
			}
		})
	}
}
