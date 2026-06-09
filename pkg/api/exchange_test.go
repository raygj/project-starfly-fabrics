package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/exchange"
)

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// mockExchanger implements core.TokenExchanger for handler tests.
type mockExchanger struct {
	resp *core.TokenExchangeResponse
	err  error
}

func (m *mockExchanger) Exchange(_ context.Context, _ *core.TokenExchangeRequest) (*core.TokenExchangeResponse, error) {
	return m.resp, m.err
}

func newTestServerWithExchanger(ex core.TokenExchanger) *Server {
	cfg := &core.Config{
		ListenAddr: ":0",
		RateLimit:  core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10},
	}
	return New(cfg, "test-version", ex)
}

func TestHandleExchangeToken(t *testing.T) {
	validBody := `{
		"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":"eyJhbGciOi...",
		"subject_token_type":"urn:ietf:params:oauth:token-type:jwt",
		"audience":"spiffe://target.example.com",
		"scope":"read:data"
	}`

	tests := []struct {
		name           string
		body           string
		exchanger      *mockExchanger
		wantStatus     int
		wantError      string
		wantOpaqueDesc string // exact description expected (non-empty = check it)
		wantNotInDesc  string // string that must NOT appear in error_description
	}{
		{
			name: "valid exchange",
			body: validBody,
			exchanger: &mockExchanger{
				resp: &core.TokenExchangeResponse{
					AccessToken:     "signed.jwt.token",
					IssuedTokenType: "urn:ietf:params:oauth:token-type:jwt",
					TokenType:       "Bearer",
					ExpiresIn:       300,
					Scope:           "read:data",
				},
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "malformed JSON body",
			body:       `{not json`,
			exchanger:  &mockExchanger{},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request",
		},
		{
			name: "invalid grant type",
			body: validBody,
			exchanger: &mockExchanger{
				err: fmt.Errorf("%w: got \"bad\"", exchange.ErrInvalidGrantType),
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "unsupported_grant_type",
		},
		{
			name: "unsupported token type",
			body: validBody,
			exchanger: &mockExchanger{
				err: fmt.Errorf("%w: \"saml\"", exchange.ErrUnsupportedToken),
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request",
		},
		{
			name: "policy denied",
			body: validBody,
			exchanger: &mockExchanger{
				err: fmt.Errorf("%w: untrusted target", exchange.ErrPolicyDenied),
			},
			wantStatus: http.StatusForbidden,
			wantError:  "access_denied",
		},
		{
			name: "internal error",
			body: validBody,
			exchanger: &mockExchanger{
				err: errors.New("something broke"),
			},
			wantStatus: http.StatusInternalServerError,
			wantError:  "server_error",
		},
		// HARDEN-001: security denial → 4xx with opaque bodies
		{
			name: "workload validation failed → 401",
			body: validBody,
			exchanger: &mockExchanger{
				err: fmt.Errorf("%w: unknown issuer: https://attacker.example.com", exchange.ErrWorkloadValidation),
			},
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_client",
		},
		{
			name: "actor token invalid → 401",
			body: validBody,
			exchanger: &mockExchanger{
				err: fmt.Errorf("%w: bad sig", exchange.ErrActorTokenInvalid),
			},
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_client",
		},
		{
			name: "delegation denied → 403",
			body: validBody,
			exchanger: &mockExchanger{
				err: fmt.Errorf("%w: depth exhausted", exchange.ErrDelegationDenied),
			},
			wantStatus: http.StatusForbidden,
			wantError:  "access_denied",
		},
		{
			name: "nonce replay → 400",
			body: validBody,
			exchanger: &mockExchanger{
				err: fmt.Errorf("%w: abc123", exchange.ErrNonceReplay),
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request",
		},
		{
			name: "stale attestation → 400",
			body: validBody,
			exchanger: &mockExchanger{
				err: fmt.Errorf("%w: age 90s", exchange.ErrStaleAttestation),
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request",
		},
		// HARDEN-001: opaque bodies — internal details must not leak
		{
			name: "workload validation error body is opaque",
			body: validBody,
			exchanger: &mockExchanger{
				err: fmt.Errorf("%w: unknown issuer: https://attacker.example.com", exchange.ErrWorkloadValidation),
			},
			wantStatus:      http.StatusUnauthorized,
			wantError:       "invalid_client",
			wantOpaqueDesc:  "subject token validation failed",
			wantNotInDesc:   "attacker.example.com",
		},
		{
			name: "nonce replay body is opaque",
			body: validBody,
			exchanger: &mockExchanger{
				err: fmt.Errorf("%w: secret-nonce-value-abc123", exchange.ErrNonceReplay),
			},
			wantStatus:     http.StatusBadRequest,
			wantError:      "invalid_request",
			wantOpaqueDesc: "invalid request parameters",
			wantNotInDesc:  "secret-nonce-value-abc123",
		},
		// HARDEN-004: oversized body → 413
		{
			name:       "body exceeds 1MB limit → 413",
			body:       `{"subject_token":"` + strings.Repeat("a", maxExchangeBodyBytes) + `"}`,
			exchanger:  &mockExchanger{},
			wantStatus: http.StatusRequestEntityTooLarge,
			wantError:  "invalid_request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServerWithExchanger(tt.exchanger)

			req := httptest.NewRequest(http.MethodPost, "/v1/exchange/token",
				bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			s.httpServer.Handler.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tt.wantStatus)
			}

			// Verify X-Request-ID is always present.
			if w.Header().Get("X-Request-ID") == "" {
				t.Error("X-Request-ID header should be present")
			}

			if tt.wantError != "" {
				var errResp errorResponse
				if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
					t.Fatalf("decoding error response: %v", err)
				}
				if errResp.Error != tt.wantError {
					t.Errorf("error = %q, want %q", errResp.Error, tt.wantError)
				}
				if tt.wantOpaqueDesc != "" && errResp.ErrorDescription != tt.wantOpaqueDesc {
					t.Errorf("error_description = %q, want opaque %q", errResp.ErrorDescription, tt.wantOpaqueDesc)
				}
				if tt.wantNotInDesc != "" && contains(errResp.ErrorDescription, tt.wantNotInDesc) {
					t.Errorf("error_description leaks internal detail %q: got %q", tt.wantNotInDesc, errResp.ErrorDescription)
				}
			}

			if tt.wantStatus == http.StatusOK {
				var resp core.TokenExchangeResponse
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("decoding success response: %v", err)
				}
				if resp.AccessToken != "signed.jwt.token" {
					t.Errorf("access_token = %q, want %q", resp.AccessToken, "signed.jwt.token")
				}
				if resp.TokenType != "Bearer" {
					t.Errorf("token_type = %q, want %q", resp.TokenType, "Bearer")
				}
				if resp.ExpiresIn != 300 {
					t.Errorf("expires_in = %d, want 300", resp.ExpiresIn)
				}
			}
		})
	}
}

func TestExchangeRequestIDPresent(t *testing.T) {
	s := newTestServerWithExchanger(&mockExchanger{
		resp: &core.TokenExchangeResponse{
			AccessToken:     "tok",
			IssuedTokenType: "urn:ietf:params:oauth:token-type:jwt",
			TokenType:       "Bearer",
			ExpiresIn:       300,
		},
	})

	body := `{"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","subject_token":"x","subject_token_type":"urn:ietf:params:oauth:token-type:jwt","audience":"a"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/exchange/token",
		bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	s.httpServer.Handler.ServeHTTP(w, req)

	reqID := w.Header().Get("X-Request-ID")
	if reqID == "" {
		t.Error("X-Request-ID header should be present")
	}
	if len(reqID) != 36 {
		t.Errorf("X-Request-ID length = %d, want 36 (UUID v4)", len(reqID))
	}
}
