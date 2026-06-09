package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientAcquireToken(t *testing.T) {
	// Mock Starfly exchange endpoint.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/exchange/token" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Verify the request body includes resource parameter.
		var req tokenExchangeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.Resource == "" {
			t.Error("expected resource parameter (RFC 8707)")
		}
		if req.GrantType != "urn:ietf:params:oauth:grant-type:token-exchange" {
			t.Errorf("grant_type = %q", req.GrantType)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenExchangeResponse{
			AccessToken:     "test.access.token",
			IssuedTokenType: "urn:ietf:params:oauth:token-type:jwt",
			TokenType:       "Bearer",
			ExpiresIn:       300,
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "source-token", "urn:ietf:params:oauth:token-type:jwt")

	token, err := client.AcquireToken(context.Background(), "https://mcp.example.com/tools/search", []string{"read"})
	if err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if token != "test.access.token" {
		t.Fatalf("token = %q, want %q", token, "test.access.token")
	}
}

func TestClientAcquireToken_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server_error"}`))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "source-token", "urn:ietf:params:oauth:token-type:jwt")

	_, err := client.AcquireToken(context.Background(), "https://mcp.example.com/tools/search", nil)
	if err == nil {
		t.Fatal("expected error on 500 response")
	}
}

func TestClientCallTool(t *testing.T) {
	// Mock Starfly exchange.
	exchangeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenExchangeResponse{
			AccessToken: "scoped.jwt.token",
			ExpiresIn:   300,
		})
	}))
	defer exchangeSrv.Close()

	// Mock MCP tool server.
	toolSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the Starfly token is attached.
		auth := r.Header.Get("Authorization")
		if auth != "Bearer scoped.jwt.token" {
			t.Errorf("Authorization = %q, want Bearer scoped.jwt.token", auth)
		}
		// Verify tool ID header.
		toolID := r.Header.Get("X-MCP-Tool-ID")
		if toolID != "code-search" {
			t.Errorf("X-MCP-Tool-ID = %q", toolID)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": "found 42 matches",
		})
	}))
	defer toolSrv.Close()

	client := NewClient(exchangeSrv.URL, "source-token", "urn:ietf:params:oauth:token-type:jwt")

	resp, err := client.CallTool(context.Background(), &CallToolRequest{
		ToolID:       "code-search",
		ToolName:     "Code Search",
		ResourceURI:  "https://mcp.example.com/tools/code-search",
		Capabilities: []string{"query-read"},
		Params:       map[string]interface{}{"query": "security"},
		TargetURL:    toolSrv.URL,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if resp.Body["result"] != "found 42 matches" {
		t.Fatalf("body = %v", resp.Body)
	}
}
