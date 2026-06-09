package httpgeneric

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/starfly-fabrics/starfly/pkg/toolcall"
)

func TestExtractFromHTTP_MappedPath(t *testing.T) {
	a := New(
		ToolIDMapping{PathPrefix: "/api/analytics", ToolID: "analytics-tool"},
		ToolIDMapping{PathPrefix: "/api/orders", ToolID: "orders-tool"},
	)
	r := httptest.NewRequest(http.MethodGet, "/api/analytics/summary", nil)
	r.Header.Set("Authorization", "Bearer tok-123")

	result, err := a.ExtractFromHTTP(r)
	if err != nil {
		t.Fatal(err)
	}
	if result.Confidence != toolcall.MatchDefinitive {
		t.Errorf("confidence: got %d, want %d", result.Confidence, toolcall.MatchDefinitive)
	}
	if result.Request.ToolID != "analytics-tool" {
		t.Errorf("ToolID: %q", result.Request.ToolID)
	}
	if result.Request.Token != "tok-123" {
		t.Errorf("Token: %q", result.Request.Token)
	}
	if result.Request.Protocol != toolcall.ProtocolHTTP {
		t.Errorf("Protocol: %q", result.Request.Protocol)
	}
}

func TestExtractFromHTTP_NoMapping(t *testing.T) {
	a := New() // no mappings
	r := httptest.NewRequest(http.MethodPost, "/some/path", nil)
	r.Header.Set("Authorization", "Bearer tok")

	result, err := a.ExtractFromHTTP(r)
	if err != nil {
		t.Fatal(err)
	}
	// No mapping = MatchLikely fallback.
	if result.Confidence != toolcall.MatchLikely {
		t.Errorf("confidence: got %d, want %d", result.Confidence, toolcall.MatchLikely)
	}
	if result.Request.ToolID != "" {
		t.Errorf("ToolID should be empty without mapping, got %q", result.Request.ToolID)
	}
}

func TestExtractFromHTTP_NoToken(t *testing.T) {
	a := New(ToolIDMapping{PathPrefix: "/api", ToolID: "api-tool"})
	r := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	// No Authorization header.
	result, err := a.ExtractFromHTTP(r)
	if err != nil {
		t.Fatal(err)
	}
	if result.Confidence != toolcall.MatchNone {
		t.Errorf("no token should return MatchNone, got %d", result.Confidence)
	}
}

func TestExtractFromHTTP_LongestPrefixWins(t *testing.T) {
	a := New(
		ToolIDMapping{PathPrefix: "/api", ToolID: "api-tool"},
		ToolIDMapping{PathPrefix: "/api/orders", ToolID: "orders-tool"},
	)
	r := httptest.NewRequest(http.MethodPost, "/api/orders/123", nil)
	r.Header.Set("Authorization", "Bearer tok")

	result, _ := a.ExtractFromHTTP(r)
	if result.Request.ToolID != "orders-tool" {
		t.Errorf("longest prefix should win, got %q", result.Request.ToolID)
	}
}

func TestExtractFromHTTP_GRPCContentType(t *testing.T) {
	a := New(ToolIDMapping{PathPrefix: "/grpc", ToolID: "grpc-tool"})
	r := httptest.NewRequest(http.MethodPost, "/grpc/service/method", nil)
	r.Header.Set("Authorization", "Bearer tok")
	r.Header.Set("Content-Type", "application/grpc")

	result, _ := a.ExtractFromHTTP(r)
	if result.Request.TransportMeta.Custom == nil {
		t.Error("gRPC metadata should be set")
	}
	if _, ok := result.Request.TransportMeta.Custom["grpc"]; !ok {
		t.Error("grpc flag should be in Custom metadata")
	}
}

func TestExtractFromMessage_AlwaysNone(t *testing.T) {
	a := New()
	result, err := a.ExtractFromMessage([]byte(`anything`))
	if err != nil {
		t.Fatal(err)
	}
	if result.Confidence != toolcall.MatchNone {
		t.Errorf("HTTP adapter should never match messages, got %d", result.Confidence)
	}
}

func TestOperationFromRequest(t *testing.T) {
	tests := []struct {
		method, path string
		want         string
	}{
		{"GET", "/api/orders", "get:orders"},
		{"POST", "/api/ship", "post:ship"},
		{"DELETE", "/api/resource/123", "delete:123"},
		{"GET", "/", "get"},
	}
	for _, tc := range tests {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		got := operationFromRequest(r)
		if got != tc.want {
			t.Errorf("operationFromRequest(%q %q) = %q, want %q", tc.method, tc.path, got, tc.want)
		}
	}
}

func TestFormatError(t *testing.T) {
	a := New()
	w := httptest.NewRecorder()
	a.FormatError(w, "access_denied", "insufficient capabilities", http.StatusForbidden)
	if w.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", w.Code)
	}
}
