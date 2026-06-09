package provider

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIClientJWTAuthorizationHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"tools":[],"count":0}`))
	}))
	t.Cleanup(srv.Close)

	client := newAPIClient(srv.URL, srv.Client(), "test-jwt-token")
	_, _, err := client.request(t.Context(), "GET", "/v1/mcp/tools", nil)
	if err != nil {
		t.Fatalf("request() error = %v", err)
	}
	if gotAuth != "Bearer test-jwt-token" {
		t.Fatalf("Authorization = %q, want Bearer test-jwt-token", gotAuth)
	}
}
