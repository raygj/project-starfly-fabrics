package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMetrics_Handler(t *testing.T) {
	m := NewMetrics()
	handler := m.Handler()
	if handler == nil {
		t.Fatal("Handler() returned nil")
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Error("expected non-empty metrics response")
	}
}
