package metrics

import (
	"strings"
	"testing"
)

func TestToolCallMiddlewareMetrics_Nil(t *testing.T) {
	var m *Metrics
	if m.ToolCallMiddlewareMetrics() != nil {
		t.Error("nil Metrics should return nil MiddlewareMetrics")
	}
}

func TestToolCallMiddlewareMetrics_Wired(t *testing.T) {
	m := New("test", "unit-1", "spiffe://example.com")
	mm := m.ToolCallMiddlewareMetrics()
	if mm == nil {
		t.Fatal("ToolCallMiddlewareMetrics() returned nil")
	}
	if mm.RecordCall == nil {
		t.Error("RecordCall hook not wired")
	}
	if mm.ObserveDuration == nil {
		t.Error("ObserveDuration hook not wired")
	}
	if mm.IncTie == nil {
		t.Error("IncTie hook not wired")
	}

	// Exercise each hook — should not panic.
	mm.RecordCall("mcp", "allowed")
	mm.RecordCall("http", "denied")
	mm.ObserveDuration("mcp", 0.002)
	mm.IncTie()

	// Verify counters appear in Prometheus output.
	body := scrape(t, m)
	if !strings.Contains(body, `tool_call_total{`) {
		t.Error("tool_call_total not in metrics output")
	}
	if !strings.Contains(body, `tool_call_duration_seconds`) {
		t.Error("tool_call_duration_seconds not in metrics output")
	}
	if !strings.Contains(body, `tool_call_protocol_ties_total`) {
		t.Error("tool_call_protocol_ties_total not in metrics output")
	}
}
