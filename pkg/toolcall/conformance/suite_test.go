package conformance_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/starfly-fabrics/starfly/pkg/toolcall"
	a2aadapter "github.com/starfly-fabrics/starfly/pkg/toolcall/adapters/a2a"
	httpgeneric "github.com/starfly-fabrics/starfly/pkg/toolcall/adapters/httpgeneric"
	mcpadapter "github.com/starfly-fabrics/starfly/pkg/toolcall/adapters/mcp"
	"github.com/starfly-fabrics/starfly/pkg/toolcall/conformance"
)

// ── MCP adapter ───────────────────────────────────────────────────────────────

func TestConformance_MCP(t *testing.T) {
	conformance.Run(t, conformance.Config{
		NewAdapter: func() toolcall.Adapter { return mcpadapter.New() },
		Protocol:   toolcall.ProtocolMCP,
		ValidHTTPRequest: func() *http.Request {
			body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"my-tool","arguments":{}},"id":1}`
			r := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer tok")
			return r
		},
		InvalidHTTPRequest: func() *http.Request {
			return httptest.NewRequest(http.MethodGet, "/", nil)
		},
		ValidMessagePayload: func() []byte {
			return []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"stdio-tool","arguments":{}},"id":2}`)
		},
		ExpectMessageSupport: true,
	})
}

// ── HTTP Generic adapter ──────────────────────────────────────────────────────

func TestConformance_HTTPGeneric(t *testing.T) {
	conformance.Run(t, conformance.Config{
		NewAdapter: func() toolcall.Adapter {
			return httpgeneric.New(
				httpgeneric.ToolIDMapping{PathPrefix: "/api", ToolID: "api-tool"},
			)
		},
		Protocol: toolcall.ProtocolHTTP,
		ValidHTTPRequest: func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
			r.Header.Set("Authorization", "Bearer tok")
			return r
		},
		InvalidHTTPRequest: func() *http.Request {
			return httptest.NewRequest(http.MethodGet, "/api/resource", nil)
		},
		// HTTP adapter always returns MatchNone for raw messages.
		ExpectMessageSupport: false,
	})
}

// ── A2A adapter ───────────────────────────────────────────────────────────────

func TestConformance_A2A(t *testing.T) {
	const agentCard = `{"name":"test-agent","url":"https://agent.example.com","version":"1.0","capabilities":["search"]}`

	conformance.Run(t, conformance.Config{
		NewAdapter: func() toolcall.Adapter {
			return a2aadapter.New()
		},
		Protocol: toolcall.ProtocolA2A,
		ValidHTTPRequest: func() *http.Request {
			body := `{"jsonrpc":"2.0","method":"a2a/tasks/send","params":{"taskType":"search","agentCard":` + agentCard + `},"id":1}`
			r := httptest.NewRequest(http.MethodPost, "/a2a", bytes.NewBufferString(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer tok")
			return r
		},
		InvalidHTTPRequest: func() *http.Request {
			return httptest.NewRequest(http.MethodGet, "/a2a", nil)
		},
		ValidMessagePayload: func() []byte {
			return []byte(`{"jsonrpc":"2.0","method":"a2a/tasks/send","params":{"taskType":"search","agentCard":` + agentCard + `},"id":2}`)
		},
		ExpectMessageSupport: true,
	})
}

// ── RunReport / WriteReport ───────────────────────────────────────────────────

func mcpCfg() conformance.Config {
	return conformance.Config{
		NewAdapter: func() toolcall.Adapter { return mcpadapter.New() },
		Protocol:   toolcall.ProtocolMCP,
		ValidHTTPRequest: func() *http.Request {
			body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"my-tool","arguments":{}},"id":1}`
			r := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer tok")
			return r
		},
		InvalidHTTPRequest: func() *http.Request {
			return httptest.NewRequest(http.MethodGet, "/", nil)
		},
		ValidMessagePayload: func() []byte {
			return []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"t","arguments":{}},"id":1}`)
		},
		ExpectMessageSupport: true,
	}
}

func TestRunReport_MCP(t *testing.T) {
	report := conformance.RunReport(mcpCfg())
	if report == nil {
		t.Fatal("RunReport returned nil")
	}
	if report.Total == 0 {
		t.Error("report has no checks")
	}
	if report.Failed > 0 {
		for _, r := range report.Results {
			if !r.Passed && !r.Skipped {
				t.Errorf("check failed: %s — %s", r.Name, r.Detail)
			}
		}
	}
	if report.AdapterProtocol == "" {
		t.Error("AdapterProtocol not set in report")
	}
	report.Assert(t)
}

func TestWriteReport(t *testing.T) {
	report := conformance.RunReport(mcpCfg())
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := conformance.WriteReport(report, path); err != nil {
		t.Fatalf("WriteReport: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if _, ok := decoded["results"]; !ok {
		t.Error("report JSON missing 'results' key")
	}
}
