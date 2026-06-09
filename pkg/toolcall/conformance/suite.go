// Package conformance provides a reusable test suite that any toolcall.Adapter
// implementation must pass.
//
// Usage — in your adapter's test file:
//
//	func TestConformance(t *testing.T) {
//	    conformance.Run(t, conformance.Config{
//	        NewAdapter: func() toolcall.Adapter { return mcp.New() },
//	        Protocol:   toolcall.ProtocolMCP,
//	        ValidHTTPRequest: func(t *testing.T) *http.Request {
//	            r := httptest.NewRequest("POST", "/", body)
//	            r.Header.Set("Authorization", "Bearer tok")
//	            return r
//	        },
//	        ValidMessagePayload: func() []byte {
//	            return []byte(`{...valid message...}`)
//	        },
//	    })
//	}
//
// To produce a machine-readable JSON report alongside the test run:
//
//	func TestConformance(t *testing.T) {
//	    report := conformance.RunReport(cfg)
//	    if path := os.Getenv("CONFORMANCE_REPORT_PATH"); path != "" {
//	        if err := conformance.WriteReport(report, path); err != nil {
//	            t.Logf("warning: could not write conformance report: %v", err)
//	        }
//	    }
//	    report.Assert(t) // fail the test if any check failed
//	}
package conformance

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/toolcall"
)

// Config parameterizes the conformance suite for a specific adapter.
type Config struct {
	// NewAdapter constructs a fresh adapter for each test case.
	NewAdapter func() toolcall.Adapter

	// Protocol is the expected return value of Adapter.Protocol().
	Protocol toolcall.Protocol

	// ValidHTTPRequest returns an HTTP request that the adapter should accept
	// with at least MatchPossible confidence. Must include Authorization header.
	ValidHTTPRequest func() *http.Request

	// InvalidHTTPRequest returns an HTTP request the adapter should reject
	// (MatchNone). Defaults to a plain GET with no headers.
	InvalidHTTPRequest func() *http.Request

	// ValidMessagePayload returns a raw message the adapter should accept
	// via ExtractFromMessage with at least MatchPossible confidence.
	// May be nil if the adapter always returns MatchNone for messages.
	ValidMessagePayload func() []byte

	// ExpectMessageSupport, when true, asserts that ExtractFromMessage returns
	// at least MatchPossible on ValidMessagePayload.
	ExpectMessageSupport bool
}

// ── JSON report types ─────────────────────────────────────────────────────────

// CheckResult records the outcome of a single conformance check.
type CheckResult struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Skipped bool   `json:"skipped"`
	Detail  string `json:"detail,omitempty"`
}

// ConformanceReport is the machine-readable output of RunReport. It can be
// written to disk for CI gating via WriteReport.
type ConformanceReport struct {
	AdapterProtocol string        `json:"adapter_protocol"`
	Timestamp       string        `json:"timestamp"`
	Total           int           `json:"total"`
	Passed          int           `json:"passed"`
	Failed          int           `json:"failed"`
	Skipped         int           `json:"skipped"`
	Results         []CheckResult `json:"results"`
}

// Assert fails t for every check that did not pass and was not skipped.
func (r *ConformanceReport) Assert(t *testing.T) {
	t.Helper()
	for _, c := range r.Results {
		if !c.Passed && !c.Skipped {
			t.Errorf("conformance check FAILED: %s — %s", c.Name, c.Detail)
		}
	}
}

// WriteReport serialises report as indented JSON and writes it to path.
func WriteReport(report *ConformanceReport, path string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling report: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// ── Internal check abstraction ────────────────────────────────────────────────

// tb is the minimal testing interface the check functions need. Both
// *testing.T and *checkRecorder satisfy it.
type tb interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	Skip(args ...any)
}

type check struct {
	name string
	run  func(tb tb, cfg Config)
}

func allChecks() []check {
	return []check{
		{
			"Protocol/returns_non_empty",
			func(tb tb, cfg Config) {
				tb.Helper()
				a := cfg.NewAdapter()
				if a.Protocol() == "" {
					tb.Errorf("Protocol() must return a non-empty Protocol value")
				}
			},
		},
		{
			"Protocol/matches_expected",
			func(tb tb, cfg Config) {
				tb.Helper()
				if cfg.Protocol == "" {
					tb.Skip("Protocol not specified in Config")
					return
				}
				a := cfg.NewAdapter()
				got := a.Protocol()
				name, _ := toolcall.ParseProtocol(cfg.Protocol)
				gotName, _ := toolcall.ParseProtocol(got)
				if gotName != name {
					tb.Errorf("Protocol() name: got %q, want prefix %q", got, cfg.Protocol)
				}
			},
		},
		{
			"ExtractFromHTTP/returns_non_nil",
			func(tb tb, cfg Config) {
				tb.Helper()
				if cfg.ValidHTTPRequest == nil {
					tb.Skip("ValidHTTPRequest not provided")
					return
				}
				a := cfg.NewAdapter()
				r := cfg.ValidHTTPRequest()
				result, err := a.ExtractFromHTTP(r)
				if err != nil {
					tb.Fatalf("ExtractFromHTTP returned error: %v", err)
					return
				}
				if result == nil {
					tb.Fatalf("ExtractFromHTTP must not return nil MatchResult")
				}
			},
		},
		{
			"ExtractFromHTTP/valid_request_above_none",
			func(tb tb, cfg Config) {
				tb.Helper()
				if cfg.ValidHTTPRequest == nil {
					tb.Skip("ValidHTTPRequest not provided")
					return
				}
				a := cfg.NewAdapter()
				r := cfg.ValidHTTPRequest()
				result, _ := a.ExtractFromHTTP(r)
				if result.Confidence <= toolcall.MatchNone {
					tb.Errorf("valid HTTP request should return confidence > MatchNone, got %d", result.Confidence)
				}
			},
		},
		{
			"ExtractFromHTTP/valid_request_has_request_struct",
			func(tb tb, cfg Config) {
				tb.Helper()
				if cfg.ValidHTTPRequest == nil {
					tb.Skip("ValidHTTPRequest not provided")
					return
				}
				a := cfg.NewAdapter()
				r := cfg.ValidHTTPRequest()
				result, _ := a.ExtractFromHTTP(r)
				if result.Confidence > toolcall.MatchNone && result.Request == nil {
					tb.Errorf("MatchResult.Request must not be nil when Confidence > MatchNone")
				}
			},
		},
		{
			"ExtractFromHTTP/valid_request_sets_protocol",
			func(tb tb, cfg Config) {
				tb.Helper()
				if cfg.ValidHTTPRequest == nil {
					tb.Skip("ValidHTTPRequest not provided")
					return
				}
				a := cfg.NewAdapter()
				r := cfg.ValidHTTPRequest()
				result, _ := a.ExtractFromHTTP(r)
				if result.Confidence > toolcall.MatchNone && result.Request != nil {
					if result.Request.Protocol == "" {
						tb.Errorf("ToolCallRequest.Protocol must be set when Confidence > MatchNone")
					}
				}
			},
		},
		{
			"ExtractFromHTTP/valid_request_has_transport_meta",
			func(tb tb, cfg Config) {
				tb.Helper()
				if cfg.ValidHTTPRequest == nil {
					tb.Skip("ValidHTTPRequest not provided")
					return
				}
				a := cfg.NewAdapter()
				r := cfg.ValidHTTPRequest()
				result, _ := a.ExtractFromHTTP(r)
				if result.Confidence > toolcall.MatchNone && result.Request != nil {
					if result.Request.TransportMeta == nil {
						tb.Errorf("ToolCallRequest.TransportMeta must not be nil for HTTP requests")
					}
				}
			},
		},
		{
			"ExtractFromHTTP/invalid_request_returns_none",
			func(tb tb, cfg Config) {
				tb.Helper()
				a := cfg.NewAdapter()
				var r *http.Request
				if cfg.InvalidHTTPRequest != nil {
					r = cfg.InvalidHTTPRequest()
				} else {
					r = httptest.NewRequest(http.MethodGet, "/", nil)
				}
				result, err := a.ExtractFromHTTP(r)
				if err != nil {
					tb.Fatalf("ExtractFromHTTP returned error on invalid request: %v", err)
					return
				}
				if result == nil {
					tb.Fatalf("ExtractFromHTTP must not return nil MatchResult (even for invalid)")
					return
				}
				if result.Confidence != toolcall.MatchNone {
					tb.Errorf("invalid request should return MatchNone, got %d", result.Confidence)
				}
			},
		},
		{
			"ExtractFromHTTP/idempotent_on_same_request",
			func(tb tb, cfg Config) {
				tb.Helper()
				if cfg.ValidHTTPRequest == nil {
					tb.Skip("ValidHTTPRequest not provided")
					return
				}
				a := cfg.NewAdapter()
				r := cfg.ValidHTTPRequest()
				r1, err1 := a.ExtractFromHTTP(r)
				r2, err2 := a.ExtractFromHTTP(r)
				if err1 != nil || err2 != nil {
					tb.Fatalf("second ExtractFromHTTP call errored: %v / %v", err1, err2)
					return
				}
				if r1.Confidence != r2.Confidence {
					tb.Errorf("ExtractFromHTTP not idempotent: first=%d second=%d", r1.Confidence, r2.Confidence)
				}
			},
		},
		{
			"ExtractFromMessage/returns_non_nil",
			func(tb tb, cfg Config) {
				tb.Helper()
				a := cfg.NewAdapter()
				result, err := a.ExtractFromMessage([]byte(`{}`))
				if err != nil {
					tb.Fatalf("ExtractFromMessage returned error: %v", err)
					return
				}
				if result == nil {
					tb.Fatalf("ExtractFromMessage must not return nil MatchResult")
				}
			},
		},
		{
			"ExtractFromMessage/invalid_json_returns_none",
			func(tb tb, cfg Config) {
				tb.Helper()
				a := cfg.NewAdapter()
				result, _ := a.ExtractFromMessage([]byte(`not json`))
				if result == nil {
					tb.Fatalf("result must not be nil")
					return
				}
				if result.Confidence != toolcall.MatchNone {
					tb.Errorf("invalid JSON should return MatchNone, got %d", result.Confidence)
				}
			},
		},
		{
			"ExtractFromMessage/empty_input_returns_none",
			func(tb tb, cfg Config) {
				tb.Helper()
				a := cfg.NewAdapter()
				result, _ := a.ExtractFromMessage(nil)
				if result == nil {
					tb.Fatalf("result must not be nil")
					return
				}
				if result.Confidence != toolcall.MatchNone {
					tb.Errorf("nil input should return MatchNone, got %d", result.Confidence)
				}
			},
		},
		{
			"ExtractFromMessage/valid_payload_above_none",
			func(tb tb, cfg Config) {
				tb.Helper()
				if !cfg.ExpectMessageSupport {
					tb.Skip("ExpectMessageSupport=false")
					return
				}
				if cfg.ValidMessagePayload == nil {
					tb.Fatalf("ExpectMessageSupport=true but ValidMessagePayload not provided")
					return
				}
				a := cfg.NewAdapter()
				result, _ := a.ExtractFromMessage(cfg.ValidMessagePayload())
				if result.Confidence <= toolcall.MatchNone {
					tb.Errorf("valid message should return confidence > MatchNone, got %d", result.Confidence)
				}
				if result.Request == nil {
					tb.Errorf("MatchResult.Request must not be nil when Confidence > MatchNone")
				}
			},
		},
		{
			"FormatError/writes_status_code",
			func(tb tb, cfg Config) {
				tb.Helper()
				a := cfg.NewAdapter()
				w := httptest.NewRecorder()
				a.FormatError(w, "test_error", "test description", http.StatusForbidden)
				if w.Code != http.StatusForbidden {
					tb.Errorf("FormatError status: got %d, want 403", w.Code)
				}
			},
		},
		{
			"FormatError/writes_non_empty_body",
			func(tb tb, cfg Config) {
				tb.Helper()
				a := cfg.NewAdapter()
				w := httptest.NewRecorder()
				a.FormatError(w, "test_error", "description", http.StatusUnauthorized)
				if w.Body.Len() == 0 {
					tb.Errorf("FormatError must write a non-empty response body")
				}
			},
		},
		{
			"FormatError/sets_content_type",
			func(tb tb, cfg Config) {
				tb.Helper()
				a := cfg.NewAdapter()
				w := httptest.NewRecorder()
				a.FormatError(w, "err", "desc", http.StatusForbidden)
				ct := w.Header().Get("Content-Type")
				if ct == "" {
					tb.Errorf("FormatError must set Content-Type header")
				}
			},
		},
	}
}

// ── Public API ────────────────────────────────────────────────────────────────

// Run executes the standard adapter conformance suite using Go's testing
// framework. Each check runs as a subtest via t.Run.
func Run(t *testing.T, cfg Config) {
	t.Helper()
	for _, c := range allChecks() {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Helper()
			c.run(&testingTAdapter{t: t}, cfg)
		})
	}
}

// RunReport executes the conformance suite without *testing.T and returns a
// structured report. Useful for generating machine-readable JSON in CI.
// Call report.Assert(t) inside a test to propagate failures.
func RunReport(cfg Config) *ConformanceReport {
	checks := allChecks()
	report := &ConformanceReport{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Results:   make([]CheckResult, 0, len(checks)),
	}

	// Determine adapter protocol for the report header.
	if cfg.NewAdapter != nil {
		a := cfg.NewAdapter()
		report.AdapterProtocol = string(a.Protocol())
	}

	for _, c := range checks {
		rec := &checkRecorder{name: c.name}
		c.run(rec, cfg)
		result := CheckResult{
			Name:    c.name,
			Passed:  !rec.failed && !rec.skipped,
			Skipped: rec.skipped,
			Detail:  rec.detail,
		}
		report.Results = append(report.Results, result)
		report.Total++
		switch {
		case rec.skipped:
			report.Skipped++
		case rec.failed:
			report.Failed++
		default:
			report.Passed++
		}
	}
	return report
}

// ── Internal: testingTAdapter wraps *testing.T to satisfy tb ─────────────────

type testingTAdapter struct{ t *testing.T }

func (a *testingTAdapter) Helper()                         { a.t.Helper() }
func (a *testingTAdapter) Errorf(f string, args ...any)    { a.t.Errorf(f, args...) }
func (a *testingTAdapter) Fatalf(f string, args ...any)    { a.t.Fatalf(f, args...) }
func (a *testingTAdapter) Skip(args ...any)                { a.t.Skip(args...) }

// ── Internal: checkRecorder records pass/fail/skip without testing.T ──────────

type checkRecorder struct {
	name    string
	failed  bool
	skipped bool
	detail  string
	stopped bool // set by Fatalf/Skip to prevent further check execution
}

func (r *checkRecorder) Helper() {}

func (r *checkRecorder) Errorf(format string, args ...any) {
	if r.stopped {
		return
	}
	r.failed = true
	if r.detail == "" {
		r.detail = fmt.Sprintf(format, args...)
	}
}

func (r *checkRecorder) Fatalf(format string, args ...any) {
	if r.stopped {
		return
	}
	r.failed = true
	r.stopped = true
	if r.detail == "" {
		r.detail = fmt.Sprintf(format, args...)
	}
}

func (r *checkRecorder) Skip(args ...any) {
	if r.stopped {
		return
	}
	r.skipped = true
	r.stopped = true
	if r.detail == "" && len(args) > 0 {
		r.detail = fmt.Sprint(args...)
	}
}
