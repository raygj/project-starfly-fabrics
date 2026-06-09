package toolcall

import (
	"encoding/json"
	"testing"
	"time"
)

func TestParseProtocol(t *testing.T) {
	tests := []struct {
		in      Protocol
		name    string
		version string
	}{
		{"mcp", "mcp", ""},
		{"http", "http", ""},
		{"a2a", "a2a", ""},
		{"mcp/v2", "mcp", "v2"},
		{"a2a/2026-draft-01", "a2a", "2026-draft-01"},
		{"", "", ""},
	}
	for _, tc := range tests {
		name, ver := ParseProtocol(tc.in)
		if name != tc.name || ver != tc.version {
			t.Errorf("ParseProtocol(%q) = (%q, %q), want (%q, %q)",
				tc.in, name, ver, tc.name, tc.version)
		}
	}
}

func TestFormatProtocol(t *testing.T) {
	tests := []struct {
		name, version string
		want          Protocol
	}{
		{"mcp", "", "mcp"},
		{"a2a", "2026-draft-01", "a2a/2026-draft-01"},
		{"http", "v1", "http/v1"},
	}
	for _, tc := range tests {
		got := FormatProtocol(tc.name, tc.version)
		if got != tc.want {
			t.Errorf("FormatProtocol(%q, %q) = %q, want %q", tc.name, tc.version, got, tc.want)
		}
	}
}

func TestFormatParseRoundTrip(t *testing.T) {
	pairs := []struct{ name, ver string }{
		{"mcp", ""},
		{"a2a", "2026-draft-01"},
		{"http", "v2"},
	}
	for _, p := range pairs {
		got := FormatProtocol(p.name, p.ver)
		n, v := ParseProtocol(got)
		if n != p.name || v != p.ver {
			t.Errorf("round-trip (%q, %q): got (%q, %q)", p.name, p.ver, n, v)
		}
	}
}

func TestVerifiedIdentityJSONRoundTrip(t *testing.T) {
	orig := &VerifiedIdentity{
		Subject:      "spiffe://example.com/agent",
		Issuer:       "https://starfly.example.com",
		Capabilities: []string{"read", "write"},
		BlastRadius:  "namespace:dev",
		Protocol:     ProtocolMCP,
		ExpiresAt:    time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		ToolID:       "tool-123",
		Resource:     "mcp://tool-123",
		Delegation: &Delegation{
			OnBehalfOf: "spiffe://example.com/human",
			Depth:      1,
		},
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got VerifiedIdentity
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Subject != orig.Subject {
		t.Errorf("Subject: got %q, want %q", got.Subject, orig.Subject)
	}
	if got.Protocol != orig.Protocol {
		t.Errorf("Protocol: got %q, want %q", got.Protocol, orig.Protocol)
	}
	if got.BlastRadius != orig.BlastRadius {
		t.Errorf("BlastRadius: got %q, want %q", got.BlastRadius, orig.BlastRadius)
	}
	if len(got.Capabilities) != len(orig.Capabilities) {
		t.Errorf("Capabilities length: got %d, want %d", len(got.Capabilities), len(orig.Capabilities))
	}
	if got.Delegation == nil || got.Delegation.OnBehalfOf != orig.Delegation.OnBehalfOf {
		t.Errorf("Delegation mismatch")
	}
	if !got.ExpiresAt.Equal(orig.ExpiresAt) {
		t.Errorf("ExpiresAt: got %v, want %v", got.ExpiresAt, orig.ExpiresAt)
	}
}

func TestToolCallRequestSensitiveFieldsOmitted(t *testing.T) {
	req := &ToolCallRequest{
		Protocol: ProtocolMCP,
		ToolID:   "my-tool",
		Token:    "super-secret-jwt",
		Params:   map[string]interface{}{"key": "val"},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Token must not appear in JSON output (tagged json:"-").
	if string(data) == "" {
		t.Fatal("empty JSON")
	}
	var m map[string]interface{}
	_ = json.Unmarshal(data, &m)
	if _, ok := m["token"]; ok {
		t.Error("token field should be omitted from JSON output")
	}
}

func TestMatchConfidenceOrdering(t *testing.T) {
	if MatchNone >= MatchPossible {
		t.Error("MatchNone should be less than MatchPossible")
	}
	if MatchPossible >= MatchLikely {
		t.Error("MatchPossible should be less than MatchLikely")
	}
	if MatchLikely >= MatchDefinitive {
		t.Error("MatchLikely should be less than MatchDefinitive")
	}
}
