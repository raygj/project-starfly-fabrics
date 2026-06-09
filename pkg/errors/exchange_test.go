package errors

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestExchangeError_Error_FullFields(t *testing.T) {
	e := &ExchangeError{
		Code:       ErrPolicyDenied,
		Subject:    "wimse://payments.prod/ns/batch/sa/nightly-job",
		Credential: "k8s-sa (issued 2026-03-07T09:00:00Z)",
		Rule:       "allow_cross_namespace",
		RuleFile:   "policies/exchange.rego:42",
		Reason:     "cross-namespace access denied by policy",
		Action:     "add an exception in the exchange policy",
		DocsURL:    "https://starfly.dev/troubleshoot/policy-denied",
	}

	got := e.Error()

	// First line
	if !strings.HasPrefix(got, "exchange denied: cross-namespace access denied by policy") {
		t.Errorf("unexpected first line:\n%s", got)
	}

	// All fields present
	for _, want := range []string{
		"subject:",
		"wimse://payments.prod/ns/batch/sa/nightly-job",
		"credential:",
		"k8s-sa (issued 2026-03-07T09:00:00Z)",
		"rule:",
		"allow_cross_namespace",
		"rule_file:",
		"policies/exchange.rego:42",
		"action:",
		"add an exception in the exchange policy",
		"docs:",
		"https://starfly.dev/troubleshoot/policy-denied",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}

	// Should be multi-line
	lines := strings.Split(got, "\n")
	if len(lines) < 7 {
		t.Errorf("expected at least 7 lines, got %d:\n%s", len(lines), got)
	}
}

func TestExchangeError_Error_MinimalFields(t *testing.T) {
	e := &ExchangeError{
		Code:   ErrInternalError,
		Reason: "unexpected nil pointer",
	}

	got := e.Error()
	lines := strings.Split(got, "\n")

	// First line + docs line only (auto-generated docs URL)
	if len(lines) != 2 {
		t.Errorf("expected 2 lines for minimal error, got %d:\n%s", len(lines), got)
	}

	if !strings.HasPrefix(lines[0], "exchange denied: unexpected nil pointer") {
		t.Errorf("unexpected first line: %s", lines[0])
	}
}

func TestExchangeError_Error_SkipsEmptyFields(t *testing.T) {
	e := &ExchangeError{
		Code:    ErrCredentialExpired,
		Subject: "wimse://test/sa/foo",
		Reason:  "source credential expired",
		Action:  "regenerate the token",
	}

	got := e.Error()

	if strings.Contains(got, "rule:") {
		t.Errorf("output should not contain rule: when Rule is empty:\n%s", got)
	}
	if strings.Contains(got, "rule_file:") {
		t.Errorf("output should not contain rule_file: when RuleFile is empty:\n%s", got)
	}
	if strings.Contains(got, "credential:") {
		t.Errorf("output should not contain credential: when Credential is empty:\n%s", got)
	}
}

func TestExchangeError_JSON_Valid(t *testing.T) {
	e := &ExchangeError{
		Code:       ErrCredentialExpired,
		Subject:    "wimse://payments.prod/ns/batch/sa/nightly-job",
		Credential: "k8s-sa (issued 2026-03-07T09:00:00Z)",
		Reason:     "source credential expired",
		Action:     "regenerate the ServiceAccount token",
	}

	data, err := e.JSON()
	if err != nil {
		t.Fatalf("JSON() returned error: %v", err)
	}

	// Must be valid JSON
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("JSON() produced invalid JSON: %v\n%s", err, data)
	}

	// Check key fields
	if raw["code"] != string(ErrCredentialExpired) {
		t.Errorf("code = %v, want %s", raw["code"], ErrCredentialExpired)
	}
	if raw["reason"] != "source credential expired" {
		t.Errorf("reason = %v, want 'source credential expired'", raw["reason"])
	}
	if raw["docs_url"] == nil || raw["docs_url"] == "" {
		t.Error("docs_url should be auto-generated")
	}
}

func TestExchangeError_JSON_Roundtrip(t *testing.T) {
	original := &ExchangeError{
		Code:       ErrPolicyDenied,
		Subject:    "wimse://test/sa/foo",
		Credential: "oidc-token",
		Rule:       "deny_external",
		RuleFile:   "policy.rego:10",
		Reason:     "external access denied",
		Action:     "update policy",
		DocsURL:    "https://starfly.dev/troubleshoot/policy-denied",
	}

	data, err := original.JSON()
	if err != nil {
		t.Fatalf("JSON() error: %v", err)
	}

	var roundtripped ExchangeError
	if err := json.Unmarshal(data, &roundtripped); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if roundtripped.Code != original.Code {
		t.Errorf("Code = %s, want %s", roundtripped.Code, original.Code)
	}
	if roundtripped.Subject != original.Subject {
		t.Errorf("Subject = %s, want %s", roundtripped.Subject, original.Subject)
	}
	if roundtripped.Credential != original.Credential {
		t.Errorf("Credential = %s, want %s", roundtripped.Credential, original.Credential)
	}
	if roundtripped.Rule != original.Rule {
		t.Errorf("Rule = %s, want %s", roundtripped.Rule, original.Rule)
	}
	if roundtripped.RuleFile != original.RuleFile {
		t.Errorf("RuleFile = %s, want %s", roundtripped.RuleFile, original.RuleFile)
	}
	if roundtripped.Reason != original.Reason {
		t.Errorf("Reason = %s, want %s", roundtripped.Reason, original.Reason)
	}
	if roundtripped.Action != original.Action {
		t.Errorf("Action = %s, want %s", roundtripped.Action, original.Action)
	}
	if roundtripped.DocsURL != original.DocsURL {
		t.Errorf("DocsURL = %s, want %s", roundtripped.DocsURL, original.DocsURL)
	}
}

func TestExchangeError_Is_MatchesCode(t *testing.T) {
	e1 := &ExchangeError{Code: ErrCredentialExpired, Reason: "expired"}
	e2 := &ExchangeError{Code: ErrCredentialExpired, Reason: "different reason"}

	if !errors.Is(e1, e2) {
		t.Error("errors.Is should match errors with the same Code")
	}
}

func TestExchangeError_Is_DifferentCode(t *testing.T) {
	e1 := &ExchangeError{Code: ErrCredentialExpired}
	e2 := &ExchangeError{Code: ErrPolicyDenied}

	if errors.Is(e1, e2) {
		t.Error("errors.Is should not match errors with different Codes")
	}
}

func TestNewCredentialExpired_Defaults(t *testing.T) {
	e := NewCredentialExpired(
		"wimse://test/sa/foo",
		"k8s-sa (issued 2026-03-07T09:00:00Z, expired 2026-03-07T09:10:00Z)",
		"regenerate the ServiceAccount token and retry",
	)

	if e.Code != ErrCredentialExpired {
		t.Errorf("Code = %s, want %s", e.Code, ErrCredentialExpired)
	}
	if e.Reason == "" {
		t.Error("Reason should be auto-filled")
	}
	if e.Subject != "wimse://test/sa/foo" {
		t.Errorf("Subject = %s, want wimse://test/sa/foo", e.Subject)
	}

	docsURL := e.docsURL()
	want := DocsBase + string(ErrCredentialExpired)
	if docsURL != want {
		t.Errorf("docsURL = %s, want %s", docsURL, want)
	}
}

func TestNewPolicyDenied_IncludesRule(t *testing.T) {
	e := NewPolicyDenied(
		"wimse://test/sa/foo",
		"allow_cross_namespace",
		"policies/exchange.rego:42",
		"cross-namespace access denied",
		"update exchange policy",
	)

	if e.Code != ErrPolicyDenied {
		t.Errorf("Code = %s, want %s", e.Code, ErrPolicyDenied)
	}
	if e.Rule != "allow_cross_namespace" {
		t.Errorf("Rule = %s, want allow_cross_namespace", e.Rule)
	}
	if e.RuleFile != "policies/exchange.rego:42" {
		t.Errorf("RuleFile = %s, want policies/exchange.rego:42", e.RuleFile)
	}
}

func TestNewRevoked_Defaults(t *testing.T) {
	e := NewRevoked("wimse://test/sa/foo", "credential revoked via SSF event")

	if e.Code != ErrRevoked {
		t.Errorf("Code = %s, want %s", e.Code, ErrRevoked)
	}
	if e.Reason != "credential revoked via SSF event" {
		t.Errorf("Reason = %s", e.Reason)
	}
	if e.Action == "" {
		t.Error("Action should be auto-filled")
	}
}

func TestNewBlastRadiusExceeded_Defaults(t *testing.T) {
	e := NewBlastRadiusExceeded(
		"wimse://test/sa/foo",
		"cluster-admin",
		"reduce the requested scope or update blast radius policy",
	)

	if e.Code != ErrBlastRadiusExceeded {
		t.Errorf("Code = %s, want %s", e.Code, ErrBlastRadiusExceeded)
	}
	if !strings.Contains(e.Reason, "cluster-admin") {
		t.Errorf("Reason should mention the scope, got: %s", e.Reason)
	}
}

func TestNewDelegationDepthExceeded_IncludesDepths(t *testing.T) {
	e := NewDelegationDepthExceeded("wimse://test/sa/foo", 5, 3)

	if e.Code != ErrDelegationDepthExceeded {
		t.Errorf("Code = %s, want %s", e.Code, ErrDelegationDepthExceeded)
	}
	if !strings.Contains(e.Reason, "5") || !strings.Contains(e.Reason, "3") {
		t.Errorf("Reason should include depth (5) and maxDepth (3), got: %s", e.Reason)
	}
	if !strings.Contains(e.Action, "3") {
		t.Errorf("Action should reference maxDepth, got: %s", e.Action)
	}
}

func TestNewUntrustedDomain_IncludesDomain(t *testing.T) {
	e := NewUntrustedDomain("wimse://test/sa/foo", "evil.example.com")

	if e.Code != ErrUntrustedDomain {
		t.Errorf("Code = %s, want %s", e.Code, ErrUntrustedDomain)
	}
	if !strings.Contains(e.Reason, "evil.example.com") {
		t.Errorf("Reason should mention the domain, got: %s", e.Reason)
	}
	if !strings.Contains(e.Action, "evil.example.com") {
		t.Errorf("Action should mention the domain, got: %s", e.Action)
	}
}

func TestDocsURL_AutoGenerated(t *testing.T) {
	e := &ExchangeError{
		Code:   ErrCredentialExpired,
		Reason: "expired",
	}

	got := e.Error()
	want := DocsBase + string(ErrCredentialExpired)
	if !strings.Contains(got, want) {
		t.Errorf("auto-generated docs URL not found in output:\n%s\nwant: %s", got, want)
	}
}

func TestZeroValue_NoPanic(t *testing.T) {
	var e ExchangeError
	// Should not panic
	got := e.Error()
	if got == "" {
		t.Error("zero-value Error() should produce non-empty output")
	}
}
