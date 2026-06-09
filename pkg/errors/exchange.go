// Package errors provides structured error types for the Starfly exchange engine.
// Each error carries enough context for an operator to diagnose and fix the
// problem from the error message alone.
package errors

import (
	"encoding/json"
	"fmt"
	"strings"
)

// DocsBase is the base URL for troubleshooting documentation.
// Override this in tests or custom deployments.
var DocsBase = "https://starfly.dev/troubleshoot/"

// ErrorCode is a machine-readable error classification.
type ErrorCode string

const (
	ErrCredentialExpired       ErrorCode = "credential_expired"
	ErrCredentialInvalid       ErrorCode = "credential_invalid"
	ErrPolicyDenied            ErrorCode = "policy_denied"
	ErrRevoked                 ErrorCode = "revoked"
	ErrBadAudience             ErrorCode = "bad_audience"
	ErrBlastRadiusExceeded     ErrorCode = "blast_radius_exceeded"
	ErrDelegationDepthExceeded ErrorCode = "delegation_depth_exceeded"
	ErrUntrustedDomain         ErrorCode = "untrusted_domain"
	ErrActorTokenMalformed     ErrorCode = "actor_token_malformed"
	ErrActorTokenExpired       ErrorCode = "actor_token_expired"
	ErrInternalError           ErrorCode = "internal_error"
)

// ExchangeError is a structured error returned by the exchange engine.
// It provides enough context for an operator to diagnose and fix the
// problem from the error message alone.
type ExchangeError struct {
	Code       ErrorCode `json:"code"`                  // machine-readable code
	Subject    string    `json:"subject,omitempty"`      // wimse:// URI of the requester
	Credential string    `json:"credential,omitempty"`   // source credential type and metadata
	Rule       string    `json:"rule,omitempty"`         // OPA rule name (if policy denial)
	RuleFile   string    `json:"rule_file,omitempty"`    // file:line of the rule (if policy denial)
	Reason     string    `json:"reason"`                 // human-readable explanation
	Action     string    `json:"action,omitempty"`       // what the operator should do to fix it
	DocsURL    string    `json:"docs_url,omitempty"`     // link to troubleshooting docs
}

// Error implements the error interface with multi-line formatted output.
//
// Format:
//
//	exchange denied: {Reason}
//	  subject:      wimse://...
//	  credential:   k8s-sa (...)
//	  rule:         allow_cross_namespace
//	  rule_file:    policies/exchange.rego:42
//	  action:       regenerate the ServiceAccount token and retry
//	  docs:         https://starfly.dev/troubleshoot/credential-expired
//
// Lines with empty values are omitted.
func (e *ExchangeError) Error() string {
	reason := e.Reason
	if reason == "" {
		reason = string(e.Code)
	}

	var b strings.Builder

	if strings.HasPrefix(reason, "exchange denied") {
		b.WriteString(reason)
	} else {
		b.WriteString("exchange denied: ")
		b.WriteString(reason)
	}

	type field struct {
		key string
		val string
	}

	docsURL := e.docsURL()

	fields := []field{
		{"subject", e.Subject},
		{"credential", e.Credential},
		{"rule", e.Rule},
		{"rule_file", e.RuleFile},
		{"action", e.Action},
		{"docs", docsURL},
	}

	for _, f := range fields {
		if f.val == "" {
			continue
		}
		b.WriteByte('\n')
		// Left-pad key to 12 chars, indented with 2 spaces
		fmt.Fprintf(&b, "  %-12s%s", f.key+":", f.val)
	}

	return b.String()
}

// docsURL returns the documentation URL, auto-generating from DocsBase + Code
// if DocsURL is not explicitly set.
func (e *ExchangeError) docsURL() string {
	if e.DocsURL != "" {
		return e.DocsURL
	}
	if e.Code != "" {
		return DocsBase + string(e.Code)
	}
	return ""
}

// JSON returns the JSON representation of the error for API responses.
func (e *ExchangeError) JSON() ([]byte, error) {
	// Use the auto-generated docs URL in JSON output too.
	type alias ExchangeError
	out := struct {
		*alias
		DocsURL string `json:"docs_url,omitempty"`
	}{
		alias:   (*alias)(e),
		DocsURL: e.docsURL(),
	}
	return json.Marshal(out)
}

// Is allows errors.Is() matching by ErrorCode. Two ExchangeErrors match
// if they share the same Code.
func (e *ExchangeError) Is(target error) bool {
	t, ok := target.(*ExchangeError)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

// Unwrap returns nil; ExchangeError is a leaf error.
func (e *ExchangeError) Unwrap() error {
	return nil
}

// --- Convenience constructors ---

// NewCredentialExpired creates an error for an expired source credential.
func NewCredentialExpired(subject, credential, action string) *ExchangeError {
	return &ExchangeError{
		Code:       ErrCredentialExpired,
		Subject:    subject,
		Credential: credential,
		Reason:     "source credential expired",
		Action:     action,
	}
}

// NewPolicyDenied creates an error for an OPA policy denial.
func NewPolicyDenied(subject, rule, ruleFile, reason, action string) *ExchangeError {
	return &ExchangeError{
		Code:     ErrPolicyDenied,
		Subject:  subject,
		Rule:     rule,
		RuleFile: ruleFile,
		Reason:   reason,
		Action:   action,
	}
}

// NewRevoked creates an error for a revoked credential.
func NewRevoked(subject, reason string) *ExchangeError {
	return &ExchangeError{
		Code:    ErrRevoked,
		Subject: subject,
		Reason:  reason,
		Action:  "check the revocation list and re-issue the credential if appropriate",
	}
}

// NewUntrustedDomain creates an error for an untrusted domain.
func NewUntrustedDomain(subject, domain string) *ExchangeError {
	return &ExchangeError{
		Code:    ErrUntrustedDomain,
		Subject: subject,
		Reason:  fmt.Sprintf("domain %q is not in the trusted domain list", domain),
		Action:  fmt.Sprintf("add %q to the trusted domains configuration or verify the request origin", domain),
	}
}

// NewBlastRadiusExceeded creates an error when a request exceeds the
// configured blast radius scope.
func NewBlastRadiusExceeded(subject, scope, action string) *ExchangeError {
	return &ExchangeError{
		Code:    ErrBlastRadiusExceeded,
		Subject: subject,
		Reason:  fmt.Sprintf("requested scope %q exceeds the allowed blast radius", scope),
		Action:  action,
	}
}

// NewDelegationDepthExceeded creates an error when delegation chain depth
// exceeds the configured maximum.
func NewDelegationDepthExceeded(subject string, depth, maxDepth int) *ExchangeError {
	return &ExchangeError{
		Code:    ErrDelegationDepthExceeded,
		Subject: subject,
		Reason:  fmt.Sprintf("delegation depth %d exceeds maximum allowed depth %d", depth, maxDepth),
		Action:  fmt.Sprintf("reduce the delegation chain or increase max_delegation_depth (currently %d)", maxDepth),
	}
}
