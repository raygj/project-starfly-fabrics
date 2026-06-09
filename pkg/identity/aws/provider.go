package aws

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

const (
	tracerName    = "github.com/starfly-fabrics/starfly/pkg/identity/aws"
	credType      = "aws-sts"
	defaultSTSURL = "https://sts.amazonaws.com"
	maxRequestAge = 15 * time.Minute
)

var _ core.IdentityProvider = (*Provider)(nil)

// STSCredential is the JSON object a caller sends containing a presigned
// GetCallerIdentity request. Starfly re-executes the request against STS.
type STSCredential struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
}

// getCallerIdentityResponse is the XML envelope returned by STS.
type getCallerIdentityResponse struct {
	XMLName xml.Name                `xml:"GetCallerIdentityResponse"`
	Result  getCallerIdentityResult `xml:"GetCallerIdentityResult"`
}

// getCallerIdentityResult holds the account, ARN, and user ID.
type getCallerIdentityResult struct {
	Account string `xml:"Account"`
	Arn     string `xml:"Arn"`
	UserId  string `xml:"UserId"`
}

// Provider validates AWS caller identity by replaying presigned STS requests.
type Provider struct {
	trustDomains    map[string]core.TrustDomain // account ID -> trust domain
	allowedRoleARNs map[string]bool
	stsEndpoint     string // override for testing; default: real STS
	httpClient      *http.Client
	devMode         bool
}

// Option configures the Provider.
type Option func(*Provider)

// WithTrustDomains maps trust domains for AWS account lookups.
// The trust domain Name is used as the key for account ID matching.
func WithTrustDomains(domains []core.TrustDomain) Option {
	return func(p *Provider) {
		for _, d := range domains {
			if d.Enabled {
				p.trustDomains[d.Name] = d
			}
		}
	}
}

// WithAllowedRoles restricts which IAM role ARNs are accepted.
func WithAllowedRoles(arns []string) Option {
	return func(p *Provider) {
		for _, a := range arns {
			p.allowedRoleARNs[a] = true
		}
	}
}

// WithSTSEndpoint overrides the STS URL (useful for testing).
func WithSTSEndpoint(url string) Option {
	return func(p *Provider) { p.stsEndpoint = url }
}

// WithHTTPClient injects a custom HTTP client.
func WithHTTPClient(c *http.Client) Option {
	return func(p *Provider) { p.httpClient = c }
}

// WithDevMode enables development mode (skips real STS call).
func WithDevMode(dev bool) Option {
	return func(p *Provider) { p.devMode = dev }
}

// NewProvider creates a new AWS STS identity provider.
func NewProvider(opts ...Option) (*Provider, error) {
	p := &Provider{
		trustDomains:    make(map[string]core.TrustDomain),
		allowedRoleARNs: make(map[string]bool),
		stsEndpoint:     defaultSTSURL,
		httpClient:      core.NewDefaultHTTPClient(),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// ValidateWorkload validates an AWS presigned GetCallerIdentity credential.
func (p *Provider) ValidateWorkload(ctx context.Context, credential string, ct string) (*core.WorkloadIdentity, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "identity.aws.ValidateWorkload")
	defer span.End()

	// 1. Check credential type.
	if ct != credType {
		err := fmt.Errorf("unsupported credential type: %s", ct)
		telemetry.SpanError(span, err)
		return nil, err
	}

	// 2. Unmarshal credential JSON.
	var cred STSCredential
	if err := json.Unmarshal([]byte(credential), &cred); err != nil {
		err = fmt.Errorf("malformed AWS STS credential: %w", err)
		telemetry.SpanError(span, err)
		return nil, err
	}

	// 3. Validate method and URL.
	if cred.Method != "POST" {
		err := fmt.Errorf("invalid STS request method: %s (must be POST)", cred.Method)
		telemetry.SpanError(span, err)
		return nil, err
	}
	if !p.isAllowedSTSURL(cred.URL) {
		err := fmt.Errorf("invalid STS URL: %s", cred.URL)
		telemetry.SpanError(span, err)
		return nil, err
	}

	// 4. Dev mode: return synthetic identity.
	if p.devMode {
		return p.devIdentity(cred), nil
	}

	// 5. Prod mode: validate request freshness.
	if err := p.validateFreshness(cred); err != nil {
		telemetry.SpanError(span, err)
		return nil, err
	}

	// 6. Re-execute the presigned request against STS.
	result, err := p.callSTS(ctx, cred)
	if err != nil {
		telemetry.SpanError(span, err)
		return nil, err
	}

	span.SetAttributes(
		attribute.String("aws.account_id", result.Account),
		attribute.String("aws.arn", result.Arn),
	)

	// 7. Look up account in trust domains.
	domain, ok := p.trustDomains[result.Account]
	if !ok {
		err = fmt.Errorf("unknown AWS account: %s", result.Account)
		telemetry.SpanError(span, err)
		return nil, err
	}

	// 8. Check allowed role ARNs (if configured).
	if len(p.allowedRoleARNs) > 0 && !p.allowedRoleARNs[result.Arn] {
		err = fmt.Errorf("role ARN not allowed: %s", result.Arn)
		telemetry.SpanError(span, err)
		return nil, err
	}

	// 9. Build WIMSE identity.
	roleName := extractRoleName(result.Arn)
	wimseURI := fmt.Sprintf("wimse://%s/aws/%s", domain.Name, roleName)

	return &core.WorkloadIdentity{
		ID:          wimseURI,
		TrustDomain: domain.Name,
		Attestation: &core.AttestationEvidence{
			Method:    credType,
			Timestamp: time.Now().UTC(),
		},
		Claims: map[string]interface{}{
			"account_id": result.Account,
			"arn":        result.Arn,
			"role_name":  roleName,
			"user_id":    result.UserId,
		},
	}, nil
}

// isAllowedSTSURL checks whether the credential URL targets STS.
func (p *Provider) isAllowedSTSURL(u string) bool {
	if strings.Contains(u, "sts.amazonaws.com") {
		return true
	}
	// Allow the configured test endpoint.
	if p.stsEndpoint != defaultSTSURL && strings.HasPrefix(u, p.stsEndpoint) {
		return true
	}
	return false
}

// validateFreshness ensures the presigned request is not stale.
func (p *Provider) validateFreshness(cred STSCredential) error {
	dateStr, ok := cred.Headers["X-Amz-Date"]
	if !ok {
		// Try lowercase variant.
		dateStr, ok = cred.Headers["x-amz-date"]
	}
	if !ok {
		return fmt.Errorf("missing X-Amz-Date header in STS credential")
	}

	// AWS date format: 20060102T150405Z
	t, err := time.Parse("20060102T150405Z", dateStr)
	if err != nil {
		return fmt.Errorf("invalid X-Amz-Date format: %w", err)
	}
	if time.Since(t) > maxRequestAge {
		return fmt.Errorf("request too old: X-Amz-Date %s exceeds %v max age", dateStr, maxRequestAge)
	}
	return nil
}

// callSTS re-executes the presigned GetCallerIdentity request.
func (p *Provider) callSTS(ctx context.Context, cred STSCredential) (*getCallerIdentityResult, error) {
	// Build the HTTP request against our configured endpoint.
	targetURL := p.stsEndpoint
	req, err := http.NewRequestWithContext(ctx, cred.Method, targetURL, strings.NewReader(cred.Body))
	if err != nil {
		return nil, fmt.Errorf("building STS request: %w", err)
	}

	// Copy headers from the presigned credential, but NEVER log or propagate
	// the Authorization header or security tokens.
	for k, v := range cred.Headers {
		req.Header.Set(k, v)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("STS request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading STS response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("STS returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var stsResp getCallerIdentityResponse
	if err := xml.Unmarshal(body, &stsResp); err != nil {
		return nil, fmt.Errorf("parsing STS XML response: %w", err)
	}

	return &stsResp.Result, nil
}

// devIdentity returns a synthetic identity for development mode.
func (p *Provider) devIdentity(cred STSCredential) *core.WorkloadIdentity {
	roleName := "unknown-role"

	// Best-effort: try to extract something useful from the credential.
	if arn, ok := cred.Headers["X-Starfly-Dev-Arn"]; ok {
		roleName = extractRoleName(arn)
	}

	return &core.WorkloadIdentity{
		ID:          fmt.Sprintf("wimse://dev.local/aws/%s", roleName),
		TrustDomain: "dev.local",
		Attestation: &core.AttestationEvidence{
			Method:    credType,
			Timestamp: time.Now().UTC(),
		},
		Claims: map[string]interface{}{
			"dev_mode": true,
		},
	}
}

// extractRoleName extracts the role name from an AWS ARN.
//
// Supported formats:
//
//	arn:aws:sts::123456789012:assumed-role/MyRole/session-name -> MyRole
//	arn:aws:iam::123456789012:role/MyRole                      -> MyRole
//	arn:aws:iam::123456789012:user/MyUser                      -> MyUser
func extractRoleName(arn string) string {
	// ARN format: arn:partition:service::account:resource
	// resource examples:
	//   assumed-role/MyRole/session-name
	//   role/MyRole
	//   user/MyUser
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return arn // fallback: return as-is
	}
	resource := parts[5]

	segments := strings.Split(resource, "/")
	switch {
	case len(segments) >= 3 && segments[0] == "assumed-role":
		// assumed-role/RoleName/session-name -> RoleName
		return segments[1]
	case len(segments) >= 2:
		// role/RoleName or user/UserName -> second segment
		return segments[1]
	default:
		return resource
	}
}
