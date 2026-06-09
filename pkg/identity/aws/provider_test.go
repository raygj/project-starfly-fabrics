package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// testSTSServer returns an httptest server that responds with valid
// GetCallerIdentity XML for the given account, ARN, and user ID.
func testSTSServer(t *testing.T, account, arn, userID string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = fmt.Fprintf(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Account>%s</Account>
    <Arn>%s</Arn>
    <UserId>%s</UserId>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>`, account, arn, userID)
	}))
}

// makeCredential builds a valid STSCredential JSON string with a current X-Amz-Date.
func makeCredential(url string) string {
	cred := STSCredential{
		URL:    url,
		Method: "POST",
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"X-Amz-Date":  time.Now().UTC().Format("20060102T150405Z"),
		},
		Body: "Action=GetCallerIdentity&Version=2011-06-15",
	}
	b, _ := json.Marshal(cred)
	return string(b)
}

func TestDevMode_HappyPath(t *testing.T) {
	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	cred := makeCredential("https://sts.amazonaws.com")
	identity, err := p.ValidateWorkload(context.Background(), cred, credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if identity.ID != "wimse://dev.local/aws/unknown-role" {
		t.Errorf("ID = %q, want %q", identity.ID, "wimse://dev.local/aws/unknown-role")
	}
	if identity.TrustDomain != "dev.local" {
		t.Errorf("TrustDomain = %q, want %q", identity.TrustDomain, "dev.local")
	}
	if identity.Attestation.Method != credType {
		t.Errorf("Attestation.Method = %q, want %q", identity.Attestation.Method, credType)
	}
	if identity.Claims["dev_mode"] != true {
		t.Error("expected dev_mode=true in claims")
	}
}

func TestProdMode_HappyPath(t *testing.T) {
	account := "123456789012"
	arn := "arn:aws:sts::123456789012:assumed-role/MyLambdaRole/session-abc"
	userID := "AROAEXAMPLEID:session-abc"

	srv := testSTSServer(t, account, arn, userID)
	defer srv.Close()

	p, err := NewProvider(
		WithSTSEndpoint(srv.URL),
		WithTrustDomains([]core.TrustDomain{
			{Name: account, Enabled: true},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	cred := makeCredential(srv.URL)
	identity, err := p.ValidateWorkload(context.Background(), cred, credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantURI := "wimse://123456789012/aws/MyLambdaRole"
	if identity.ID != wantURI {
		t.Errorf("ID = %q, want %q", identity.ID, wantURI)
	}
	if identity.TrustDomain != "123456789012" {
		t.Errorf("TrustDomain = %q, want %q", identity.TrustDomain, "123456789012")
	}
	if identity.Claims["account_id"] != account {
		t.Errorf("account_id claim = %v, want %s", identity.Claims["account_id"], account)
	}
	if identity.Claims["arn"] != arn {
		t.Errorf("arn claim = %v, want %s", identity.Claims["arn"], arn)
	}
	if identity.Claims["role_name"] != "MyLambdaRole" {
		t.Errorf("role_name claim = %v, want MyLambdaRole", identity.Claims["role_name"])
	}
	if identity.Claims["user_id"] != userID {
		t.Errorf("user_id claim = %v, want %s", identity.Claims["user_id"], userID)
	}
}

func TestProdMode_UnknownAccount(t *testing.T) {
	srv := testSTSServer(t, "999999999999", "arn:aws:sts::999999999999:assumed-role/Rogue/s", "AROA123")
	defer srv.Close()

	p, err := NewProvider(
		WithSTSEndpoint(srv.URL),
		WithTrustDomains([]core.TrustDomain{
			{Name: "123456789012", Enabled: true},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	cred := makeCredential(srv.URL)
	_, err = p.ValidateWorkload(context.Background(), cred, credType)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown AWS account") {
		t.Fatalf("error = %q, want containing 'unknown AWS account'", err.Error())
	}
}

func TestProdMode_RoleNotAllowed(t *testing.T) {
	account := "123456789012"
	arn := "arn:aws:sts::123456789012:assumed-role/ForbiddenRole/s"

	srv := testSTSServer(t, account, arn, "AROA123")
	defer srv.Close()

	p, err := NewProvider(
		WithSTSEndpoint(srv.URL),
		WithTrustDomains([]core.TrustDomain{
			{Name: account, Enabled: true},
		}),
		WithAllowedRoles([]string{
			"arn:aws:sts::123456789012:assumed-role/AllowedRole/s",
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	cred := makeCredential(srv.URL)
	_, err = p.ValidateWorkload(context.Background(), cred, credType)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "role ARN not allowed") {
		t.Fatalf("error = %q, want containing 'role ARN not allowed'", err.Error())
	}
}

func TestProdMode_STSError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, "<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>")
	}))
	defer srv.Close()

	p, err := NewProvider(
		WithSTSEndpoint(srv.URL),
		WithTrustDomains([]core.TrustDomain{
			{Name: "123456789012", Enabled: true},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	cred := makeCredential(srv.URL)
	_, err = p.ValidateWorkload(context.Background(), cred, credType)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "STS returned HTTP 403") {
		t.Fatalf("error = %q, want containing 'STS returned HTTP 403'", err.Error())
	}
}

func TestProdMode_StaleRequest(t *testing.T) {
	srv := testSTSServer(t, "123456789012", "arn:aws:sts::123456789012:assumed-role/R/s", "U")
	defer srv.Close()

	p, err := NewProvider(
		WithSTSEndpoint(srv.URL),
		WithTrustDomains([]core.TrustDomain{
			{Name: "123456789012", Enabled: true},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	// Build credential with an old X-Amz-Date.
	staleTime := time.Now().UTC().Add(-30 * time.Minute).Format("20060102T150405Z")
	cred := STSCredential{
		URL:    srv.URL,
		Method: "POST",
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"X-Amz-Date":  staleTime,
		},
		Body: "Action=GetCallerIdentity&Version=2011-06-15",
	}
	b, _ := json.Marshal(cred)

	_, err = p.ValidateWorkload(context.Background(), string(b), credType)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "request too old") {
		t.Fatalf("error = %q, want containing 'request too old'", err.Error())
	}
}

func TestWrongCredType(t *testing.T) {
	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), "{}", "k8s-sa")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported credential type") {
		t.Fatalf("error = %q, want containing 'unsupported credential type'", err.Error())
	}
}

func TestMalformedJSON(t *testing.T) {
	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), "not-json{{{", credType)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "malformed AWS STS credential") {
		t.Fatalf("error = %q, want containing 'malformed AWS STS credential'", err.Error())
	}
}

func TestExtractRoleName(t *testing.T) {
	tests := []struct {
		arn  string
		want string
	}{
		{
			arn:  "arn:aws:sts::123456789012:assumed-role/MyRole/session-name",
			want: "MyRole",
		},
		{
			arn:  "arn:aws:iam::123456789012:role/MyRole",
			want: "MyRole",
		},
		{
			arn:  "arn:aws:iam::123456789012:user/MyUser",
			want: "MyUser",
		},
		{
			arn:  "arn:aws:sts::123456789012:assumed-role/path/to/role/session",
			want: "path",
		},
		{
			arn:  "arn:aws:iam::123456789012:role/nested/path/role",
			want: "nested",
		},
		{
			arn:  "not-an-arn",
			want: "not-an-arn",
		},
		{
			arn:  "arn:aws:sts::123456789012:root",
			want: "root",
		},
	}

	for _, tt := range tests {
		t.Run(tt.arn, func(t *testing.T) {
			got := extractRoleName(tt.arn)
			if got != tt.want {
				t.Errorf("extractRoleName(%q) = %q, want %q", tt.arn, got, tt.want)
			}
		})
	}
}

func TestWithHTTPClient(t *testing.T) {
	custom := &http.Client{Timeout: 42 * time.Second}
	p, err := NewProvider(WithHTTPClient(custom))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if p.httpClient != custom {
		t.Error("WithHTTPClient did not set custom client")
	}
}

func TestValidateFreshness_MissingDate(t *testing.T) {
	p, _ := NewProvider()
	cred := STSCredential{Headers: map[string]string{}}
	err := p.validateFreshness(cred)
	if err == nil {
		t.Fatal("expected error for missing X-Amz-Date")
	}
	if !strings.Contains(err.Error(), "missing X-Amz-Date") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateFreshness_LowercaseDate(t *testing.T) {
	p, _ := NewProvider()
	cred := STSCredential{
		Headers: map[string]string{
			"x-amz-date": time.Now().UTC().Format("20060102T150405Z"),
		},
	}
	err := p.validateFreshness(cred)
	if err != nil {
		t.Fatalf("expected success with lowercase header, got: %v", err)
	}
}

func TestValidateFreshness_StaleDate(t *testing.T) {
	p, _ := NewProvider()
	staleDate := time.Now().UTC().Add(-20 * time.Minute).Format("20060102T150405Z")
	cred := STSCredential{
		Headers: map[string]string{
			"X-Amz-Date": staleDate,
		},
	}
	err := p.validateFreshness(cred)
	if err == nil {
		t.Fatal("expected error for stale date")
	}
}

func TestValidateFreshness_InvalidFormat(t *testing.T) {
	p, _ := NewProvider()
	cred := STSCredential{
		Headers: map[string]string{
			"X-Amz-Date": "not-a-date",
		},
	}
	err := p.validateFreshness(cred)
	if err == nil {
		t.Fatal("expected error for invalid date format")
	}
}

func TestIsAllowedSTSURL_Custom(t *testing.T) {
	p, _ := NewProvider(WithSTSEndpoint("https://custom-sts.example.com"))

	if !p.isAllowedSTSURL("https://sts.amazonaws.com/something") {
		t.Error("expected real STS URL to be allowed")
	}
	if !p.isAllowedSTSURL("https://custom-sts.example.com/api") {
		t.Error("expected custom STS URL to be allowed")
	}
	if p.isAllowedSTSURL("https://evil.example.com") {
		t.Error("expected unknown URL to be rejected")
	}
}

func TestDevIdentity_WithDevArn(t *testing.T) {
	p, _ := NewProvider(WithDevMode(true))
	cred := STSCredential{
		Headers: map[string]string{
			"X-Starfly-Dev-Arn": "arn:aws:sts::123456789012:assumed-role/TestRole/session",
		},
	}
	id := p.devIdentity(cred)
	if !strings.Contains(id.ID, "TestRole") {
		t.Errorf("expected ID to contain TestRole, got %q", id.ID)
	}
}

func TestInterfaceAssertion(t *testing.T) {
	// Compile-time check is in provider.go (var _ core.IdentityProvider = (*Provider)(nil)).
	// Runtime verification:
	var ip core.IdentityProvider
	p, err := NewProvider()
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	ip = p
	_ = ip
}
