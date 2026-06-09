package kerberos

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/starfly-fabrics/starfly/pkg/core"
)

func TestValidateWorkload(t *testing.T) {
	tests := []struct {
		name       string
		credential string
		credType   string
		devMode    bool
		wantErr    string
		wantID     string
		wantClaims map[string]interface{}
	}{
		{
			name:       "dev mode happy path — simple principal",
			credential: base64.StdEncoding.EncodeToString([]byte("svc-worker")),
			credType:   "kerberos",
			devMode:    true,
			wantID:     "wimse://dev.local/kerberos/svc-worker",
			wantClaims: map[string]interface{}{
				"principal": "svc-worker",
				"realm":     "DEV.LOCAL",
				"dev_mode":  true,
			},
		},
		{
			name:       "dev mode — principal with realm",
			credential: base64.StdEncoding.EncodeToString([]byte("admin@CORP.EXAMPLE.COM")),
			credType:   "kerberos",
			devMode:    true,
			wantID:     "wimse://dev.local/kerberos/admin",
			wantClaims: map[string]interface{}{
				"principal": "admin",
				"realm":     "CORP.EXAMPLE.COM",
				"dev_mode":  true,
			},
		},
		{
			name:       "dev mode — SPN style principal",
			credential: base64.StdEncoding.EncodeToString([]byte("HTTP/api.corp.com@CORP.COM")),
			credType:   "kerberos",
			devMode:    true,
			wantID:     "wimse://dev.local/kerberos/HTTP/api.corp.com",
			wantClaims: map[string]interface{}{
				"principal": "HTTP/api.corp.com",
				"realm":     "CORP.COM",
				"dev_mode":  true,
			},
		},
		{
			name:       "wrong cred type",
			credential: base64.StdEncoding.EncodeToString([]byte("test")),
			credType:   "jwt",
			devMode:    true,
			wantErr:    "unsupported credential type",
		},
		{
			name:       "malformed base64",
			credential: "not-valid-base64!!!",
			credType:   "kerberos",
			devMode:    true,
			wantErr:    "malformed base64",
		},
		{
			name:       "dev mode — empty principal",
			credential: base64.StdEncoding.EncodeToString([]byte("")),
			credType:   "kerberos",
			devMode:    true,
			wantErr:    "empty principal",
		},
		{
			name:       "prod mode — no keytab configured",
			credential: base64.StdEncoding.EncodeToString([]byte("test-data")),
			credType:   "kerberos",
			devMode:    false,
			wantErr:    "no keytab configured",
		},
		{
			name:       "prod mode — malformed AP-REQ",
			credential: base64.StdEncoding.EncodeToString([]byte("not-a-real-apreq")),
			credType:   "kerberos",
			devMode:    false,
			wantErr:    "malformed AP-REQ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p *Provider
			var err error

			if tt.devMode {
				p, err = NewProvider(WithDevMode(true))
			} else {
				if tt.name == "prod mode — malformed AP-REQ" {
					p = &Provider{
						trustDomains: make(map[string]core.TrustDomain),
						kt:           &keytab.Keytab{},
					}
				} else {
					p, err = NewProvider()
				}
			}
			if err != nil {
				t.Fatalf("NewProvider: %v", err)
			}

			identity, err := p.ValidateWorkload(context.Background(), tt.credential, tt.credType)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %q, want containing %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if identity.ID != tt.wantID {
				t.Errorf("ID = %q, want %q", identity.ID, tt.wantID)
			}

			if identity.TrustDomain != "dev.local" {
				t.Errorf("TrustDomain = %q, want %q", identity.TrustDomain, "dev.local")
			}

			if identity.Attestation == nil || identity.Attestation.Method != "kerberos" {
				t.Error("Attestation should have method 'kerberos'")
			}

			for k, want := range tt.wantClaims {
				got, ok := identity.Claims[k]
				if !ok {
					t.Errorf("missing claim %q", k)
					continue
				}
				if fmt.Sprintf("%v", got) != fmt.Sprintf("%v", want) {
					t.Errorf("claim[%q] = %v, want %v", k, got, want)
				}
			}
		})
	}
}

func TestNewProvider_Options(t *testing.T) {
	p, err := NewProvider(
		WithDevMode(true),
		WithKeytabPath("/nonexistent"),
	)
	if err != nil {
		t.Fatalf("NewProvider with dev mode should not fail: %v", err)
	}
	if !p.devMode {
		t.Error("devMode should be true")
	}
	if p.keytabPath != "/nonexistent" {
		t.Errorf("keytabPath = %q, want /nonexistent", p.keytabPath)
	}
}

func TestNewProvider_ProdMode_BadKeytab(t *testing.T) {
	_, err := NewProvider(
		WithKeytabPath("/nonexistent/keytab"),
	)
	if err == nil {
		t.Fatal("expected error for nonexistent keytab")
	}
}

func TestValidateWorkload_InterfaceAssertion(t *testing.T) {
	var _ core.IdentityProvider = (*Provider)(nil)
}

func TestComposePrincipal(t *testing.T) {
	tests := []struct {
		nameString []string
		realm      string
		want       string
	}{
		{[]string{"admin"}, "CORP.COM", "admin@CORP.COM"},
		{[]string{"HTTP", "api.corp.com"}, "CORP.COM", "HTTP/api.corp.com@CORP.COM"},
		{[]string{}, "CORP.COM", "@CORP.COM"},
	}

	for _, tt := range tests {
		name := types.PrincipalName{NameString: tt.nameString}
		got := composePrincipal(name, tt.realm)
		if got != tt.want {
			t.Errorf("composePrincipal(%v, %q) = %q, want %q", tt.nameString, tt.realm, got, tt.want)
		}
	}
}

// testKeytab creates a keytab with a known key for the given service principal and realm.
func testKeytab(t *testing.T, servicePrincipal, realm, password string) *keytab.Keytab {
	t.Helper()
	kt := keytab.New()
	if err := kt.AddEntry(servicePrincipal, realm, password, time.Now(), 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatalf("keytab.AddEntry: %v", err)
	}
	return kt
}

// testAPReq creates a valid AP-REQ message for the given client/service principals,
// encrypted with the given keytab. Returns base64-encoded bytes suitable for ValidateWorkload.
func testAPReq(t *testing.T, clientPrincipal []string, clientRealm string, servicePrincipal []string, serviceRealm string, kt *keytab.Keytab) string {
	t.Helper()

	cname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: clientPrincipal}
	sname := types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: servicePrincipal}

	now := time.Now().UTC()
	flags := types.NewKrbFlags()

	tkt, sessionKey, err := messages.NewTicket(
		cname, clientRealm,
		sname, serviceRealm,
		flags, kt,
		etypeID.AES256_CTS_HMAC_SHA1_96,
		1, // kvno
		now, now, now.Add(10*time.Hour), now.Add(24*time.Hour),
	)
	if err != nil {
		t.Fatalf("NewTicket: %v", err)
	}

	auth, err := types.NewAuthenticator(clientRealm, cname)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	apreq, err := messages.NewAPReq(tkt, sessionKey, auth)
	if err != nil {
		t.Fatalf("NewAPReq: %v", err)
	}

	b, err := apreq.Marshal()
	if err != nil {
		t.Fatalf("APReq.Marshal: %v", err)
	}

	return base64.StdEncoding.EncodeToString(b)
}

func TestProdValidate_HappyPath(t *testing.T) {
	realm := "CORP.EXAMPLE.COM"
	svcPrincipal := "starfly"
	password := "test-keytab-password-1234"

	kt := testKeytab(t, svcPrincipal, realm, password)

	cred := testAPReq(t,
		[]string{"svc-worker"}, realm,
		[]string{svcPrincipal}, realm,
		kt,
	)

	p := &Provider{
		trustDomains: map[string]core.TrustDomain{
			"corp.example.com": {Name: "corp.example.com", Enabled: true},
		},
		kt: kt,
	}

	identity, err := p.ValidateWorkload(context.Background(), cred, "kerberos")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantID := "wimse://corp.example.com/kerberos/svc-worker@CORP.EXAMPLE.COM"
	if identity.ID != wantID {
		t.Errorf("ID = %q, want %q", identity.ID, wantID)
	}
	if identity.TrustDomain != "corp.example.com" {
		t.Errorf("TrustDomain = %q, want %q", identity.TrustDomain, "corp.example.com")
	}
	if identity.Attestation == nil || identity.Attestation.Method != "kerberos" {
		t.Error("Attestation should have method 'kerberos'")
	}
	if p, ok := identity.Claims["principal"]; !ok || p != "svc-worker@CORP.EXAMPLE.COM" {
		t.Errorf("claim[principal] = %v, want %q", p, "svc-worker@CORP.EXAMPLE.COM")
	}
	if r, ok := identity.Claims["realm"]; !ok || r != realm {
		t.Errorf("claim[realm] = %v, want %q", r, realm)
	}
	if _, ok := identity.Claims["etype"]; !ok {
		t.Error("claim[etype] should be present")
	}
}

func TestProdValidate_MultiPartPrincipal(t *testing.T) {
	realm := "CORP.COM"
	svcPrincipal := "starfly"
	password := "test-keytab-password-5678"

	kt := testKeytab(t, svcPrincipal, realm, password)

	// SPN-style client principal: HTTP/api.corp.com
	cred := testAPReq(t,
		[]string{"HTTP", "api.corp.com"}, realm,
		[]string{svcPrincipal}, realm,
		kt,
	)

	p := &Provider{
		trustDomains: map[string]core.TrustDomain{
			"corp.com": {Name: "corp.com", Enabled: true},
		},
		kt: kt,
	}

	identity, err := p.ValidateWorkload(context.Background(), cred, "kerberos")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantID := "wimse://corp.com/kerberos/HTTP/api.corp.com@CORP.COM"
	if identity.ID != wantID {
		t.Errorf("ID = %q, want %q", identity.ID, wantID)
	}
	if p, ok := identity.Claims["principal"]; !ok || p != "HTTP/api.corp.com@CORP.COM" {
		t.Errorf("claim[principal] = %v, want %q", p, "HTTP/api.corp.com@CORP.COM")
	}
}

func TestProdValidate_DecryptionFailure(t *testing.T) {
	realm := "CORP.COM"
	svcPrincipal := "starfly"

	// Create AP-REQ with one keytab (password A)
	ktA := testKeytab(t, svcPrincipal, realm, "password-A")
	cred := testAPReq(t,
		[]string{"user1"}, realm,
		[]string{svcPrincipal}, realm,
		ktA,
	)

	// Provider uses a different keytab (password B) — decryption should fail
	ktB := testKeytab(t, svcPrincipal, realm, "password-B")
	p := &Provider{
		trustDomains: map[string]core.TrustDomain{
			"corp.com": {Name: "corp.com", Enabled: true},
		},
		kt: ktB,
	}

	_, err := p.ValidateWorkload(context.Background(), cred, "kerberos")
	if err == nil {
		t.Fatal("expected decryption failure error, got nil")
	}
	if !contains(err.Error(), "ticket decryption failed") {
		t.Errorf("error = %q, want containing %q", err.Error(), "ticket decryption failed")
	}
}

func TestProdValidate_UnknownRealm(t *testing.T) {
	realm := "UNKNOWN.REALM"
	svcPrincipal := "starfly"
	password := "test-keytab-password-9999"

	kt := testKeytab(t, svcPrincipal, realm, password)

	cred := testAPReq(t,
		[]string{"user1"}, realm,
		[]string{svcPrincipal}, realm,
		kt,
	)

	// Provider only trusts "corp.com", not "unknown.realm"
	p := &Provider{
		trustDomains: map[string]core.TrustDomain{
			"corp.com": {Name: "corp.com", Enabled: true},
		},
		kt: kt,
	}

	_, err := p.ValidateWorkload(context.Background(), cred, "kerberos")
	if err == nil {
		t.Fatal("expected unknown realm error, got nil")
	}
	if !contains(err.Error(), "unknown Kerberos realm") {
		t.Errorf("error = %q, want containing %q", err.Error(), "unknown Kerberos realm")
	}
}

func TestProdValidate_ReplayDetection(t *testing.T) {
	realm := "CORP.EXAMPLE.COM"
	svcPrincipal := "starfly"
	password := "test-keytab-password-replay"

	kt := testKeytab(t, svcPrincipal, realm, password)

	cred := testAPReq(t,
		[]string{"svc-worker"}, realm,
		[]string{svcPrincipal}, realm,
		kt,
	)

	p := &Provider{
		trustDomains: map[string]core.TrustDomain{
			"corp.example.com": {Name: "corp.example.com", Enabled: true},
		},
		kt: kt,
	}

	// First call should succeed.
	_, err := p.ValidateWorkload(context.Background(), cred, "kerberos")
	if err != nil {
		t.Fatalf("first validation: unexpected error: %v", err)
	}

	// Second call with the same credential should fail as a replay.
	_, err = p.ValidateWorkload(context.Background(), cred, "kerberos")
	if err == nil {
		t.Fatal("expected replay detection error, got nil")
	}
	if !contains(err.Error(), "replay detected") {
		t.Errorf("error = %q, want containing %q", err.Error(), "replay detected")
	}
}

func TestCleanupReplayCache(t *testing.T) {
	realm := "CORP.EXAMPLE.COM"
	svcPrincipal := "starfly"
	password := "test-keytab-password-cleanup"

	kt := testKeytab(t, svcPrincipal, realm, password)

	cred := testAPReq(t,
		[]string{"svc-worker"}, realm,
		[]string{svcPrincipal}, realm,
		kt,
	)

	p := &Provider{
		trustDomains: map[string]core.TrustDomain{
			"corp.example.com": {Name: "corp.example.com", Enabled: true},
		},
		kt:           kt,
		replayWindow: 1 * time.Millisecond,
	}

	// Validate to populate the cache.
	_, err := p.ValidateWorkload(context.Background(), cred, "kerberos")
	if err != nil {
		t.Fatalf("first validation: unexpected error: %v", err)
	}

	// Wait for the entry to expire.
	time.Sleep(5 * time.Millisecond)

	// Cleanup should remove the expired entry.
	removed := p.CleanupReplayCache()
	if removed != 1 {
		t.Errorf("CleanupReplayCache removed %d entries, want 1", removed)
	}

	// Same credential should now succeed again.
	_, err = p.ValidateWorkload(context.Background(), cred, "kerberos")
	if err != nil {
		t.Fatalf("post-cleanup validation: unexpected error: %v", err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
