package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAWSAttestor_Available(t *testing.T) {
	srv := newMockIMDS(t)
	defer srv.Close()

	a := NewAWSAttestor(srv.URL)
	if !a.Available(context.Background()) {
		t.Error("Available() should be true when IMDS is reachable")
	}
}

func TestAWSAttestor_Unavailable(t *testing.T) {
	a := NewAWSAttestor("http://127.0.0.1:1")
	if a.Available(context.Background()) {
		t.Error("Available() should be false when IMDS is unreachable")
	}
}

func TestAWSAttestor_Name(t *testing.T) {
	a := NewAWSAttestor("")
	if a.Name() != "aws-imds" {
		t.Errorf("Name() = %q, want aws-imds", a.Name())
	}
}

func TestAWSAttestor_Attest(t *testing.T) {
	srv := newMockIMDS(t)
	defer srv.Close()

	a := NewAWSAttestor(srv.URL)
	result, err := a.Attest(context.Background())
	if err != nil {
		t.Fatalf("Attest() error: %v", err)
	}

	if result.Source != "aws-imds" {
		t.Errorf("Source = %q, want aws-imds", result.Source)
	}
	if result.CredType != "urn:starfly:token-type:aws-sts" {
		t.Errorf("CredType = %q", result.CredType)
	}
	if result.Metadata["account_id"] != "123456789012" {
		t.Errorf("account_id = %q", result.Metadata["account_id"])
	}
	if result.Metadata["instance_id"] != "i-0abcdef1234567890" {
		t.Errorf("instance_id = %q", result.Metadata["instance_id"])
	}
	if result.Metadata["region"] != "us-east-1" {
		t.Errorf("region = %q", result.Metadata["region"])
	}
	if result.Metadata["instance_type"] != "m5.large" {
		t.Errorf("instance_type = %q", result.Metadata["instance_type"])
	}
	if len(result.Credential) == 0 {
		t.Error("expected non-empty credential")
	}
}

func TestAWSAttestor_IMDSv2TokenFlow(t *testing.T) {
	var gotPUT bool
	var gotTokenHeader bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == awsTokenPath:
			gotPUT = true
			if r.Header.Get(awsTokenTTLHeader) == "" {
				t.Error("missing TTL header on token request")
			}
			_, _ = w.Write([]byte("test-session-token"))
		case r.Method == http.MethodGet && r.URL.Path == awsIdentityDocPath:
			if r.Header.Get(awsTokenHeader) != "test-session-token" {
				t.Errorf("token header = %q, want test-session-token", r.Header.Get(awsTokenHeader))
			}
			gotTokenHeader = true
			_ = json.NewEncoder(w).Encode(map[string]string{
				"accountId":    "111",
				"instanceId":   "i-111",
				"region":       "eu-west-1",
				"instanceType": "t3.micro",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a := NewAWSAttestor(srv.URL)
	_, err := a.Attest(context.Background())
	if err != nil {
		t.Fatalf("Attest() error: %v", err)
	}
	if !gotPUT {
		t.Error("IMDSv2 PUT token request not made")
	}
	if !gotTokenHeader {
		t.Error("IMDSv2 token not sent on identity doc request")
	}
}

func TestAWSAttestor_Attest_TokenError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == awsTokenPath {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	a := NewAWSAttestor(srv.URL)
	_, err := a.Attest(context.Background())
	if err == nil {
		t.Fatal("expected error when IMDS token request fails")
	}
}

func TestAWSAttestor_Attest_IdentityDocError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == awsTokenPath:
			_, _ = w.Write([]byte("mock-token"))
		case r.Method == http.MethodGet && r.URL.Path == awsIdentityDocPath:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("internal error"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a := NewAWSAttestor(srv.URL)
	_, err := a.Attest(context.Background())
	if err == nil {
		t.Fatal("expected error when identity doc returns 500")
	}
}

func TestAWSAttestor_Attest_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == awsTokenPath:
			_, _ = w.Write([]byte("mock-token"))
		case r.Method == http.MethodGet && r.URL.Path == awsIdentityDocPath:
			_, _ = w.Write([]byte("not json"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a := NewAWSAttestor(srv.URL)
	_, err := a.Attest(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid JSON identity document")
	}
}

func TestAWSAttestor_GetToken_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == awsTokenPath {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("unavailable"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	a := NewAWSAttestor(srv.URL)
	if a.Available(context.Background()) {
		t.Error("Available() should be false when token returns non-200")
	}
}

// newMockIMDS creates an httptest server that mimics AWS IMDS v2.
func newMockIMDS(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == awsTokenPath:
			_, _ = w.Write([]byte("mock-imds-token"))
		case r.Method == http.MethodGet && r.URL.Path == awsIdentityDocPath:
			_ = json.NewEncoder(w).Encode(map[string]string{
				"accountId":    "123456789012",
				"instanceId":   "i-0abcdef1234567890",
				"region":       "us-east-1",
				"instanceType": "m5.large",
			})
		default:
			http.NotFound(w, r)
		}
	}))
}
