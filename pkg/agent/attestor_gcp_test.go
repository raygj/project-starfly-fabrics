package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGCPAttestor_Available(t *testing.T) {
	srv := newMockGCPMetadata(t)
	defer srv.Close()

	a := NewGCPAttestor(srv.URL, "starfly.prod")
	if !a.Available(context.Background()) {
		t.Error("Available() should be true when metadata server is reachable")
	}
}

func TestGCPAttestor_Unavailable(t *testing.T) {
	a := NewGCPAttestor("http://127.0.0.1:1", "starfly.prod")
	if a.Available(context.Background()) {
		t.Error("Available() should be false when metadata server is unreachable")
	}
}

func TestGCPAttestor_Name(t *testing.T) {
	a := NewGCPAttestor("", "test")
	if a.Name() != "gcp-metadata" {
		t.Errorf("Name() = %q, want gcp-metadata", a.Name())
	}
}

func TestGCPAttestor_Attest(t *testing.T) {
	srv := newMockGCPMetadata(t)
	defer srv.Close()

	a := NewGCPAttestor(srv.URL, "starfly.prod")
	result, err := a.Attest(context.Background())
	if err != nil {
		t.Fatalf("Attest() error: %v", err)
	}

	if result.Source != "gcp-metadata" {
		t.Errorf("Source = %q, want gcp-metadata", result.Source)
	}
	if result.CredType != "urn:starfly:token-type:gcp-wif" {
		t.Errorf("CredType = %q", result.CredType)
	}
	if len(result.Credential) == 0 {
		t.Error("expected non-empty credential")
	}
	if result.Metadata["project_id"] != "my-project-123" {
		t.Errorf("project_id = %q", result.Metadata["project_id"])
	}
	if result.Metadata["zone"] != "us-central1-a" {
		t.Errorf("zone = %q, want us-central1-a", result.Metadata["zone"])
	}
	if result.Metadata["instance_name"] != "worker-01" {
		t.Errorf("instance_name = %q", result.Metadata["instance_name"])
	}
	if result.Metadata["service_account"] != "my-sa@my-project-123.iam.gserviceaccount.com" {
		t.Errorf("service_account = %q", result.Metadata["service_account"])
	}
}

func TestGCPAttestor_MetadataFlavorHeader(t *testing.T) {
	var gotFlavor bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(gcpFlavorHeader) == gcpFlavorValue {
			gotFlavor = true
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	a := NewGCPAttestor(srv.URL, "test")
	_ = a.Available(context.Background())
	if !gotFlavor {
		t.Error("Metadata-Flavor: Google header not sent")
	}
}

func TestGCPAttestor_Attest_TokenError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(gcpFlavorHeader) != gcpFlavorValue {
			http.Error(w, "missing flavor", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case gcpIdentityTokenPath:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()

	a := NewGCPAttestor(srv.URL, "test")
	_, err := a.Attest(context.Background())
	if err == nil {
		t.Fatal("expected error when identity token fetch fails")
	}
}

func TestGCPAttestor_GetMetadata_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable"))
	}))
	defer srv.Close()

	a := NewGCPAttestor(srv.URL, "test")
	if a.Available(context.Background()) {
		t.Error("Available() should be false when metadata server returns non-200")
	}
}

func TestGCPAttestor_DefaultEndpoint(t *testing.T) {
	a := NewGCPAttestor("", "test")
	if a.endpoint != defaultGCPMetadataEndpoint {
		t.Errorf("endpoint = %q, want default", a.endpoint)
	}
}

func newMockGCPMetadata(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(gcpFlavorHeader) != gcpFlavorValue {
			http.Error(w, "missing Metadata-Flavor header", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case gcpProjectIDPath:
			_, _ = w.Write([]byte("my-project-123"))
		case gcpZonePath:
			_, _ = w.Write([]byte("projects/123456/zones/us-central1-a"))
		case gcpInstanceNamePath:
			_, _ = w.Write([]byte("worker-01"))
		case gcpServiceAccountPath:
			_, _ = w.Write([]byte("my-sa@my-project-123.iam.gserviceaccount.com"))
		case gcpIdentityTokenPath:
			_, _ = w.Write([]byte("eyJhbGciOiJSUzI1NiJ9.gcp-identity-token.sig"))
		default:
			http.NotFound(w, r)
		}
	}))
}
