package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAzureAttestor_Available(t *testing.T) {
	srv := newMockAzureIMDS(t)
	defer srv.Close()

	a := NewAzureAttestor(srv.URL, "https://management.azure.com/")
	if !a.Available(context.Background()) {
		t.Error("Available() should be true when Azure IMDS is reachable")
	}
}

func TestAzureAttestor_Unavailable(t *testing.T) {
	a := NewAzureAttestor("http://127.0.0.1:1", "")
	if a.Available(context.Background()) {
		t.Error("Available() should be false when IMDS is unreachable")
	}
}

func TestAzureAttestor_Name(t *testing.T) {
	a := NewAzureAttestor("", "")
	if a.Name() != "azure-imds" {
		t.Errorf("Name() = %q, want azure-imds", a.Name())
	}
}

func TestAzureAttestor_Attest(t *testing.T) {
	srv := newMockAzureIMDS(t)
	defer srv.Close()

	a := NewAzureAttestor(srv.URL, "https://management.azure.com/")
	result, err := a.Attest(context.Background())
	if err != nil {
		t.Fatalf("Attest() error: %v", err)
	}

	if result.Source != "azure-imds" {
		t.Errorf("Source = %q, want azure-imds", result.Source)
	}
	if result.CredType != "urn:starfly:token-type:azure-mi" {
		t.Errorf("CredType = %q", result.CredType)
	}
	if len(result.Credential) == 0 {
		t.Error("expected non-empty credential")
	}
	if result.Metadata["subscription_id"] != "sub-123-456" {
		t.Errorf("subscription_id = %q", result.Metadata["subscription_id"])
	}
	if result.Metadata["resource_group"] != "my-rg" {
		t.Errorf("resource_group = %q", result.Metadata["resource_group"])
	}
	if result.Metadata["vm_name"] != "worker-vm-01" {
		t.Errorf("vm_name = %q", result.Metadata["vm_name"])
	}
	if result.Metadata["location"] != "eastus" {
		t.Errorf("location = %q", result.Metadata["location"])
	}
}

func TestAzureAttestor_MetadataHeader(t *testing.T) {
	var gotMetadataHeader bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(azureMetadataHeader) == "true" {
			gotMetadataHeader = true
		}
		switch r.URL.Path {
		case azureInstancePath:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"compute": map[string]string{
					"subscriptionId":    "s",
					"resourceGroupName": "r",
					"name":              "n",
					"location":          "l",
				},
			})
		case azureTokenPath:
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a := NewAzureAttestor(srv.URL, "https://management.azure.com/")
	_, _ = a.Attest(context.Background())
	if !gotMetadataHeader {
		t.Error("Metadata: true header not sent")
	}
}

func TestAzureAttestor_Attest_TokenError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case azureTokenPath:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("forbidden"))
		case azureInstancePath:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"compute": map[string]string{
					"subscriptionId": "s", "resourceGroupName": "r",
					"name": "n", "location": "l",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a := NewAzureAttestor(srv.URL, "https://management.azure.com/")
	_, err := a.Attest(context.Background())
	if err == nil {
		t.Fatal("expected error when token request returns 403")
	}
}

func TestAzureAttestor_Attest_MetadataError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case azureTokenPath:
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case azureInstancePath:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("error"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a := NewAzureAttestor(srv.URL, "https://management.azure.com/")
	_, err := a.Attest(context.Background())
	if err == nil {
		t.Fatal("expected error when instance metadata returns 500")
	}
}

func TestAzureAttestor_Attest_TokenInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case azureTokenPath:
			_, _ = w.Write([]byte("not json"))
		case azureInstancePath:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"compute": map[string]string{
					"subscriptionId": "s", "resourceGroupName": "r",
					"name": "n", "location": "l",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a := NewAzureAttestor(srv.URL, "https://management.azure.com/")
	_, err := a.Attest(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid JSON token response")
	}
}

func TestAzureAttestor_Attest_MetadataInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case azureTokenPath:
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case azureInstancePath:
			_, _ = w.Write([]byte("not json"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a := NewAzureAttestor(srv.URL, "https://management.azure.com/")
	_, err := a.Attest(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid JSON metadata response")
	}
}

func TestAzureAttestor_Available_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	a := NewAzureAttestor(srv.URL, "")
	if a.Available(context.Background()) {
		t.Error("Available() should be false when IMDS returns non-200")
	}
}

func TestAzureAttestor_DefaultEndpointAndResource(t *testing.T) {
	a := NewAzureAttestor("", "")
	if a.endpoint != defaultAzureIMDSEndpoint {
		t.Errorf("endpoint = %q, want default", a.endpoint)
	}
	if a.resource != "https://management.azure.com/" {
		t.Errorf("resource = %q, want default", a.resource)
	}
}

func newMockAzureIMDS(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(azureMetadataHeader) != "true" {
			http.Error(w, "missing Metadata header", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case azureInstancePath:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"compute": map[string]string{
					"subscriptionId":    "sub-123-456",
					"resourceGroupName": "my-rg",
					"name":              "worker-vm-01",
					"location":          "eastus",
				},
			})
		case azureTokenPath:
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.azure-mi-token.sig",
			})
		default:
			http.NotFound(w, r)
		}
	}))
}
