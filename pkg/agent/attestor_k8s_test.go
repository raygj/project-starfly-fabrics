package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestK8sAttestor_AvailableWhenTokenExists(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	_ = os.WriteFile(tokenPath, []byte("fake-sa-token"), 0600)

	a := NewK8sAttestor(tokenPath, "")
	if !a.Available(context.Background()) {
		t.Error("Available() should be true when token file exists")
	}
}

func TestK8sAttestor_UnavailableWhenNoToken(t *testing.T) {
	a := NewK8sAttestor("/nonexistent/path/token", "")
	if a.Available(context.Background()) {
		t.Error("Available() should be false when token file does not exist")
	}
}

func TestK8sAttestor_Name(t *testing.T) {
	a := NewK8sAttestor("", "")
	if a.Name() != "k8s-sa" {
		t.Errorf("Name() = %q, want k8s-sa", a.Name())
	}
}

func TestK8sAttestor_Attest(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	nsPath := filepath.Join(dir, "namespace")

	_ = os.WriteFile(tokenPath, []byte("eyJhbGciOiJSUzI1NiJ9.payload.sig"), 0600)
	_ = os.WriteFile(nsPath, []byte("production\n"), 0600)

	t.Setenv("POD_NAME", "my-pod-abc123")
	t.Setenv("NODE_NAME", "node-01")

	a := NewK8sAttestor(tokenPath, nsPath)
	result, err := a.Attest(context.Background())
	if err != nil {
		t.Fatalf("Attest() error: %v", err)
	}

	if result.Source != "k8s-sa" {
		t.Errorf("Source = %q, want k8s-sa", result.Source)
	}
	if result.CredType != "urn:ietf:params:oauth:token-type:jwt" {
		t.Errorf("CredType = %q, want urn:ietf:params:oauth:token-type:jwt", result.CredType)
	}
	if string(result.Credential) != "eyJhbGciOiJSUzI1NiJ9.payload.sig" {
		t.Errorf("Credential = %q, want token bytes", string(result.Credential))
	}
	if result.Metadata["namespace"] != "production" {
		t.Errorf("namespace = %q, want production", result.Metadata["namespace"])
	}
	if result.Metadata["pod_name"] != "my-pod-abc123" {
		t.Errorf("pod_name = %q, want my-pod-abc123", result.Metadata["pod_name"])
	}
	if result.Metadata["node_name"] != "node-01" {
		t.Errorf("node_name = %q, want node-01", result.Metadata["node_name"])
	}
}

func TestK8sAttestor_AttestWithoutOptionalFields(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	_ = os.WriteFile(tokenPath, []byte("token-data"), 0600)

	t.Setenv("POD_NAME", "")
	t.Setenv("NODE_NAME", "")

	a := NewK8sAttestor(tokenPath, "/nonexistent/namespace")
	result, err := a.Attest(context.Background())
	if err != nil {
		t.Fatalf("Attest() error: %v", err)
	}

	if _, ok := result.Metadata["namespace"]; ok {
		t.Error("namespace should not be set when namespace file is missing")
	}
	if _, ok := result.Metadata["pod_name"]; ok {
		t.Error("pod_name should not be set when POD_NAME env is empty")
	}
}

func TestK8sAttestor_AttestErrorOnMissingToken(t *testing.T) {
	a := NewK8sAttestor("/nonexistent/token", "")
	_, err := a.Attest(context.Background())
	if err == nil {
		t.Error("expected error when token file is missing")
	}
}
