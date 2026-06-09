package provider

import (
	"testing"

	starflyv1 "github.com/starfly-fabrics/starfly/pkg/operator/api/v1alpha1"
)

func TestHashStarlightFabricSpecStable(t *testing.T) {
	spec := starflyv1.StarlightFabricSpec{
		TrustDomains: []starflyv1.TrustDomainSpec{
			{Name: "spiffe://prod.example.com", Type: "spiffe", Enabled: true},
		},
		Policy: &starflyv1.PolicySpec{BundlePath: "/etc/starfly/policies/"},
	}

	first, err := hashStarlightFabricSpec(spec)
	if err != nil {
		t.Fatalf("hashStarlightFabricSpec() error = %v", err)
	}

	second, err := hashStarlightFabricSpec(spec)
	if err != nil {
		t.Fatalf("hashStarlightFabricSpec() error = %v", err)
	}

	if first != second {
		t.Fatalf("hash mismatch: %q vs %q", first, second)
	}
	if len(first) != 64 {
		t.Fatalf("expected sha256 hex length 64, got %d", len(first))
	}
}

func TestHashStarlightFabricSpecChangesWhenSpecChanges(t *testing.T) {
	base := starflyv1.StarlightFabricSpec{
		TrustDomains: []starflyv1.TrustDomainSpec{
			{Name: "spiffe://prod.example.com", Type: "spiffe", Enabled: true},
		},
	}
	changed := starflyv1.StarlightFabricSpec{
		TrustDomains: []starflyv1.TrustDomainSpec{
			{Name: "spiffe://prod.example.com", Type: "spiffe", Enabled: false},
		},
	}

	baseHash, err := hashStarlightFabricSpec(base)
	if err != nil {
		t.Fatalf("hashStarlightFabricSpec(base) error = %v", err)
	}
	changedHash, err := hashStarlightFabricSpec(changed)
	if err != nil {
		t.Fatalf("hashStarlightFabricSpec(changed) error = %v", err)
	}
	if baseHash == changedHash {
		t.Fatal("expected different hashes for different specs")
	}
}

func TestLoadPEMInline(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
	got, err := loadPEM(pem)
	if err != nil {
		t.Fatalf("loadPEM() error = %v", err)
	}
	if string(got) != pem {
		t.Fatalf("loadPEM() = %q, want %q", string(got), pem)
	}
}

func TestBuildHTTPClientRequiresBothCertAndKey(t *testing.T) {
	_, err := buildHTTPClient("", "cert-only", "")
	if err == nil {
		t.Fatal("expected error when only client_cert is set")
	}
}
