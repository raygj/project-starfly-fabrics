package operator

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/starfly-fabrics/starfly/pkg/operator/api/v1alpha1"
)

func TestValidateFabric_Valid(t *testing.T) {
	fabric := &v1alpha1.StarlightFabric{
		ObjectMeta: metav1.ObjectMeta{Name: "test-fabric"},
		Spec: v1alpha1.StarlightFabricSpec{
			TrustDomains: []v1alpha1.TrustDomainSpec{
				{Name: "payments.prod", Type: "oidc", Enabled: true},
			},
			SigningKeys: []v1alpha1.SigningKeySpec{
				{KID: "key-001", Algorithm: "ES256", KMSKeyID: "arn:key"},
			},
			SSFStreams: []v1alpha1.SSFStreamSpec{
				{StreamID: "s1", Transmitter: "https://ssf.example.com"},
			},
			Anchor: &v1alpha1.AnchorSpec{Type: "s3", Bucket: "my-bucket"},
		},
	}

	errs := ValidateFabric(fabric)
	if len(errs) > 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
}

func TestValidateFabric_DuplicateTrustDomains(t *testing.T) {
	fabric := &v1alpha1.StarlightFabric{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: v1alpha1.StarlightFabricSpec{
			TrustDomains: []v1alpha1.TrustDomainSpec{
				{Name: "dup", Type: "oidc"},
				{Name: "dup", Type: "oidc"},
			},
		},
	}

	errs := ValidateFabric(fabric)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "duplicate") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected duplicate error, got: %v", errs)
	}
}

func TestValidateFabric_InvalidType(t *testing.T) {
	fabric := &v1alpha1.StarlightFabric{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: v1alpha1.StarlightFabricSpec{
			TrustDomains: []v1alpha1.TrustDomainSpec{
				{Name: "td", Type: "unsupported"},
			},
		},
	}

	errs := ValidateFabric(fabric)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "not supported") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected unsupported type error, got: %v", errs)
	}
}

func TestValidateFabric_DuplicateSigningKeys(t *testing.T) {
	fabric := &v1alpha1.StarlightFabric{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: v1alpha1.StarlightFabricSpec{
			SigningKeys: []v1alpha1.SigningKeySpec{
				{KID: "k1", Algorithm: "ES256", KMSKeyID: "arn:key"},
				{KID: "k1", Algorithm: "RS256", KMSKeyID: "arn:key2"},
			},
		},
	}

	errs := ValidateFabric(fabric)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "duplicate") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected duplicate KID error, got: %v", errs)
	}
}

func TestValidateFabric_InvalidAlgorithm(t *testing.T) {
	fabric := &v1alpha1.StarlightFabric{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: v1alpha1.StarlightFabricSpec{
			SigningKeys: []v1alpha1.SigningKeySpec{
				{KID: "k1", Algorithm: "HMAC", KMSKeyID: "arn:key"},
			},
		},
	}

	errs := ValidateFabric(fabric)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "not supported") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected unsupported algorithm error, got: %v", errs)
	}
}

func TestValidateFabric_DuplicateStreams(t *testing.T) {
	fabric := &v1alpha1.StarlightFabric{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: v1alpha1.StarlightFabricSpec{
			SSFStreams: []v1alpha1.SSFStreamSpec{
				{StreamID: "s1", Transmitter: "https://a.com"},
				{StreamID: "s1", Transmitter: "https://b.com"},
			},
		},
	}

	errs := ValidateFabric(fabric)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "duplicate") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected duplicate stream error, got: %v", errs)
	}
}

func TestValidateFabric_InvalidTransmitterURL(t *testing.T) {
	fabric := &v1alpha1.StarlightFabric{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: v1alpha1.StarlightFabricSpec{
			SSFStreams: []v1alpha1.SSFStreamSpec{
				{StreamID: "s1", Transmitter: "not-a-url"},
			},
		},
	}

	errs := ValidateFabric(fabric)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "not a valid URL") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected invalid URL error, got: %v", errs)
	}
}

func TestValidateFabric_AnchorS3NoBucket(t *testing.T) {
	fabric := &v1alpha1.StarlightFabric{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: v1alpha1.StarlightFabricSpec{
			Anchor: &v1alpha1.AnchorSpec{Type: "s3"},
		},
	}

	errs := ValidateFabric(fabric)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "bucket is required") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected bucket required error, got: %v", errs)
	}
}

func TestValidateFabric_AnchorFilesystemNoPath(t *testing.T) {
	fabric := &v1alpha1.StarlightFabric{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: v1alpha1.StarlightFabricSpec{
			Anchor: &v1alpha1.AnchorSpec{Type: "filesystem"},
		},
	}

	errs := ValidateFabric(fabric)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "path is required") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected path required error, got: %v", errs)
	}
}

func TestValidateFabric_EmptySpec(t *testing.T) {
	fabric := &v1alpha1.StarlightFabric{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec:       v1alpha1.StarlightFabricSpec{},
	}

	errs := ValidateFabric(fabric)
	if len(errs) > 0 {
		t.Errorf("empty spec should be valid, got: %v", errs)
	}
}

func TestValidateFabric_MissingName(t *testing.T) {
	fabric := &v1alpha1.StarlightFabric{
		Spec: v1alpha1.StarlightFabricSpec{},
	}

	errs := ValidateFabric(fabric)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "metadata.name") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected name required error, got: %v", errs)
	}
}

func TestValidateFabric_MissingRequiredFields(t *testing.T) {
	fabric := &v1alpha1.StarlightFabric{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: v1alpha1.StarlightFabricSpec{
			TrustDomains: []v1alpha1.TrustDomainSpec{
				{Name: "td"}, // missing type
			},
			SigningKeys: []v1alpha1.SigningKeySpec{
				{KID: "k1"}, // missing algorithm and kmsKeyId
			},
			SSFStreams: []v1alpha1.SSFStreamSpec{
				{StreamID: "s1"}, // missing transmitter
			},
		},
	}

	errs := ValidateFabric(fabric)
	if len(errs) < 3 {
		t.Errorf("expected at least 3 errors, got %d: %v", len(errs), errs)
	}
}
