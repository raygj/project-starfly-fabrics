package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestDeepCopy_StarlightFabric(t *testing.T) {
	original := &StarlightFabric{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-fabric",
			Namespace: "starfly-system",
		},
		Spec: StarlightFabricSpec{
			TrustDomains: []TrustDomainSpec{
				{Name: "payments.prod", Type: "oidc", Issuer: "https://pay.example.com", Enabled: true},
			},
			SigningKeys: []SigningKeySpec{
				{KID: "key-001", Algorithm: "ES256", KMSKeyID: "arn:key", Status: "active"},
			},
			SSFStreams: []SSFStreamSpec{
				{StreamID: "s1", Transmitter: "https://ssf.example.com", EventsRequested: []string{"credential-revoked"}},
			},
			Anchor: &AnchorSpec{Type: "s3", Bucket: "my-bucket"},
			Policy: &PolicySpec{BundlePath: "policies/prod"},
		},
		Status: StarlightFabricStatus{
			Phase:              PhaseConverged,
			SoulSequence:       42,
			TrustDomainsActive: 1,
			Conditions: []metav1.Condition{
				{Type: ConditionReady, Status: metav1.ConditionTrue},
			},
		},
	}

	copied := original.DeepCopy()

	// Verify independent copies.
	if copied.Name != original.Name {
		t.Errorf("Name = %q, want %q", copied.Name, original.Name)
	}

	// Mutate original — copy should be unaffected.
	original.Spec.TrustDomains[0].Name = "MUTATED"
	if copied.Spec.TrustDomains[0].Name == "MUTATED" {
		t.Error("TrustDomains not deep copied")
	}

	original.Spec.SSFStreams[0].EventsRequested[0] = "MUTATED"
	if copied.Spec.SSFStreams[0].EventsRequested[0] == "MUTATED" {
		t.Error("SSFStreams.EventsRequested not deep copied")
	}

	original.Spec.Anchor.Bucket = "MUTATED"
	if copied.Spec.Anchor.Bucket == "MUTATED" {
		t.Error("Anchor not deep copied")
	}

	original.Status.Conditions[0].Type = "MUTATED"
	if copied.Status.Conditions[0].Type == "MUTATED" {
		t.Error("Status.Conditions not deep copied")
	}
}

func TestDeepCopy_Nil(t *testing.T) {
	var f *StarlightFabric
	if f.DeepCopy() != nil {
		t.Error("DeepCopy of nil should return nil")
	}

	var spec *StarlightFabricSpec
	if spec.DeepCopy() != nil {
		t.Error("DeepCopy of nil spec should return nil")
	}

	var status *StarlightFabricStatus
	if status.DeepCopy() != nil {
		t.Error("DeepCopy of nil status should return nil")
	}

	var list *StarlightFabricList
	if list.DeepCopy() != nil {
		t.Error("DeepCopy of nil list should return nil")
	}
}

func TestDeepCopyObject(t *testing.T) {
	f := &StarlightFabric{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
	}

	obj := f.DeepCopyObject()
	if _, ok := obj.(*StarlightFabric); !ok {
		t.Error("DeepCopyObject should return *StarlightFabric")
	}
}

func TestDeepCopy_List(t *testing.T) {
	list := &StarlightFabricList{
		Items: []StarlightFabric{
			{ObjectMeta: metav1.ObjectMeta{Name: "a"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "b"}},
		},
	}

	copied := list.DeepCopy()
	if len(copied.Items) != 2 {
		t.Fatalf("Items count = %d, want 2", len(copied.Items))
	}

	list.Items[0].Name = "MUTATED"
	if copied.Items[0].Name == "MUTATED" {
		t.Error("List items not deep copied")
	}
}

func TestSchemeGroupVersion(t *testing.T) {
	if SchemeGroupVersion.Group != GroupName {
		t.Errorf("Group = %q, want %q", SchemeGroupVersion.Group, GroupName)
	}
	if SchemeGroupVersion.Version != Version {
		t.Errorf("Version = %q, want %q", SchemeGroupVersion.Version, Version)
	}
}

func TestDeepCopy_WithFederation(t *testing.T) {
	original := &StarlightFabric{
		ObjectMeta: metav1.ObjectMeta{Name: "fed-fabric"},
		Spec: StarlightFabricSpec{
			Federation: &FederationSpec{
				Peers: []FederationPeerSpec{
					{FabricID: "peer-eu", JWKSEndpoint: "https://eu.example.com/jwks"},
					{FabricID: "peer-us", JWKSEndpoint: "https://us.example.com/jwks"},
				},
			},
		},
	}

	copied := original.DeepCopy()
	if copied.Spec.Federation == nil {
		t.Fatal("Federation should be deep copied")
	}
	if len(copied.Spec.Federation.Peers) != 2 {
		t.Fatalf("Peers count = %d, want 2", len(copied.Spec.Federation.Peers))
	}

	original.Spec.Federation.Peers[0].FabricID = "MUTATED"
	if copied.Spec.Federation.Peers[0].FabricID == "MUTATED" {
		t.Error("Federation peers not deep copied")
	}
}

func TestDeepCopy_StatusWithLastConvergence(t *testing.T) {
	now := metav1.Now()
	original := &StarlightFabricStatus{
		Phase:           PhaseConverged,
		SoulSequence:    10,
		LastConvergence: &now,
		Conditions: []metav1.Condition{
			{Type: ConditionReady, Status: metav1.ConditionTrue},
		},
	}

	copied := original.DeepCopy()
	if copied.LastConvergence == nil {
		t.Fatal("LastConvergence should be deep copied")
	}
	if copied.Phase != PhaseConverged {
		t.Errorf("Phase = %q, want %q", copied.Phase, PhaseConverged)
	}
}

func TestDeepCopyObject_List(t *testing.T) {
	list := &StarlightFabricList{
		Items: []StarlightFabric{
			{ObjectMeta: metav1.ObjectMeta{Name: "a"}},
		},
	}

	obj := list.DeepCopyObject()
	if _, ok := obj.(*StarlightFabricList); !ok {
		t.Error("DeepCopyObject should return *StarlightFabricList")
	}
}

func TestAddToScheme(t *testing.T) {
	s := runtime.NewScheme()
	if err := AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme error: %v", err)
	}

	gvk := schema.GroupVersionKind{Group: GroupName, Version: Version, Kind: "StarlightFabric"}
	obj, err := s.New(gvk)
	if err != nil {
		t.Fatalf("scheme does not recognize StarlightFabric: %v", err)
	}
	if _, ok := obj.(*StarlightFabric); !ok {
		t.Errorf("expected *StarlightFabric, got %T", obj)
	}
}

func TestFederationSpec_DeepCopyInto_Nil(t *testing.T) {
	in := &FederationSpec{}
	out := &FederationSpec{}
	in.DeepCopyInto(out)
	if out.Peers != nil {
		t.Error("DeepCopyInto of empty FederationSpec should have nil peers")
	}
}

func TestResource(t *testing.T) {
	gr := Resource("starlightfabrics")
	if gr.Group != GroupName {
		t.Errorf("Group = %q, want %q", gr.Group, GroupName)
	}
	if gr.Resource != "starlightfabrics" {
		t.Errorf("Resource = %q, want %q", gr.Resource, "starlightfabrics")
	}
}
