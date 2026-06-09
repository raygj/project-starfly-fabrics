package operator

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/starfly-fabrics/starfly/pkg/operator/api/v1alpha1"
	"github.com/starfly-fabrics/starfly/pkg/soul"
)

type mockErrConnection struct {
	manifestErr error
}

func (m *mockErrConnection) CurrentManifest(_ context.Context) (*soul.SoulManifest, error) {
	return nil, m.manifestErr
}

func (m *mockErrConnection) ApplyAction(_ context.Context, _ soul.ConvergenceAction) error {
	return nil
}

func (m *mockErrConnection) ApplyPlan(ctx context.Context, plan *soul.ConvergencePlan) (*ApplyResult, error) {
	return ExecutePlan(ctx, m, plan)
}

func (m *mockErrConnection) Health(_ context.Context) (*HealthStatus, error) {
	return &HealthStatus{Healthy: true}, nil
}

func init() {
	_ = v1alpha1.AddToScheme(scheme.Scheme)
}

func newTestFabric(name, ns string) *v1alpha1.StarlightFabric {
	return &v1alpha1.StarlightFabric{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: v1alpha1.StarlightFabricSpec{
			TrustDomains: []v1alpha1.TrustDomainSpec{
				{Name: "payments.prod", Type: "oidc", Issuer: "https://pay.example.com", Enabled: true},
			},
			SigningKeys: []v1alpha1.SigningKeySpec{
				{KID: "key-001", Algorithm: "ES256", KMSKeyID: "arn:key", Status: "active"},
			},
		},
	}
}

func TestReconcile_NewFabric(t *testing.T) {
	fabric := newTestFabric("test-fabric", "default")

	c := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(fabric).
		WithStatusSubresource(fabric).
		Build()

	conn := &mockConnection{
		manifest: soul.NewManifest("test-fabric", 1),
		health: &HealthStatus{
			Healthy:            true,
			TrustDomainsActive: 1,
			SigningKeysActive:  1,
			SoulSequence:       2,
		},
	}
	conn.manifest.Identity.SigningKeys = []soul.SigningKeyRef{
		{KID: "key-001", Algorithm: "ES256", KMSKeyID: "arn:key", Status: "active"},
	}

	r := &FabricReconciler{
		Client:     c,
		Scheme:     scheme.Scheme,
		conn: conn,
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-fabric", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile() error: %v", err)
	}
	if result.RequeueAfter == 0 {
		t.Error("expected requeue")
	}

	// Verify convergence actions were applied (add trust domain).
	found := false
	for _, a := range conn.applied {
		if a.Type == soul.ActionAddTrustDomain {
			found = true
		}
	}
	if !found {
		t.Error("expected AddTrustDomain action to be applied")
	}
}

func TestReconcile_NotFound(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		Build()

	conn := &mockConnection{}
	r := &FabricReconciler{
		Client:     c,
		Scheme:     scheme.Scheme,
		conn: conn,
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "nonexistent", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile() error for not found: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Error("should not requeue for not found")
	}
}

func TestReconcile_ConvergedNoActions(t *testing.T) {
	fabric := newTestFabric("test-fabric", "default")

	c := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(fabric).
		WithStatusSubresource(fabric).
		Build()

	// Current manifest matches spec exactly.
	current := SpecToManifest("test-fabric", &fabric.Spec)
	current.Metadata.Sequence = 5

	conn := &mockConnection{
		manifest: current,
		health: &HealthStatus{
			Healthy:            true,
			TrustDomainsActive: 1,
			SigningKeysActive:  1,
			SoulSequence:       5,
		},
	}

	r := &FabricReconciler{
		Client:     c,
		Scheme:     scheme.Scheme,
		conn: conn,
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-fabric", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile() error: %v", err)
	}
	if result.RequeueAfter == 0 {
		t.Error("expected periodic requeue even when converged")
	}

	// No convergence actions should be applied (revocations import is expected).
	for _, a := range conn.applied {
		if a.Type != soul.ActionImportRevocations && a.Type != soul.ActionResetRevocations {
			t.Errorf("unexpected action applied: %s", a.Type)
		}
	}
}

func TestReconcile_UpdateTrustDomain(t *testing.T) {
	fabric := newTestFabric("test-fabric", "default")
	// Add a second trust domain to the spec.
	fabric.Spec.TrustDomains = append(fabric.Spec.TrustDomains, v1alpha1.TrustDomainSpec{
		Name: "analytics.int", Type: "spiffe", Issuer: "spiffe://analytics.internal", Enabled: true,
	})

	c := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(fabric).
		WithStatusSubresource(fabric).
		Build()

	// Current has only payments.prod.
	current := soul.NewManifest("test-fabric", 5)
	current.Identity.SigningKeys = []soul.SigningKeyRef{
		{KID: "key-001", Algorithm: "ES256", KMSKeyID: "arn:key", Status: "active"},
	}
	current.TrustDomains = []soul.TrustDomainSpec{
		{Name: "payments.prod", Type: "oidc", Issuer: "https://pay.example.com", Enabled: true},
	}

	conn := &mockConnection{
		manifest: current,
		health: &HealthStatus{
			Healthy:            true,
			TrustDomainsActive: 2,
			SigningKeysActive:  1,
			SoulSequence:       6,
		},
	}

	r := &FabricReconciler{
		Client:     c,
		Scheme:     scheme.Scheme,
		conn: conn,
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-fabric", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile() error: %v", err)
	}

	// Should add analytics.int trust domain.
	found := false
	for _, a := range conn.applied {
		if a.Type == soul.ActionAddTrustDomain && a.Target == "analytics.int" {
			found = true
		}
	}
	if !found {
		t.Error("expected AddTrustDomain for analytics.int")
	}
}

func TestReconcile_RotateKey(t *testing.T) {
	fabric := newTestFabric("test-fabric", "default")
	// Spec has a new key.
	fabric.Spec.SigningKeys = append(fabric.Spec.SigningKeys, v1alpha1.SigningKeySpec{
		KID: "key-002", Algorithm: "ES256", KMSKeyID: "arn:key2", Status: "active",
	})

	c := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(fabric).
		WithStatusSubresource(fabric).
		Build()

	current := soul.NewManifest("test-fabric", 5)
	current.Identity.SigningKeys = []soul.SigningKeyRef{
		{KID: "key-001", Algorithm: "ES256", KMSKeyID: "arn:key", Status: "active"},
	}
	current.TrustDomains = []soul.TrustDomainSpec{
		{Name: "payments.prod", Type: "oidc", Issuer: "https://pay.example.com", Enabled: true},
	}

	conn := &mockConnection{
		manifest: current,
		health:   &HealthStatus{Healthy: true, SoulSequence: 6},
	}

	r := &FabricReconciler{
		Client:     c,
		Scheme:     scheme.Scheme,
		conn: conn,
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-fabric", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile() error: %v", err)
	}

	// Should rotate (add) key-002.
	found := false
	for _, a := range conn.applied {
		if a.Type == soul.ActionRotateSigningKey && a.Target == "key-002" {
			found = true
		}
	}
	if !found {
		t.Error("expected RotateSigningKey for key-002")
	}
}

func TestReconcile_RemoveTrustDomain(t *testing.T) {
	fabric := newTestFabric("test-fabric", "default")
	// Spec has only payments.prod.

	c := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(fabric).
		WithStatusSubresource(fabric).
		Build()

	// Current has payments.prod AND legacy.old.
	current := soul.NewManifest("test-fabric", 5)
	current.Identity.SigningKeys = []soul.SigningKeyRef{
		{KID: "key-001", Algorithm: "ES256", KMSKeyID: "arn:key", Status: "active"},
	}
	current.TrustDomains = []soul.TrustDomainSpec{
		{Name: "payments.prod", Type: "oidc", Issuer: "https://pay.example.com", Enabled: true},
		{Name: "legacy.old", Type: "oidc", Issuer: "https://legacy.example.com", Enabled: true},
	}

	conn := &mockConnection{
		manifest: current,
		health:   &HealthStatus{Healthy: true, SoulSequence: 6},
	}

	r := &FabricReconciler{
		Client:     c,
		Scheme:     scheme.Scheme,
		conn: conn,
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-fabric", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile() error: %v", err)
	}

	// Should remove legacy.old.
	found := false
	for _, a := range conn.applied {
		if a.Type == soul.ActionRemoveTrustDomain && a.Target == "legacy.old" {
			found = true
		}
	}
	if !found {
		t.Error("expected RemoveTrustDomain for legacy.old")
	}
}

func TestConditionForPhase(t *testing.T) {
	tests := []struct {
		phase string
		want  string
	}{
		{v1alpha1.PhaseConverging, v1alpha1.ConditionConverged},
		{v1alpha1.PhaseDegraded, v1alpha1.ConditionDegraded},
		{v1alpha1.PhaseConverged, v1alpha1.ConditionReady},
		{"Unknown", v1alpha1.ConditionReady},
	}
	for _, tc := range tests {
		got := conditionForPhase(tc.phase)
		if got != tc.want {
			t.Errorf("conditionForPhase(%q) = %q, want %q", tc.phase, got, tc.want)
		}
	}
}

func TestReconcile_ManifestReadError(t *testing.T) {
	fabric := newTestFabric("test-fabric", "default")

	c := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(fabric).
		WithStatusSubresource(fabric).
		Build()

	conn := &mockErrConnection{manifestErr: errors.New("keeper unavailable")}

	r := &FabricReconciler{
		Client:     c,
		Scheme:     scheme.Scheme,
		conn: conn,
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-fabric", Namespace: "default"},
	})
	if err == nil {
		t.Fatal("expected error when manifest read fails")
	}
}

func TestReconcile_ApplyError(t *testing.T) {
	fabric := newTestFabric("test-fabric", "default")

	c := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(fabric).
		WithStatusSubresource(fabric).
		Build()

	conn := &mockConnection{
		manifest: soul.NewManifest("test-fabric", 1),
		failOn:   soul.ActionAddTrustDomain,
		health:   &HealthStatus{Healthy: true},
	}

	r := &FabricReconciler{
		Client:     c,
		Scheme:     scheme.Scheme,
		conn: conn,
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-fabric", Namespace: "default"},
	})
	if err == nil {
		t.Fatal("expected error when apply fails")
	}
}

func TestReconcile_SSFStreamAddRemove(t *testing.T) {
	fabric := newTestFabric("test-fabric", "default")
	fabric.Spec.SSFStreams = []v1alpha1.SSFStreamSpec{
		{StreamID: "stream-new", Transmitter: "https://new.example.com"},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(fabric).
		WithStatusSubresource(fabric).
		Build()

	current := soul.NewManifest("test-fabric", 5)
	current.Identity.SigningKeys = []soul.SigningKeyRef{
		{KID: "key-001", Algorithm: "ES256", KMSKeyID: "arn:key", Status: "active"},
	}
	current.TrustDomains = []soul.TrustDomainSpec{
		{Name: "payments.prod", Type: "oidc", Issuer: "https://pay.example.com", Enabled: true},
	}
	current.SSFStreams = []soul.SSFStreamSpec{
		{StreamID: "stream-old", Transmitter: "https://old.example.com"},
	}

	conn := &mockConnection{
		manifest: current,
		health:   &HealthStatus{Healthy: true, SoulSequence: 6},
	}

	r := &FabricReconciler{
		Client:     c,
		Scheme:     scheme.Scheme,
		conn: conn,
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-fabric", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile() error: %v", err)
	}

	var addFound, removeFound bool
	for _, a := range conn.applied {
		if a.Type == soul.ActionAddSSFStream && a.Target == "stream-new" {
			addFound = true
		}
		if a.Type == soul.ActionRemoveSSFStream && a.Target == "stream-old" {
			removeFound = true
		}
	}
	if !addFound {
		t.Error("expected AddSSFStream for stream-new")
	}
	if !removeFound {
		t.Error("expected RemoveSSFStream for stream-old")
	}
}
