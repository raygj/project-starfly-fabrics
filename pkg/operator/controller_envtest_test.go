//go:build operator_pressure

package operator

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	v1alpha1 "github.com/starfly-fabrics/starfly/pkg/operator/api/v1alpha1"
	"github.com/starfly-fabrics/starfly/pkg/soul"
)

var (
	envtestClient client.Client
	envtestScheme *runtime.Scheme
)

func TestMain(m *testing.M) {
	_, thisFile, _, _ := goruntime.Caller(0)
	crdPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "deploy", "helm", "crds")
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{crdPath},
		ErrorIfCRDPathMissing: true,
	}
	if assets := os.Getenv("KUBEBUILDER_ASSETS"); assets != "" {
		env.BinaryAssetsDirectory = assets
	}

	cfg, err := env.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "envtest start: %v\n", err)
		os.Exit(1)
	}

	envtestScheme = runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(envtestScheme))
	utilruntime.Must(v1alpha1.AddToScheme(envtestScheme))

	envtestClient, err = client.New(cfg, client.Options{Scheme: envtestScheme})
	if err != nil {
		fmt.Fprintf(os.Stderr, "envtest client: %v\n", err)
		_ = env.Stop()
		os.Exit(1)
	}

	code := m.Run()

	if err := env.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "envtest stop: %v\n", err)
	}
	os.Exit(code)
}

func envtestReconciler(t *testing.T, conn FabricConnection) *FabricReconciler {
	t.Helper()
	return &FabricReconciler{
		Client: envtestClient,
		Scheme: envtestScheme,
		conn:   conn,
	}
}

func createEnvtestFabric(t *testing.T, name string) *v1alpha1.StarlightFabric {
	t.Helper()
	ctx := context.Background()
	fabric := newTestFabric(name, "default")
	ensureFabricGVK(fabric)
	fabric.TypeMeta = metav1.TypeMeta{
		APIVersion: v1alpha1.GroupName + "/" + v1alpha1.Version,
		Kind:       "StarlightFabric",
	}
	if err := envtestClient.Create(ctx, fabric); err != nil {
		t.Fatalf("create fabric: %v", err)
	}
	t.Cleanup(func() {
		_ = envtestClient.Delete(context.Background(), fabric)
	})
	return fabric
}

func getEnvtestFabric(t *testing.T, name string) v1alpha1.StarlightFabric {
	t.Helper()
	var got v1alpha1.StarlightFabric
	if err := envtestClient.Get(context.Background(), types.NamespacedName{Name: name, Namespace: "default"}, &got); err != nil {
		t.Fatalf("get fabric: %v", err)
	}
	return got
}

func TestEnvtest_Reconcile_NewFabric_Converges(t *testing.T) {
	fabric := createEnvtestFabric(t, "env-new-fabric")
	conn := &mockConnection{
		manifest: soul.NewManifest(fabric.Name, 1),
		health: &HealthStatus{
			Healthy:            true,
			TrustDomainsActive: 1,
			SigningKeysActive:  1,
			SoulSequence:       2,
		},
	}
	r := envtestReconciler(t, conn)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: fabric.Name, Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile() error: %v", err)
	}

	got := getEnvtestFabric(t, fabric.Name)
	if got.Status.Phase != v1alpha1.PhaseConverged {
		t.Fatalf("phase = %q, want Converged", got.Status.Phase)
	}
	if got.Status.SoulSequence != 2 {
		t.Fatalf("soulSequence = %d, want 2", got.Status.SoulSequence)
	}
	if got.Status.TrustDomainsActive != 1 {
		t.Fatalf("trustDomainsActive = %d, want 1", got.Status.TrustDomainsActive)
	}
}

func TestEnvtest_Reconcile_ApplyFailure_DegradedThenRecover(t *testing.T) {
	fabric := createEnvtestFabric(t, "env-degraded-fabric")
	conn := &mockConnection{
		manifest: soul.NewManifest(fabric.Name, 1),
		health:   &HealthStatus{Healthy: true, SoulSequence: 1},
		failOn:   soul.ActionAddTrustDomain,
	}
	r := envtestReconciler(t, conn)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: fabric.Name, Namespace: "default"},
	})
	if err == nil {
		t.Fatal("expected apply failure")
	}

	got := getEnvtestFabric(t, fabric.Name)
	if got.Status.Phase != v1alpha1.PhaseDegraded {
		t.Fatalf("phase = %q, want Degraded", got.Status.Phase)
	}

	conn.failOn = ""
	conn.health = &HealthStatus{
		Healthy:            true,
		TrustDomainsActive: 1,
		SigningKeysActive:  1,
		SoulSequence:       3,
	}

	_, err = r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: fabric.Name, Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("recovery Reconcile() error: %v", err)
	}

	got = getEnvtestFabric(t, fabric.Name)
	if got.Status.Phase != v1alpha1.PhaseConverged {
		t.Fatalf("after recovery phase = %q, want Converged", got.Status.Phase)
	}
}

func TestEnvtest_Reconcile_EmptyPlan_ConvergedNoSideEffects(t *testing.T) {
	fabric := createEnvtestFabric(t, "env-empty-plan")
	current := SpecToManifest(fabric.Name, &fabric.Spec)
	current.Metadata.Sequence = 10

	conn := &mockConnection{
		manifest: current,
		health: &HealthStatus{
			Healthy:            true,
			TrustDomainsActive: 1,
			SigningKeysActive:  1,
			SoulSequence:       10,
		},
	}
	r := envtestReconciler(t, conn)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: fabric.Name, Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile() error: %v", err)
	}

	for _, a := range conn.applied {
		if a.Type != soul.ActionImportRevocations && a.Type != soul.ActionResetRevocations {
			t.Fatalf("unexpected side-effect action: %s", a.Type)
		}
	}

	got := getEnvtestFabric(t, fabric.Name)
	if got.Status.Phase != v1alpha1.PhaseConverged {
		t.Fatalf("phase = %q, want Converged", got.Status.Phase)
	}
}

func TestEnvtest_Reconcile_StatusConditions(t *testing.T) {
	fabric := createEnvtestFabric(t, "env-conditions")
	conn := &mockConnection{
		manifest: soul.NewManifest(fabric.Name, 1),
		health: &HealthStatus{
			Healthy:            true,
			TrustDomainsActive: 1,
			SigningKeysActive:  1,
			SoulSequence:       4,
		},
	}
	r := envtestReconciler(t, conn)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: fabric.Name, Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile() error: %v", err)
	}

	got := getEnvtestFabric(t, fabric.Name)
	if !conditionTrue(got.Status.Conditions, v1alpha1.ConditionConverged) {
		t.Fatal("expected Converged condition True")
	}
	if !conditionTrue(got.Status.Conditions, v1alpha1.ConditionReady) {
		t.Fatal("expected Ready condition True")
	}
	if got.Status.LastConvergence == nil {
		t.Fatal("expected lastConvergence timestamp")
	}
}

func TestEnvtest_Reconcile_Stability10x(t *testing.T) {
	for i := 0; i < 10; i++ {
		t.Run(fmt.Sprintf("run-%d", i), func(t *testing.T) {
			name := fmt.Sprintf("env-stable-%d", i)
			fabric := createEnvtestFabric(t, name)
			conn := &mockConnection{
				manifest: soul.NewManifest(fabric.Name, 1),
				health: &HealthStatus{
					Healthy:            true,
					TrustDomainsActive: 1,
					SigningKeysActive:  1,
					SoulSequence:       uint64(i + 1),
				},
			}
			r := envtestReconciler(t, conn)

			_, err := r.Reconcile(context.Background(), ctrl.Request{
				NamespacedName: types.NamespacedName{Name: fabric.Name, Namespace: "default"},
			})
			if err != nil {
				t.Fatalf("Reconcile() error: %v", err)
			}

			got := getEnvtestFabric(t, fabric.Name)
			if got.Status.Phase != v1alpha1.PhaseConverged {
				t.Fatalf("phase = %q, want Converged", got.Status.Phase)
			}
		})
	}
}

func conditionTrue(conditions []metav1.Condition, condType string) bool {
	for _, c := range conditions {
		if c.Type == condType && c.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}
