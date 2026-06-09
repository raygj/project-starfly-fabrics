package operator

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/starfly-fabrics/starfly/pkg/operator/api/v1alpha1"
	"github.com/starfly-fabrics/starfly/pkg/soul"
)

// FabricReconciler reconciles StarlightFabric custom resources.
type FabricReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	conn          FabricConnection // test hook; production uses embeddedFabricConn
	statusUpdater func(context.Context, *v1alpha1.StarlightFabric) error
}

func (r *FabricReconciler) connection() FabricConnection {
	if r.conn != nil {
		return r.conn
	}
	return embeddedFabricConn
}

// Reconcile is the main reconciliation loop. It reads the CR spec, converts it
// to a soul manifest, calls Converge(), applies the plan, and updates status.
func (r *FabricReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// 1. Fetch the CR.
	var fabric v1alpha1.StarlightFabric
	fabric.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   v1alpha1.GroupName,
		Version: v1alpha1.Version,
		Kind:    "StarlightFabric",
	})
	if err := r.Get(ctx, req.NamespacedName, &fabric); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	return r.ReconcileFabric(ctx, &fabric)
}

// ReconcileFabric runs convergence for a fabric object already loaded from the API.
func (r *FabricReconciler) ReconcileFabric(ctx context.Context, fabric *v1alpha1.StarlightFabric) (ctrl.Result, error) {
	log := slog.With("controller", "StarlightFabric", "namespace", fabric.Namespace, "name", fabric.Name)
	ensureFabricGVK(fabric)

	log.Info("reconciling fabric")

	// 2. Get current state from the running fabric.
	current, err := r.connection().CurrentManifest(ctx)
	if err != nil {
		log.Error("failed to read current manifest", "error", err)
		if statusErr := r.setPhase(ctx, fabric, v1alpha1.PhaseDegraded, "FailedReadManifest", err.Error()); statusErr != nil {
			log.Error("failed to update status", "error", statusErr)
		}
		return ctrl.Result{RequeueAfter: 30 * time.Second}, err
	}

	// 3. Convert spec to desired manifest.
	desired := SpecToManifest(fabric.Name, &fabric.Spec)

	// 4. Converge.
	setDesiredSpecOnConnection(r.connection(), desired)
	plan, err := soul.Converge(current, desired)
	if err != nil {
		log.Error("convergence planning failed", "error", err)
		if statusErr := r.setPhase(ctx, fabric, v1alpha1.PhaseDegraded, "ConvergenceFailed", err.Error()); statusErr != nil {
			log.Error("failed to update status", "error", statusErr)
		}
		return ctrl.Result{RequeueAfter: 30 * time.Second}, err
	}

	// 5. Apply actions via FabricConnection.ApplyPlan (F-001).
	var applyResult *ApplyResult
	if !plan.IsEmpty() {
		log.Info("applying convergence plan", "actions", len(plan.Actions))
		if statusErr := r.setPhase(ctx, fabric, v1alpha1.PhaseConverging, "Converging", fmt.Sprintf("applying %d actions", len(plan.Actions))); statusErr != nil {
			log.Error("failed to update status", "error", statusErr)
		}

		var applyErr error
		applyResult, applyErr = r.connection().ApplyPlan(ctx, plan)
		if applyErr != nil {
			log.Error("convergence apply failed", "error", applyErr)
			if statusErr := r.setPhase(ctx, fabric, v1alpha1.PhaseDegraded, "ApplyFailed", applyErr.Error()); statusErr != nil {
				log.Error("failed to update status", "error", statusErr)
			}
			return ctrl.Result{RequeueAfter: 30 * time.Second}, applyErr
		}
	} else {
		log.Info("no convergence actions needed")
	}

	// 6. Update status.
	health, err := r.connection().Health(ctx)
	if err != nil {
		log.Warn("health check failed after convergence", "error", err)
	}

	if err := r.updateStatus(ctx, fabric, health, applyResult); err != nil {
		log.Error("failed to update status", "error", err)
		return ctrl.Result{RequeueAfter: 10 * time.Second}, err
	}

	log.Info("reconciliation complete")
	return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
}

// SetupWithManager registers the controller with the manager.
func (r *FabricReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.StarlightFabric{}).
		Complete(r)
}

func ensureFabricGVK(fabric *v1alpha1.StarlightFabric) {
	fabric.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   v1alpha1.GroupName,
		Version: v1alpha1.Version,
		Kind:    "StarlightFabric",
	})
}

// setPhase updates the CR phase and sets a condition.
func (r *FabricReconciler) setPhase(ctx context.Context, fabric *v1alpha1.StarlightFabric, phase, reason, message string) error {
	ensureFabricGVK(fabric)
	fabric.Status.Phase = phase
	SetCondition(&fabric.Status, metav1.Condition{
		Type:               conditionForPhase(phase),
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	})
	return r.writeStatus(ctx, fabric)
}

func (r *FabricReconciler) writeStatus(ctx context.Context, fabric *v1alpha1.StarlightFabric) error {
	if r.statusUpdater != nil {
		return r.statusUpdater(ctx, fabric)
	}
	return r.Status().Update(ctx, fabric)
}

// updateStatus sets the final converged status from health data and apply result.
func (r *FabricReconciler) updateStatus(ctx context.Context, fabric *v1alpha1.StarlightFabric, health *HealthStatus, result *ApplyResult) error {
	ensureFabricGVK(fabric)
	now := metav1.Now()
	fabric.Status.Phase = v1alpha1.PhaseConverged
	fabric.Status.LastConvergence = &now

	if health != nil {
		fabric.Status.TrustDomainsActive = health.TrustDomainsActive
		fabric.Status.SigningKeysActive = health.SigningKeysActive
		fabric.Status.SSFStreamsActive = health.SSFStreamsActive
		fabric.Status.SoulSequence = int64(health.SoulSequence)
	}

	// Record convergence duration (F-002).
	if result != nil && result.Duration > 0 {
		fabric.Status.LastConvergenceDuration = result.Duration.String()
	}

	SetCondition(&fabric.Status, metav1.Condition{
		Type:               v1alpha1.ConditionReady,
		Status:             metav1.ConditionTrue,
		LastTransitionTime: now,
		Reason:             "Converged",
		Message:            "fabric state matches spec",
	})
	SetCondition(&fabric.Status, metav1.Condition{
		Type:               v1alpha1.ConditionConverged,
		Status:             metav1.ConditionTrue,
		LastTransitionTime: now,
		Reason:             "Converged",
		Message:            "all convergence actions applied",
	})
	// Clear any lingering Degraded condition from a previous error (F-11).
	SetCondition(&fabric.Status, metav1.Condition{
		Type:               v1alpha1.ConditionDegraded,
		Status:             metav1.ConditionFalse,
		LastTransitionTime: now,
		Reason:             "Converged",
		Message:            "fabric recovered",
	})

	return r.writeStatus(ctx, fabric)
}

// conditionForPhase maps a phase to its primary condition type.
func conditionForPhase(phase string) string {
	switch phase {
	case v1alpha1.PhaseConverging:
		return v1alpha1.ConditionConverged
	case v1alpha1.PhaseDegraded:
		return v1alpha1.ConditionDegraded
	default:
		return v1alpha1.ConditionReady
	}
}
