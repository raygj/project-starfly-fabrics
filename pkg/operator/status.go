package operator

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/starfly-fabrics/starfly/pkg/operator/api/v1alpha1"
)

// SetCondition updates or appends a condition in the status.
// If a condition with the same type already exists, it is replaced.
func SetCondition(status *v1alpha1.StarlightFabricStatus, condition metav1.Condition) {
	for i, existing := range status.Conditions {
		if existing.Type == condition.Type {
			// Only update LastTransitionTime if the status actually changed.
			if existing.Status != condition.Status {
				condition.LastTransitionTime = metav1.Now()
			} else {
				condition.LastTransitionTime = existing.LastTransitionTime
			}
			status.Conditions[i] = condition
			return
		}
	}
	// Condition not found — append.
	if condition.LastTransitionTime.IsZero() {
		condition.LastTransitionTime = metav1.Now()
	}
	status.Conditions = append(status.Conditions, condition)
}

// FindCondition returns the condition with the given type, or nil.
func FindCondition(status *v1alpha1.StarlightFabricStatus, condType string) *metav1.Condition {
	for i := range status.Conditions {
		if status.Conditions[i].Type == condType {
			return &status.Conditions[i]
		}
	}
	return nil
}

// IsReady returns true if the Ready condition is True.
func IsReady(status *v1alpha1.StarlightFabricStatus) bool {
	c := FindCondition(status, v1alpha1.ConditionReady)
	return c != nil && c.Status == metav1.ConditionTrue
}

// IsConverged returns true if the Converged condition is True.
func IsConverged(status *v1alpha1.StarlightFabricStatus) bool {
	c := FindCondition(status, v1alpha1.ConditionConverged)
	return c != nil && c.Status == metav1.ConditionTrue
}
