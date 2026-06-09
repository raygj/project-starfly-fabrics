package operator

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/starfly-fabrics/starfly/pkg/operator/api/v1alpha1"
)

func TestSetCondition_NewCondition(t *testing.T) {
	status := &v1alpha1.StarlightFabricStatus{}

	SetCondition(status, metav1.Condition{
		Type:   v1alpha1.ConditionReady,
		Status: metav1.ConditionTrue,
		Reason: "Test",
	})

	if len(status.Conditions) != 1 {
		t.Fatalf("Conditions count = %d, want 1", len(status.Conditions))
	}
	if status.Conditions[0].Type != v1alpha1.ConditionReady {
		t.Errorf("Type = %q, want %q", status.Conditions[0].Type, v1alpha1.ConditionReady)
	}
	if status.Conditions[0].LastTransitionTime.IsZero() {
		t.Error("LastTransitionTime should be set")
	}
}

func TestSetCondition_ReplaceExisting(t *testing.T) {
	status := &v1alpha1.StarlightFabricStatus{
		Conditions: []metav1.Condition{
			{Type: v1alpha1.ConditionReady, Status: metav1.ConditionFalse, Reason: "Old"},
		},
	}

	SetCondition(status, metav1.Condition{
		Type:   v1alpha1.ConditionReady,
		Status: metav1.ConditionTrue,
		Reason: "New",
	})

	if len(status.Conditions) != 1 {
		t.Fatalf("Conditions count = %d, want 1", len(status.Conditions))
	}
	if status.Conditions[0].Reason != "New" {
		t.Errorf("Reason = %q, want %q", status.Conditions[0].Reason, "New")
	}
}

func TestSetCondition_PreservesTransitionTime(t *testing.T) {
	originalTime := metav1.Now()
	status := &v1alpha1.StarlightFabricStatus{
		Conditions: []metav1.Condition{
			{Type: v1alpha1.ConditionReady, Status: metav1.ConditionTrue, LastTransitionTime: originalTime},
		},
	}

	// Same status — should preserve the original transition time.
	SetCondition(status, metav1.Condition{
		Type:   v1alpha1.ConditionReady,
		Status: metav1.ConditionTrue,
		Reason: "StillReady",
	})

	if !status.Conditions[0].LastTransitionTime.Equal(&originalTime) {
		t.Error("LastTransitionTime should be preserved when status unchanged")
	}
}

func TestFindCondition(t *testing.T) {
	status := &v1alpha1.StarlightFabricStatus{
		Conditions: []metav1.Condition{
			{Type: v1alpha1.ConditionReady, Status: metav1.ConditionTrue},
			{Type: v1alpha1.ConditionConverged, Status: metav1.ConditionFalse},
		},
	}

	c := FindCondition(status, v1alpha1.ConditionConverged)
	if c == nil {
		t.Fatal("FindCondition returned nil for existing condition")
	}
	if c.Status != metav1.ConditionFalse {
		t.Errorf("Status = %q, want %q", c.Status, metav1.ConditionFalse)
	}

	if FindCondition(status, "NonExistent") != nil {
		t.Error("FindCondition should return nil for non-existent condition")
	}
}

func TestIsReady(t *testing.T) {
	ready := &v1alpha1.StarlightFabricStatus{
		Conditions: []metav1.Condition{
			{Type: v1alpha1.ConditionReady, Status: metav1.ConditionTrue},
		},
	}
	if !IsReady(ready) {
		t.Error("IsReady should be true")
	}

	notReady := &v1alpha1.StarlightFabricStatus{
		Conditions: []metav1.Condition{
			{Type: v1alpha1.ConditionReady, Status: metav1.ConditionFalse},
		},
	}
	if IsReady(notReady) {
		t.Error("IsReady should be false")
	}

	empty := &v1alpha1.StarlightFabricStatus{}
	if IsReady(empty) {
		t.Error("IsReady should be false for empty conditions")
	}
}

func TestIsConverged(t *testing.T) {
	converged := &v1alpha1.StarlightFabricStatus{
		Conditions: []metav1.Condition{
			{Type: v1alpha1.ConditionConverged, Status: metav1.ConditionTrue},
		},
	}
	if !IsConverged(converged) {
		t.Error("IsConverged should be true")
	}
}
