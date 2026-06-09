package operator

import (
	"context"
	"errors"
	"testing"

	"github.com/starfly-fabrics/starfly/pkg/soul"
)

type mockConnection struct {
	manifest *soul.SoulManifest
	health   *HealthStatus
	applied  []soul.ConvergenceAction
	failOn   soul.ActionType // simulate failure on this action type
}

func (m *mockConnection) CurrentManifest(_ context.Context) (*soul.SoulManifest, error) {
	return m.manifest, nil
}

func (m *mockConnection) ApplyAction(_ context.Context, action soul.ConvergenceAction) error {
	if m.failOn == action.Type {
		return errors.New("simulated failure")
	}
	m.applied = append(m.applied, action)
	return nil
}

func (m *mockConnection) ApplyPlan(ctx context.Context, plan *soul.ConvergencePlan) (*ApplyResult, error) {
	return ExecutePlan(ctx, m, plan)
}

func (m *mockConnection) Health(_ context.Context) (*HealthStatus, error) {
	return m.health, nil
}

func TestExecutePlan_Empty(t *testing.T) {
	conn := &mockConnection{}
	plan := &soul.ConvergencePlan{}

	result, err := ExecutePlan(context.Background(), conn, plan)
	if err != nil {
		t.Fatalf("ExecutePlan() error: %v", err)
	}
	if result.ActionsApplied != 0 {
		t.Errorf("applied %d actions, want 0", result.ActionsApplied)
	}
}

func TestExecutePlan_OrderedExecution(t *testing.T) {
	conn := &mockConnection{}
	plan := &soul.ConvergencePlan{
		Actions: []soul.ConvergenceAction{
			{Type: soul.ActionAddSSFStream, Target: "s1"},
			{Type: soul.ActionAddTrustDomain, Target: "td1"},
			{Type: soul.ActionRotateSigningKey, Target: "k1"},
			{Type: soul.ActionImportRevocations},
		},
	}

	result, err := ExecutePlan(context.Background(), conn, plan)
	if err != nil {
		t.Fatalf("ExecutePlan() error: %v", err)
	}

	if result.ActionsApplied != 4 {
		t.Fatalf("applied %d actions, want 4", result.ActionsApplied)
	}
	if result.Duration == 0 {
		t.Error("Duration should be non-zero")
	}

	// Verify ordering: keys → domains → streams → revocations.
	expectedOrder := []soul.ActionType{
		soul.ActionRotateSigningKey,
		soul.ActionAddTrustDomain,
		soul.ActionAddSSFStream,
		soul.ActionImportRevocations,
	}
	for i, want := range expectedOrder {
		if conn.applied[i].Type != want {
			t.Errorf("applied[%d].Type = %q, want %q", i, conn.applied[i].Type, want)
		}
	}
}

func TestExecutePlan_FailureStopsExecution(t *testing.T) {
	conn := &mockConnection{failOn: soul.ActionAddTrustDomain}
	plan := &soul.ConvergencePlan{
		Actions: []soul.ConvergenceAction{
			{Type: soul.ActionRotateSigningKey, Target: "k1"},
			{Type: soul.ActionAddTrustDomain, Target: "td1"},
			{Type: soul.ActionAddSSFStream, Target: "s1"},
		},
	}

	result, err := ExecutePlan(context.Background(), conn, plan)
	if err == nil {
		t.Fatal("ExecutePlan() should return error on failure")
	}

	if result.ActionsApplied != 1 {
		t.Errorf("applied %d actions before failure, want 1", result.ActionsApplied)
	}
	if result.ActionsTotal != 3 {
		t.Errorf("total = %d, want 3", result.ActionsTotal)
	}
	if result.Duration == 0 {
		t.Error("Duration should be non-zero even on failure")
	}
}

func TestExecutePlan_ReturnsResult(t *testing.T) {
	conn := &mockConnection{}
	plan := &soul.ConvergencePlan{
		Actions: []soul.ConvergenceAction{
			{Type: soul.ActionAddTrustDomain, Target: "td1"},
			{Type: soul.ActionAddTrustDomain, Target: "td2"},
		},
	}

	result, err := ExecutePlan(context.Background(), conn, plan)
	if err != nil {
		t.Fatalf("ExecutePlan() error: %v", err)
	}

	if result.ActionsApplied != 2 {
		t.Errorf("ActionsApplied = %d, want 2", result.ActionsApplied)
	}
	if result.ActionsTotal != 2 {
		t.Errorf("ActionsTotal = %d, want 2", result.ActionsTotal)
	}
}

func TestSortActions_AllTypes(t *testing.T) {
	actions := []soul.ConvergenceAction{
		{Type: soul.ActionResetRevocations},
		{Type: soul.ActionRemoveSSFStream, Target: "s2"},
		{Type: soul.ActionUpdateTrustDomain, Target: "td2"},
		{Type: soul.ActionAddSSFStream, Target: "s1"},
		{Type: soul.ActionRemoveTrustDomain, Target: "td3"},
		{Type: soul.ActionRotateSigningKey, Target: "k1"},
		{Type: soul.ActionAddTrustDomain, Target: "td1"},
	}

	sorted := sortActions(actions)

	if len(sorted) != len(actions) {
		t.Fatalf("sorted length = %d, want %d", len(sorted), len(actions))
	}

	// First: signing keys.
	if sorted[0].Type != soul.ActionRotateSigningKey {
		t.Errorf("sorted[0] = %q, want signing key", sorted[0].Type)
	}

	// Then: trust domains (3 actions).
	for i := 1; i <= 3; i++ {
		switch sorted[i].Type {
		case soul.ActionAddTrustDomain, soul.ActionUpdateTrustDomain, soul.ActionRemoveTrustDomain:
			// ok
		default:
			t.Errorf("sorted[%d] = %q, want trust domain action", i, sorted[i].Type)
		}
	}

	// Then: SSF streams (2 actions).
	for i := 4; i <= 5; i++ {
		switch sorted[i].Type {
		case soul.ActionAddSSFStream, soul.ActionRemoveSSFStream:
			// ok
		default:
			t.Errorf("sorted[%d] = %q, want SSF stream action", i, sorted[i].Type)
		}
	}

	// Last: revocations.
	if sorted[6].Type != soul.ActionResetRevocations {
		t.Errorf("sorted[6] = %q, want revocations", sorted[6].Type)
	}
}
