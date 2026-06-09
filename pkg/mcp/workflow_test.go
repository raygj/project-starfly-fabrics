package mcp

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestWorkflowTracker_SingleTask(t *testing.T) {
	wt := NewWorkflowTracker()
	now := time.Now()

	err := wt.RecordTask("wf-001", "task-001", now, []string{})
	if err != nil {
		t.Fatalf("RecordTask: %v", err)
	}

	if wt.WorkflowSize("wf-001") != 1 {
		t.Errorf("workflow size = %d, want 1", wt.WorkflowSize("wf-001"))
	}

	rec, ok := wt.GetTask("wf-001", "task-001")
	if !ok {
		t.Fatal("task not found")
	}
	if rec.JTI != "task-001" {
		t.Errorf("jti = %q", rec.JTI)
	}
}

func TestWorkflowTracker_LinearChain(t *testing.T) {
	wt := NewWorkflowTracker()
	now := time.Now()

	// task-001 → task-002 → task-003
	if err := wt.RecordTask("wf-001", "task-001", now, []string{}); err != nil {
		t.Fatalf("task-001: %v", err)
	}
	if err := wt.RecordTask("wf-001", "task-002", now.Add(time.Second), []string{"task-001"}); err != nil {
		t.Fatalf("task-002: %v", err)
	}
	if err := wt.RecordTask("wf-001", "task-003", now.Add(2*time.Second), []string{"task-002"}); err != nil {
		t.Fatalf("task-003: %v", err)
	}

	if wt.WorkflowSize("wf-001") != 3 {
		t.Errorf("workflow size = %d, want 3", wt.WorkflowSize("wf-001"))
	}
}

func TestWorkflowTracker_FanOut(t *testing.T) {
	wt := NewWorkflowTracker()
	now := time.Now()

	// task-001 → task-002
	//          → task-003
	if err := wt.RecordTask("wf-001", "task-001", now, []string{}); err != nil {
		t.Fatal(err)
	}
	if err := wt.RecordTask("wf-001", "task-002", now.Add(time.Second), []string{"task-001"}); err != nil {
		t.Fatal(err)
	}
	if err := wt.RecordTask("wf-001", "task-003", now.Add(time.Second), []string{"task-001"}); err != nil {
		t.Fatal(err)
	}

	if wt.WorkflowSize("wf-001") != 3 {
		t.Errorf("size = %d, want 3", wt.WorkflowSize("wf-001"))
	}
}

func TestWorkflowTracker_FanIn(t *testing.T) {
	wt := NewWorkflowTracker()
	now := time.Now()

	// task-001 ─┐
	//           ├→ task-003
	// task-002 ─┘
	if err := wt.RecordTask("wf-001", "task-001", now, []string{}); err != nil {
		t.Fatal(err)
	}
	if err := wt.RecordTask("wf-001", "task-002", now, []string{}); err != nil {
		t.Fatal(err)
	}
	if err := wt.RecordTask("wf-001", "task-003", now.Add(time.Second), []string{"task-001", "task-002"}); err != nil {
		t.Fatal(err)
	}

	rec, ok := wt.GetTask("wf-001", "task-003")
	if !ok {
		t.Fatal("task-003 not found")
	}
	if len(rec.ParentIDs) != 2 {
		t.Errorf("parent count = %d, want 2", len(rec.ParentIDs))
	}
}

func TestWorkflowTracker_DuplicateTaskID(t *testing.T) {
	wt := NewWorkflowTracker()
	now := time.Now()

	_ = wt.RecordTask("wf-001", "task-001", now, []string{})

	err := wt.RecordTask("wf-001", "task-001", now.Add(time.Second), []string{})
	if err == nil {
		t.Fatal("expected duplicate task ID error")
	}
	if !errors.Is(err, ErrDuplicateTaskID) {
		t.Fatalf("error = %v, want ErrDuplicateTaskID", err)
	}
}

func TestWorkflowTracker_ParentNotFound(t *testing.T) {
	wt := NewWorkflowTracker()
	now := time.Now()

	err := wt.RecordTask("wf-001", "task-002", now, []string{"nonexistent-parent"})
	if err == nil {
		t.Fatal("expected parent not found error")
	}
	if !errors.Is(err, ErrParentNotFound) {
		t.Fatalf("error = %v, want ErrParentNotFound", err)
	}
}

func TestWorkflowTracker_TemporalViolation(t *testing.T) {
	wt := NewWorkflowTracker(WithClockSkew(5 * time.Second))
	now := time.Now()

	// Parent issued at now+10min, child at now → violation (parent way after child).
	_ = wt.RecordTask("wf-001", "task-001", now.Add(10*time.Minute), []string{})

	err := wt.RecordTask("wf-001", "task-002", now, []string{"task-001"})
	if err == nil {
		t.Fatal("expected temporal violation error")
	}
	if !errors.Is(err, ErrTemporalViolation) {
		t.Fatalf("error = %v, want ErrTemporalViolation", err)
	}
}

func TestWorkflowTracker_TemporalWithinSkew(t *testing.T) {
	wt := NewWorkflowTracker(WithClockSkew(30 * time.Second))
	now := time.Now()

	// Parent issued 10s after child — within 30s skew tolerance.
	_ = wt.RecordTask("wf-001", "task-001", now.Add(10*time.Second), []string{})

	err := wt.RecordTask("wf-001", "task-002", now, []string{"task-001"})
	if err != nil {
		t.Fatalf("should be within clock skew tolerance: %v", err)
	}
}

func TestWorkflowTracker_GlobalScope(t *testing.T) {
	wt := NewWorkflowTracker()
	now := time.Now()

	// Empty workflow ID → global scope.
	if err := wt.RecordTask("", "task-001", now, []string{}); err != nil {
		t.Fatal(err)
	}
	if err := wt.RecordTask("", "task-002", now.Add(time.Second), []string{"task-001"}); err != nil {
		t.Fatal(err)
	}

	if wt.WorkflowSize("") != 2 {
		t.Errorf("global size = %d, want 2", wt.WorkflowSize(""))
	}

	// Duplicate in global scope.
	err := wt.RecordTask("", "task-001", now.Add(2*time.Second), []string{})
	if !errors.Is(err, ErrDuplicateTaskID) {
		t.Fatalf("expected duplicate in global scope, got %v", err)
	}
}

func TestWorkflowTracker_CrossWorkflowIsolation(t *testing.T) {
	wt := NewWorkflowTracker()
	now := time.Now()

	_ = wt.RecordTask("wf-001", "task-001", now, []string{})

	// Different workflow can't reference wf-001's tasks.
	err := wt.RecordTask("wf-002", "task-002", now.Add(time.Second), []string{"task-001"})
	if !errors.Is(err, ErrParentNotFound) {
		t.Fatalf("expected parent not found across workflows, got %v", err)
	}
}

func TestWorkflowTracker_Cleanup(t *testing.T) {
	wt := NewWorkflowTracker(WithWorkflowTTL(100 * time.Millisecond))
	past := time.Now().Add(-200 * time.Millisecond)

	_ = wt.RecordTask("wf-old", "task-001", past, []string{})
	_ = wt.RecordTask("wf-new", "task-001", time.Now(), []string{})

	if wt.ActiveWorkflows() != 2 {
		t.Fatalf("active = %d, want 2", wt.ActiveWorkflows())
	}

	removed := wt.Cleanup()
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if wt.ActiveWorkflows() != 1 {
		t.Errorf("active after cleanup = %d, want 1", wt.ActiveWorkflows())
	}
}

func TestWorkflowTracker_MultipleRoots(t *testing.T) {
	wt := NewWorkflowTracker()
	now := time.Now()

	// Multiple root tasks (no parents) in same workflow — valid per spec.
	if err := wt.RecordTask("wf-001", "root-a", now, []string{}); err != nil {
		t.Fatal(err)
	}
	if err := wt.RecordTask("wf-001", "root-b", now, []string{}); err != nil {
		t.Fatal(err)
	}
	if err := wt.RecordTask("wf-001", "child", now.Add(time.Second), []string{"root-a", "root-b"}); err != nil {
		t.Fatal(err)
	}

	if wt.WorkflowSize("wf-001") != 3 {
		t.Errorf("size = %d, want 3", wt.WorkflowSize("wf-001"))
	}
}

func TestWorkflowTracker_ConcurrentAccess(t *testing.T) {
	wt := NewWorkflowTracker()
	now := time.Now()

	done := make(chan error, 100)
	for i := 0; i < 100; i++ {
		go func(idx int) {
			wid := "wf-concurrent"
			jti := fmt.Sprintf("task-%03d", idx)
			done <- wt.RecordTask(wid, jti, now.Add(time.Duration(idx)*time.Millisecond), []string{})
		}(i)
	}

	var errs int
	for i := 0; i < 100; i++ {
		if err := <-done; err != nil {
			errs++
		}
	}
	// All should succeed — unique JTIs, no parents required.
	if errs != 0 {
		t.Errorf("got %d errors, expected 0", errs)
	}
	if wt.WorkflowSize("wf-concurrent") != 100 {
		t.Errorf("size = %d, want 100", wt.WorkflowSize("wf-concurrent"))
	}
}
