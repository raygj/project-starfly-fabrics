package mcp

import (
	"fmt"
	"sync"
	"time"
)

// DAG validation errors per draft-nennemann-wimse-ect-00 Section 5.
var (
	ErrDuplicateTaskID   = fmt.Errorf("ect: duplicate task ID within workflow")
	ErrParentNotFound    = fmt.Errorf("ect: parent task not found")
	ErrTemporalViolation = fmt.Errorf("ect: parent issued after child (temporal ordering)")
	ErrCycleDetected     = fmt.Errorf("ect: cycle detected in DAG")
)

// DefaultWorkflowTTL is how long inactive workflows are retained before cleanup.
const DefaultWorkflowTTL = 1 * time.Hour

// DefaultClockSkew is the tolerance for temporal ordering checks.
const DefaultClockSkew = 30 * time.Second

// MaxAncestorTraversal is the DAG depth limit to prevent DoS (spec recommends 10000).
const MaxAncestorTraversal = 10000

// TaskRecord is a recorded ECT within a workflow.
type TaskRecord struct {
	JTI       string
	IssuedAt  time.Time
	ParentIDs []string
}

// Workflow tracks the ECT DAG for a single workflow instance.
type Workflow struct {
	ID        string
	Tasks     map[string]*TaskRecord // keyed by jti
	CreatedAt time.Time
	UpdatedAt time.Time
}

// WorkflowTracker manages active workflows and validates DAG constraints.
// Safe for concurrent use.
type WorkflowTracker struct {
	mu        sync.RWMutex
	workflows map[string]*Workflow
	ttl       time.Duration
	clockSkew time.Duration

	// globalTasks tracks task IDs when no wid is present (global scope).
	globalTasks map[string]*TaskRecord
}

// WorkflowTrackerOption configures the tracker.
type WorkflowTrackerOption func(*WorkflowTracker)

// WithWorkflowTTL sets the workflow expiry duration.
func WithWorkflowTTL(ttl time.Duration) WorkflowTrackerOption {
	return func(wt *WorkflowTracker) { wt.ttl = ttl }
}

// WithClockSkew sets the temporal ordering tolerance.
func WithClockSkew(skew time.Duration) WorkflowTrackerOption {
	return func(wt *WorkflowTracker) { wt.clockSkew = skew }
}

// NewWorkflowTracker creates a workflow tracker with the given options.
func NewWorkflowTracker(opts ...WorkflowTrackerOption) *WorkflowTracker {
	wt := &WorkflowTracker{
		workflows:   make(map[string]*Workflow),
		globalTasks: make(map[string]*TaskRecord),
		ttl:         DefaultWorkflowTTL,
		clockSkew:   DefaultClockSkew,
	}
	for _, o := range opts {
		o(wt)
	}
	return wt
}

// RecordTask validates DAG constraints and records a task ECT.
// If workflowID is empty, the task is tracked in the global scope.
func (wt *WorkflowTracker) RecordTask(workflowID, jti string, issuedAt time.Time, parentIDs []string) error {
	wt.mu.Lock()
	defer wt.mu.Unlock()

	tasks := wt.tasksForScope(workflowID)

	// 1. Task ID uniqueness (Section 5, step 1).
	if _, exists := tasks[jti]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateTaskID, jti)
	}

	// 2. Parent existence (Section 5, step 2).
	for _, pid := range parentIDs {
		if _, exists := tasks[pid]; !exists {
			return fmt.Errorf("%w: %s", ErrParentNotFound, pid)
		}
	}

	// 3. Temporal ordering (Section 5, step 3).
	for _, pid := range parentIDs {
		parent := tasks[pid]
		if parent.IssuedAt.After(issuedAt.Add(wt.clockSkew)) {
			return fmt.Errorf("%w: parent %s (iat=%v) after child (iat=%v)",
				ErrTemporalViolation, pid, parent.IssuedAt, issuedAt)
		}
	}

	// 4. Acyclicity (Section 5, step 4).
	// Since we only allow references to already-recorded tasks (parent existence check),
	// and tasks are recorded in order, cycles are structurally impossible.
	// However, we add an explicit depth-limited ancestor check for defense-in-depth.
	if err := wt.checkAcyclicity(tasks, jti, parentIDs); err != nil {
		return err
	}

	// Record the task.
	record := &TaskRecord{
		JTI:       jti,
		IssuedAt:  issuedAt,
		ParentIDs: parentIDs,
	}

	if workflowID != "" {
		wf, exists := wt.workflows[workflowID]
		if !exists {
			wf = &Workflow{
				ID:        workflowID,
				Tasks:     make(map[string]*TaskRecord),
				CreatedAt: issuedAt,
			}
			wt.workflows[workflowID] = wf
		}
		wf.Tasks[jti] = record
		wf.UpdatedAt = issuedAt
	} else {
		wt.globalTasks[jti] = record
	}

	return nil
}

// GetTask retrieves a task record by workflow ID and JTI.
func (wt *WorkflowTracker) GetTask(workflowID, jti string) (*TaskRecord, bool) {
	wt.mu.RLock()
	defer wt.mu.RUnlock()

	tasks := wt.tasksForScope(workflowID)
	t, ok := tasks[jti]
	return t, ok
}

// WorkflowSize returns the number of tasks in a workflow.
func (wt *WorkflowTracker) WorkflowSize(workflowID string) int {
	wt.mu.RLock()
	defer wt.mu.RUnlock()

	if workflowID == "" {
		return len(wt.globalTasks)
	}
	wf, exists := wt.workflows[workflowID]
	if !exists {
		return 0
	}
	return len(wf.Tasks)
}

// ActiveWorkflows returns the count of active workflows.
func (wt *WorkflowTracker) ActiveWorkflows() int {
	wt.mu.RLock()
	defer wt.mu.RUnlock()
	return len(wt.workflows)
}

// Cleanup removes workflows that have been inactive longer than the TTL.
// Returns the number of workflows removed.
func (wt *WorkflowTracker) Cleanup() int {
	wt.mu.Lock()
	defer wt.mu.Unlock()

	cutoff := time.Now().Add(-wt.ttl)
	removed := 0

	for id, wf := range wt.workflows {
		if wf.UpdatedAt.Before(cutoff) {
			delete(wt.workflows, id)
			removed++
		}
	}

	// Cleanup global tasks older than TTL.
	for jti, t := range wt.globalTasks {
		if t.IssuedAt.Before(cutoff) {
			delete(wt.globalTasks, jti)
		}
	}

	return removed
}

// tasksForScope returns the task map for the given workflow (or global scope).
// Caller must hold at least a read lock.
func (wt *WorkflowTracker) tasksForScope(workflowID string) map[string]*TaskRecord {
	if workflowID == "" {
		return wt.globalTasks
	}
	wf, exists := wt.workflows[workflowID]
	if !exists {
		return nil
	}
	return wf.Tasks
}

// checkAcyclicity performs a depth-limited traversal to ensure no cycles.
// This is defense-in-depth — the append-only recording model makes cycles
// structurally impossible, but we check anyway per spec Section 5 step 4.
func (wt *WorkflowTracker) checkAcyclicity(tasks map[string]*TaskRecord, newJTI string, parentIDs []string) error {
	// BFS up the ancestor chain, checking that newJTI never appears.
	visited := make(map[string]bool)
	queue := make([]string, len(parentIDs))
	copy(queue, parentIDs)
	depth := 0

	for len(queue) > 0 && depth < MaxAncestorTraversal {
		current := queue[0]
		queue = queue[1:]
		depth++

		if current == newJTI {
			return fmt.Errorf("%w: task %s found in ancestor chain", ErrCycleDetected, newJTI)
		}
		if visited[current] {
			continue
		}
		visited[current] = true

		if parent, ok := tasks[current]; ok {
			queue = append(queue, parent.ParentIDs...)
		}
	}

	return nil
}
