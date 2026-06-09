package mcp

import (
	"errors"
	"sync"
	"time"
)

// Registry errors.
var (
	ErrToolExists   = errors.New("mcp: tool already registered")
	ErrToolNotFound = errors.New("mcp: tool not found")
)

// ToolEntry describes a registered MCP tool and its security constraints.
type ToolEntry struct {
	// ToolID is the unique identifier for this tool.
	ToolID string `json:"tool_id"`

	// Name is the human-readable tool name.
	Name string `json:"name"`

	// Description describes what the tool does.
	Description string `json:"description,omitempty"`

	// ResourceURI is the RFC 8707 resource indicator for audience matching.
	// If empty, ToolID is used as the resource URI.
	ResourceURI string `json:"resource_uri,omitempty"`

	// RequiredCapabilities are the capabilities a token must have to call this tool.
	RequiredCapabilities []string `json:"required_capabilities,omitempty"`

	// MaxBlastRadius is the maximum blast radius scope allowed for this tool.
	MaxBlastRadius string `json:"max_blast_radius,omitempty"`

	// RequiresExecution indicates the tool requires execution-scoped tokens.
	RequiresExecution bool `json:"requires_execution,omitempty"`

	// AllowedOperations lists the exec_act values this tool accepts.
	// An empty slice means any operation is allowed (no exec_act enforcement).
	AllowedOperations []string `json:"allowed_operations,omitempty"`

	// AllowedTargets lists the target resource URIs this tool may access.
	// An empty slice means any target is allowed (no target enforcement).
	AllowedTargets []string `json:"allowed_targets,omitempty"`

	// OwnerCommune identifies the commune that owns this tool.
	OwnerCommune string `json:"owner_commune,omitempty"`

	// ServerID identifies the MCP server hosting this tool.
	ServerID string `json:"server_id,omitempty"`

	// RegisteredAt is when the tool was registered.
	RegisteredAt time.Time `json:"registered_at"`

	// UpdatedAt is when the tool was last updated.
	UpdatedAt time.Time `json:"updated_at"`
}

// Registry is a thread-safe in-memory registry of MCP tools.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]*ToolEntry
}

// NewRegistry creates an empty tool registry.
func NewRegistry() *Registry {
	return &Registry{
		tools: make(map[string]*ToolEntry),
	}
}

// Register adds a tool to the registry. Returns ErrToolExists if a tool
// with the same ID is already registered.
func (r *Registry) Register(entry *ToolEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.tools[entry.ToolID]; exists {
		return ErrToolExists
	}
	now := time.Now()
	entry.RegisteredAt = now
	entry.UpdatedAt = now
	r.tools[entry.ToolID] = entry
	return nil
}

// Update replaces a tool entry. Returns ErrToolNotFound if not registered.
func (r *Registry) Update(entry *ToolEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	existing, exists := r.tools[entry.ToolID]
	if !exists {
		return ErrToolNotFound
	}
	entry.RegisteredAt = existing.RegisteredAt
	entry.UpdatedAt = time.Now()
	r.tools[entry.ToolID] = entry
	return nil
}

// Deregister removes a tool from the registry. Returns ErrToolNotFound if not registered.
func (r *Registry) Deregister(toolID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.tools[toolID]; !exists {
		return ErrToolNotFound
	}
	delete(r.tools, toolID)
	return nil
}

// Get returns a tool entry by ID.
func (r *Registry) Get(toolID string) (*ToolEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, ok := r.tools[toolID]
	if !ok {
		return nil, false
	}
	// Return a copy to avoid data races.
	cp := *entry
	return &cp, true
}

// List returns all registered tools.
func (r *Registry) List() []*ToolEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*ToolEntry, 0, len(r.tools))
	for _, e := range r.tools {
		cp := *e
		result = append(result, &cp)
	}
	return result
}

// Count returns the number of registered tools.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tools)
}
