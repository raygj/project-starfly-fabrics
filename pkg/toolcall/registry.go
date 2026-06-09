package toolcall

import (
	"errors"
	"sync"
	"time"
)

// Registry errors.
var (
	ErrToolExists   = errors.New("toolcall: tool already registered")
	ErrToolNotFound = errors.New("toolcall: tool not found")
)

// ToolEntry describes a registered tool and its security constraints.
// It extends the MCP-only ToolEntry with multi-protocol support.
// Existing MCP entries are auto-tagged with Protocols: ["mcp"] on registration.
type ToolEntry struct {
	// ToolID is the unique canonical identifier for this tool.
	ToolID string `json:"tool_id"`
	// Name is the human-readable tool name.
	Name string `json:"name"`
	// Description describes what the tool does.
	Description string `json:"description,omitempty"`
	// ResourceURI is the RFC 8707 resource indicator for audience matching.
	// If empty, ToolID is used.
	ResourceURI string `json:"resource_uri,omitempty"`

	// Protocols lists the tool-calling protocols this tool accepts.
	// An empty slice defaults to ["mcp"] for migration compatibility.
	Protocols []Protocol `json:"protocols,omitempty"`
	// ProtocolMeta holds per-protocol configuration metadata.
	ProtocolMeta map[Protocol]map[string]string `json:"protocol_meta,omitempty"`

	// RequiredCapabilities are the token capabilities required to call this tool.
	RequiredCapabilities []string `json:"required_capabilities,omitempty"`
	// MaxBlastRadius is the maximum blast radius scope allowed for callers.
	MaxBlastRadius string `json:"max_blast_radius,omitempty"`
	// RequiresExecution indicates the tool requires execution-scoped tokens (ECT).
	RequiresExecution bool `json:"requires_execution,omitempty"`
	// AllowedOperations lists accepted exec_act values (empty = any).
	AllowedOperations []string `json:"allowed_operations,omitempty"`
	// AllowedTargets lists accepted target resource URIs (empty = any).
	AllowedTargets []string `json:"allowed_targets,omitempty"`

	// OwnerCommune identifies the commune that owns this tool.
	OwnerCommune string `json:"owner_commune,omitempty"`
	// ServerID identifies the server hosting this tool.
	ServerID string `json:"server_id,omitempty"`

	RegisteredAt time.Time `json:"registered_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// SupportsProtocol reports whether the tool accepts calls via the given protocol.
// If Protocols is empty, all protocols are accepted (migration-safe default).
func (e *ToolEntry) SupportsProtocol(p Protocol) bool {
	if len(e.Protocols) == 0 {
		return true
	}
	wantName, _ := ParseProtocol(p)
	for _, ep := range e.Protocols {
		name, _ := ParseProtocol(ep)
		if name == wantName {
			return true
		}
	}
	return false
}

// Registry is a thread-safe in-memory registry of tools supporting multiple protocols.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]*ToolEntry
}

// NewRegistry creates an empty tool registry.
func NewRegistry() *Registry {
	return &Registry{tools: make(map[string]*ToolEntry)}
}

// Register adds a tool. Returns ErrToolExists if the ToolID is already registered.
// Entries with no Protocols are defaulted to ["mcp"] for migration compatibility.
func (r *Registry) Register(entry *ToolEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.tools[entry.ToolID]; exists {
		return ErrToolExists
	}
	if len(entry.Protocols) == 0 {
		entry.Protocols = []Protocol{ProtocolMCP}
	}
	now := time.Now()
	entry.RegisteredAt = now
	entry.UpdatedAt = now
	cp := *entry
	r.tools[entry.ToolID] = &cp
	return nil
}

// Update replaces an existing tool entry. Returns ErrToolNotFound if not registered.
func (r *Registry) Update(entry *ToolEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	existing, exists := r.tools[entry.ToolID]
	if !exists {
		return ErrToolNotFound
	}
	entry.RegisteredAt = existing.RegisteredAt
	entry.UpdatedAt = time.Now()
	cp := *entry
	r.tools[entry.ToolID] = &cp
	return nil
}

// Deregister removes a tool. Returns ErrToolNotFound if not registered.
func (r *Registry) Deregister(toolID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.tools[toolID]; !exists {
		return ErrToolNotFound
	}
	delete(r.tools, toolID)
	return nil
}

// Get returns a copy of the tool entry for toolID.
func (r *Registry) Get(toolID string) (*ToolEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, ok := r.tools[toolID]
	if !ok {
		return nil, false
	}
	cp := *entry
	return &cp, true
}

// List returns all registered tools. If protocol is non-nil, only tools that
// support that protocol are returned.
func (r *Registry) List(protocol *Protocol) []*ToolEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*ToolEntry, 0, len(r.tools))
	for _, e := range r.tools {
		if protocol != nil && !e.SupportsProtocol(*protocol) {
			continue
		}
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
