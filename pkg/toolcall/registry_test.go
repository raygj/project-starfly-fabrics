package toolcall

import (
	"testing"
)

func TestRegistryRegisterAndGet(t *testing.T) {
	r := NewRegistry()

	entry := &ToolEntry{
		ToolID:    "tool-001",
		Name:      "Test Tool",
		Protocols: []Protocol{ProtocolMCP, ProtocolHTTP},
	}
	if err := r.Register(entry); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, ok := r.Get("tool-001")
	if !ok {
		t.Fatal("Get returned not found")
	}
	if got.Name != "Test Tool" {
		t.Errorf("Name: got %q, want %q", got.Name, "Test Tool")
	}
	if got.RegisteredAt.IsZero() {
		t.Error("RegisteredAt not set")
	}
}

func TestRegistryDuplicateReturnsError(t *testing.T) {
	r := NewRegistry()
	entry := &ToolEntry{ToolID: "dup", Name: "Dup"}
	_ = r.Register(entry)
	if err := r.Register(entry); err != ErrToolExists {
		t.Errorf("expected ErrToolExists, got %v", err)
	}
}

func TestRegistryDefaultProtocol(t *testing.T) {
	r := NewRegistry()
	// Register without Protocols — should default to ["mcp"].
	if err := r.Register(&ToolEntry{ToolID: "legacy", Name: "Legacy MCP"}); err != nil {
		t.Fatal(err)
	}
	got, _ := r.Get("legacy")
	if len(got.Protocols) != 1 || got.Protocols[0] != ProtocolMCP {
		t.Errorf("expected default protocol mcp, got %v", got.Protocols)
	}
}

func TestRegistryProtocolFilter(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(&ToolEntry{ToolID: "mcp-only", Name: "MCP", Protocols: []Protocol{ProtocolMCP}})
	_ = r.Register(&ToolEntry{ToolID: "http-only", Name: "HTTP", Protocols: []Protocol{ProtocolHTTP}})
	_ = r.Register(&ToolEntry{ToolID: "both", Name: "Both", Protocols: []Protocol{ProtocolMCP, ProtocolHTTP}})

	http := ProtocolHTTP
	results := r.List(&http)
	if len(results) != 2 {
		t.Errorf("expected 2 HTTP-capable tools, got %d", len(results))
	}

	all := r.List(nil)
	if len(all) != 3 {
		t.Errorf("expected 3 total tools, got %d", len(all))
	}
}

func TestRegistryUpdateAndDeregister(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(&ToolEntry{ToolID: "t1", Name: "Original"})

	if err := r.Update(&ToolEntry{ToolID: "t1", Name: "Updated"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ := r.Get("t1")
	if got.Name != "Updated" {
		t.Errorf("Name after update: %q", got.Name)
	}
	if got.RegisteredAt.IsZero() {
		t.Error("RegisteredAt must be preserved on update")
	}

	if err := r.Deregister("t1"); err != nil {
		t.Fatalf("Deregister: %v", err)
	}
	if _, ok := r.Get("t1"); ok {
		t.Error("tool should be gone after deregister")
	}
}

func TestToolEntrySupportsProtocol(t *testing.T) {
	e := &ToolEntry{Protocols: []Protocol{ProtocolMCP}}
	if !e.SupportsProtocol(ProtocolMCP) {
		t.Error("should support mcp")
	}
	if e.SupportsProtocol(ProtocolHTTP) {
		t.Error("should not support http")
	}

	// Version-stripped matching: "mcp/v2" should match entry with "mcp".
	if !e.SupportsProtocol("mcp/v2") {
		t.Error("should support mcp/v2 via name-only match")
	}

	// Empty Protocols = allow all.
	any := &ToolEntry{}
	if !any.SupportsProtocol(ProtocolA2A) {
		t.Error("empty Protocols should accept any protocol")
	}
}

func TestRegistryNotFoundErrors(t *testing.T) {
	r := NewRegistry()
	if err := r.Update(&ToolEntry{ToolID: "nope"}); err != ErrToolNotFound {
		t.Errorf("Update on missing: got %v, want ErrToolNotFound", err)
	}
	if err := r.Deregister("nope"); err != ErrToolNotFound {
		t.Errorf("Deregister on missing: got %v, want ErrToolNotFound", err)
	}
}

func TestRegistryCount(t *testing.T) {
	r := NewRegistry()
	if c := r.Count(); c != 0 {
		t.Errorf("empty registry: Count = %d, want 0", c)
	}

	_ = r.Register(&ToolEntry{ToolID: "a"})
	_ = r.Register(&ToolEntry{ToolID: "b"})
	if c := r.Count(); c != 2 {
		t.Errorf("after 2 registers: Count = %d, want 2", c)
	}

	_ = r.Deregister("a")
	if c := r.Count(); c != 1 {
		t.Errorf("after deregister: Count = %d, want 1", c)
	}
}
