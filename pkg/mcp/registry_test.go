package mcp

import (
	"sync"
	"testing"
)

func TestRegistryRegister(t *testing.T) {
	r := NewRegistry()

	entry := &ToolEntry{
		ToolID:               "code-search",
		Name:                 "Code Search",
		ResourceURI:          "https://mcp.example.com/tools/code-search",
		RequiredCapabilities: []string{"query-read"},
		MaxBlastRadius:       "workspace:dev",
	}

	if err := r.Register(entry); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if r.Count() != 1 {
		t.Fatalf("Count: got %d, want 1", r.Count())
	}

	// Duplicate registration fails.
	if err := r.Register(entry); err != ErrToolExists {
		t.Fatalf("duplicate Register: got %v, want ErrToolExists", err)
	}
}

func TestRegistryGet(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(&ToolEntry{ToolID: "tool-a", Name: "Tool A"})

	got, ok := r.Get("tool-a")
	if !ok {
		t.Fatal("Get: tool-a not found")
	}
	if got.Name != "Tool A" {
		t.Fatalf("Get: name = %q, want %q", got.Name, "Tool A")
	}

	// Returned value is a copy — mutation does not affect registry.
	got.Name = "mutated"
	orig, _ := r.Get("tool-a")
	if orig.Name != "Tool A" {
		t.Fatal("Get returned a reference, not a copy")
	}

	// Missing tool.
	_, ok = r.Get("nonexistent")
	if ok {
		t.Fatal("Get: nonexistent tool should not be found")
	}
}

func TestRegistryUpdate(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(&ToolEntry{ToolID: "tool-a", Name: "Original"})

	err := r.Update(&ToolEntry{ToolID: "tool-a", Name: "Updated"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ := r.Get("tool-a")
	if got.Name != "Updated" {
		t.Fatalf("Update: name = %q, want %q", got.Name, "Updated")
	}

	// Update preserves original RegisteredAt.
	if got.RegisteredAt.IsZero() {
		t.Fatal("Update: RegisteredAt should be preserved")
	}

	// Update of missing tool fails.
	err = r.Update(&ToolEntry{ToolID: "missing"})
	if err != ErrToolNotFound {
		t.Fatalf("Update missing: got %v, want ErrToolNotFound", err)
	}
}

func TestRegistryDeregister(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(&ToolEntry{ToolID: "tool-a"})

	if err := r.Deregister("tool-a"); err != nil {
		t.Fatalf("Deregister: %v", err)
	}
	if r.Count() != 0 {
		t.Fatalf("Count after deregister: got %d, want 0", r.Count())
	}

	// Deregister of missing tool fails.
	if err := r.Deregister("tool-a"); err != ErrToolNotFound {
		t.Fatalf("Deregister missing: got %v, want ErrToolNotFound", err)
	}
}

func TestRegistryList(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(&ToolEntry{ToolID: "a"})
	_ = r.Register(&ToolEntry{ToolID: "b"})
	_ = r.Register(&ToolEntry{ToolID: "c"})

	tools := r.List()
	if len(tools) != 3 {
		t.Fatalf("List: got %d tools, want 3", len(tools))
	}
}

func TestRegistryConcurrency(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup

	// Concurrent registrations.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			entry := &ToolEntry{ToolID: "tool-" + string(rune('a'+i%26)) + string(rune('0'+i/26))}
			_ = r.Register(entry)
		}(i)
	}
	wg.Wait()

	// Concurrent reads.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = r.List()
			_ = r.Count()
		}()
	}
	wg.Wait()
}
