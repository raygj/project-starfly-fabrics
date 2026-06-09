package secrets

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeSource struct {
	name      string
	available bool
	bundle    *SecretBundle
	fetchErr  error
}

func (f *fakeSource) Name() string                                          { return f.name }
func (f *fakeSource) Available(_ context.Context) bool                      { return f.available }
func (f *fakeSource) Fetch(_ context.Context, _ []SecretRef) (*SecretBundle, error) {
	if f.fetchErr != nil {
		return nil, f.fetchErr
	}
	return f.bundle, nil
}

func TestRegistry_NewAndSources(t *testing.T) {
	r := NewRegistry()
	if got := r.Sources(); len(got) != 0 {
		t.Errorf("empty registry Sources() = %v, want empty", got)
	}

	r.Register(&fakeSource{name: "alpha", available: true})
	r.Register(&fakeSource{name: "beta", available: true})

	names := r.Sources()
	if len(names) != 2 {
		t.Fatalf("Sources() len = %d, want 2", len(names))
	}
	found := map[string]bool{}
	for _, n := range names {
		found[n] = true
	}
	if !found["alpha"] || !found["beta"] {
		t.Errorf("Sources() = %v, want alpha and beta", names)
	}
}

func TestRegistry_Available(t *testing.T) {
	r := NewRegistry()
	ctx := context.Background()

	if r.Available(ctx, "missing") {
		t.Error("Available for unregistered source should be false")
	}

	r.Register(&fakeSource{name: "up", available: true})
	r.Register(&fakeSource{name: "down", available: false})

	if !r.Available(ctx, "up") {
		t.Error("Available(up) = false, want true")
	}
	if r.Available(ctx, "down") {
		t.Error("Available(down) = true, want false")
	}
}

func TestRegistry_Fetch_Success(t *testing.T) {
	r := NewRegistry()
	ctx := context.Background()

	r.Register(&fakeSource{
		name:      "static",
		available: true,
		bundle: &SecretBundle{
			Claims: map[string]string{"db_pass": "secret1"},
			TTL:    3 * time.Minute,
		},
	})
	r.Register(&fakeSource{
		name:      "vault",
		available: true,
		bundle: &SecretBundle{
			Claims: map[string]string{"api_key": "key-abc"},
			TTL:    1 * time.Minute,
		},
	})

	refs := []SecretRef{
		{Source: "static", Path: "app/db", Key: "password", Alias: "db_pass"},
		{Source: "vault", Path: "app/api", Key: "key", Alias: "api_key"},
	}

	bundle, err := r.Fetch(ctx, refs)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if bundle.Claims["db_pass"] != "secret1" {
		t.Errorf("db_pass = %q, want secret1", bundle.Claims["db_pass"])
	}
	if bundle.Claims["api_key"] != "key-abc" {
		t.Errorf("api_key = %q, want key-abc", bundle.Claims["api_key"])
	}
	if bundle.TTL != 1*time.Minute {
		t.Errorf("TTL = %v, want 1m (shortest)", bundle.TTL)
	}
}

func TestRegistry_Fetch_UnknownSource(t *testing.T) {
	r := NewRegistry()
	_, err := r.Fetch(context.Background(), []SecretRef{
		{Source: "nonexistent", Path: "x", Key: "y"},
	})
	if err == nil {
		t.Error("expected error for unknown source")
	}
}

func TestRegistry_Fetch_UnavailableSource(t *testing.T) {
	r := NewRegistry()
	r.Register(&fakeSource{name: "down", available: false})

	_, err := r.Fetch(context.Background(), []SecretRef{
		{Source: "down", Path: "x", Key: "y"},
	})
	if err == nil {
		t.Error("expected error for unavailable source")
	}
}

func TestRegistry_Fetch_SourceError(t *testing.T) {
	r := NewRegistry()
	r.Register(&fakeSource{
		name:      "broken",
		available: true,
		fetchErr:  errors.New("connection refused"),
	})

	_, err := r.Fetch(context.Background(), []SecretRef{
		{Source: "broken", Path: "x", Key: "y"},
	})
	if err == nil {
		t.Error("expected error when source.Fetch fails")
	}
}

func TestRegistry_Fetch_TTLMerging(t *testing.T) {
	r := NewRegistry()
	ctx := context.Background()

	r.Register(&fakeSource{
		name:      "a",
		available: true,
		bundle:    &SecretBundle{Claims: map[string]string{"x": "1"}, TTL: 5 * time.Minute},
	})
	r.Register(&fakeSource{
		name:      "b",
		available: true,
		bundle:    &SecretBundle{Claims: map[string]string{"y": "2"}, TTL: 2 * time.Minute},
	})

	bundle, err := r.Fetch(ctx, []SecretRef{
		{Source: "a", Path: "p", Key: "k"},
		{Source: "b", Path: "p", Key: "k"},
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if bundle.TTL != 2*time.Minute {
		t.Errorf("TTL = %v, want 2m (shortest)", bundle.TTL)
	}
}

func TestRegistry_Fetch_ZeroTTL(t *testing.T) {
	r := NewRegistry()
	r.Register(&fakeSource{
		name:      "notset",
		available: true,
		bundle:    &SecretBundle{Claims: map[string]string{"x": "1"}, TTL: 0},
	})

	bundle, err := r.Fetch(context.Background(), []SecretRef{
		{Source: "notset", Path: "p", Key: "k"},
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if bundle.TTL != 0 {
		t.Errorf("TTL = %v, want 0 (source returned 0)", bundle.TTL)
	}
}

func TestRegistry_RegisterOverwrite(t *testing.T) {
	r := NewRegistry()
	ctx := context.Background()

	r.Register(&fakeSource{name: "s", available: false})
	r.Register(&fakeSource{name: "s", available: true, bundle: &SecretBundle{
		Claims: map[string]string{"k": "v"}, TTL: time.Minute,
	}})

	if !r.Available(ctx, "s") {
		t.Error("overwritten source should be available")
	}
	bundle, err := r.Fetch(ctx, []SecretRef{{Source: "s", Path: "p", Key: "k"}})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if bundle.Claims["k"] != "v" {
		t.Errorf("got %q, want v", bundle.Claims["k"])
	}
}
