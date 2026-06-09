package secrets

import (
	"context"
	"testing"
	"time"
)

func TestStaticSource_Name(t *testing.T) {
	s := NewStaticSource(StaticConfig{})
	if s.Name() != "static" {
		t.Errorf("Name() = %q, want static", s.Name())
	}
}

func TestStaticSource_Available(t *testing.T) {
	s := NewStaticSource(StaticConfig{})
	if !s.Available(context.Background()) {
		t.Error("static source should always be available")
	}
}

func TestRegistryFromOptionalFile_Missing(t *testing.T) {
	reg, err := RegistryFromOptionalFile("/nonexistent/path/static-secrets.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reg != nil {
		t.Fatal("expected nil registry for missing file")
	}
}

func TestStaticSource_Fetch(t *testing.T) {
	s := NewStaticSource(StaticConfig{
		Secrets: map[string]map[string]string{
			"app/db": {
				"password": "s3cret",
				"host":     "db.internal",
			},
			"app/api": {
				"key": "api-key-123",
			},
		},
		TTL: 3 * time.Minute,
	})

	ctx := context.Background()

	t.Run("single ref", func(t *testing.T) {
		bundle, err := s.Fetch(ctx, []SecretRef{
			{Source: "static", Path: "app/db", Key: "password"},
		})
		if err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		if bundle.Claims["password"] != "s3cret" {
			t.Errorf("password = %q, want s3cret", bundle.Claims["password"])
		}
		if bundle.TTL != 3*time.Minute {
			t.Errorf("TTL = %v, want 3m", bundle.TTL)
		}
	})

	t.Run("multiple refs with alias", func(t *testing.T) {
		bundle, err := s.Fetch(ctx, []SecretRef{
			{Source: "static", Path: "app/db", Key: "password", Alias: "db_pass"},
			{Source: "static", Path: "app/api", Key: "key", Alias: "api_key"},
		})
		if err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		if bundle.Claims["db_pass"] != "s3cret" {
			t.Errorf("db_pass = %q, want s3cret", bundle.Claims["db_pass"])
		}
		if bundle.Claims["api_key"] != "api-key-123" {
			t.Errorf("api_key = %q, want api-key-123", bundle.Claims["api_key"])
		}
	})

	t.Run("missing path", func(t *testing.T) {
		_, err := s.Fetch(ctx, []SecretRef{
			{Source: "static", Path: "nonexistent", Key: "x"},
		})
		if err == nil {
			t.Error("expected error for missing path")
		}
	})

	t.Run("missing key", func(t *testing.T) {
		_, err := s.Fetch(ctx, []SecretRef{
			{Source: "static", Path: "app/db", Key: "nonexistent"},
		})
		if err == nil {
			t.Error("expected error for missing key")
		}
	})
}

func TestStaticSource_DefaultTTL(t *testing.T) {
	s := NewStaticSource(StaticConfig{
		Secrets: map[string]map[string]string{
			"a": {"b": "c"},
		},
	})
	bundle, err := s.Fetch(context.Background(), []SecretRef{
		{Source: "static", Path: "a", Key: "b"},
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if bundle.TTL != 5*time.Minute {
		t.Errorf("default TTL = %v, want 5m", bundle.TTL)
	}
}
