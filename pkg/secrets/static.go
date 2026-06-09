package secrets

import (
	"context"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// StaticSource reads secrets from an in-memory config map.
// This is the migration path for hardcoded values — no external dependency.
type StaticSource struct {
	// secrets maps workload-scoped paths to key→value pairs.
	// Structure: path → key → value
	secrets map[string]map[string]string
	ttl     time.Duration
}

// StaticConfig holds the configuration for a StaticSource.
type StaticConfig struct {
	// Secrets maps path → key → value.
	Secrets map[string]map[string]string `yaml:"secrets"`
	// TTL for secret bundles. Defaults to 5 minutes.
	TTL time.Duration `yaml:"ttl"`
}

// RegistryFromOptionalFile loads a static secrets YAML file into a registry.
// Returns nil, nil when path is empty or the file does not exist.
func RegistryFromOptionalFile(path string) (*Registry, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read static secrets %q: %w", path, err)
	}
	var cfg StaticConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse static secrets %q: %w", path, err)
	}
	reg := NewRegistry()
	reg.Register(NewStaticSource(cfg))
	return reg, nil
}

// NewStaticSource creates a StaticSource from config.
func NewStaticSource(cfg StaticConfig) *StaticSource {
	ttl := cfg.TTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	secrets := cfg.Secrets
	if secrets == nil {
		secrets = make(map[string]map[string]string)
	}
	return &StaticSource{secrets: secrets, ttl: ttl}
}

func (s *StaticSource) Name() string { return "static" }

func (s *StaticSource) Available(_ context.Context) bool { return true }

func (s *StaticSource) Fetch(_ context.Context, refs []SecretRef) (*SecretBundle, error) {
	bundle := &SecretBundle{
		Claims: make(map[string]string),
		TTL:    s.ttl,
	}
	for _, ref := range refs {
		pathData, ok := s.secrets[ref.Path]
		if !ok {
			return nil, fmt.Errorf("static secret path %q not found", ref.Path)
		}
		val, ok := pathData[ref.Key]
		if !ok {
			return nil, fmt.Errorf("static secret key %q not found at path %q", ref.Key, ref.Path)
		}
		alias := ref.Alias
		if alias == "" {
			alias = ref.Key
		}
		bundle.Claims[alias] = val
	}
	return bundle, nil
}
