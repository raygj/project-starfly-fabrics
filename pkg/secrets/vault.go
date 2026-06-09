package secrets

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// VaultAuthMethod selects how the Starfly unit authenticates to Vault.
type VaultAuthMethod string

const (
	VaultAuthJWT VaultAuthMethod = "jwt"
	VaultAuthTLS VaultAuthMethod = "tls"
)

// VaultConfig configures the VaultSource.
type VaultConfig struct {
	Address    string          `yaml:"address"`
	Namespace  string          `yaml:"namespace,omitempty"`
	AuthMethod VaultAuthMethod `yaml:"auth_method"` // "jwt" or "tls"
	JWTMount   string          `yaml:"jwt_mount,omitempty"`
	TLSMount   string          `yaml:"tls_mount,omitempty"`
	Role       string          `yaml:"role"`
	TTL        time.Duration   `yaml:"ttl,omitempty"`
	HTTPClient *http.Client    `yaml:"-"`

	// JWTTokenFunc provides the WIMSE JWT for Vault JWT auth.
	// Set by the engine at runtime — not from config YAML.
	JWTTokenFunc func() string `yaml:"-"`

	// TLS client cert paths for TLS auth.
	TLSCertFile string `yaml:"tls_cert_file,omitempty"`
	TLSKeyFile  string `yaml:"tls_key_file,omitempty"`
}

// VaultSource fetches secrets from HashiCorp Vault KV v2.
type VaultSource struct {
	cfg    VaultConfig
	client *vault.Client
	ttl    time.Duration
}

// NewVaultSource creates a VaultSource. Does not authenticate immediately —
// authentication happens lazily on first Fetch or Available call.
func NewVaultSource(cfg VaultConfig) (*VaultSource, error) {
	vcfg := vault.DefaultConfig()
	vcfg.Address = cfg.Address
	if cfg.HTTPClient != nil {
		vcfg.HttpClient = cfg.HTTPClient
	}

	client, err := vault.NewClient(vcfg)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}
	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}

	ttl := cfg.TTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}

	return &VaultSource{
		cfg:    cfg,
		client: client,
		ttl:    ttl,
	}, nil
}

func (v *VaultSource) Name() string { return "vault" }

// Available checks Vault's /v1/sys/health endpoint.
func (v *VaultSource) Available(ctx context.Context) bool {
	health, err := v.client.Sys().HealthWithContext(ctx)
	if err != nil {
		slog.Debug("vault health check failed", "error", err)
		return false
	}
	return health.Initialized && !health.Sealed
}

// Fetch authenticates (if needed) and reads secrets from Vault KV v2.
func (v *VaultSource) Fetch(ctx context.Context, refs []SecretRef) (*SecretBundle, error) {
	if err := v.ensureAuth(ctx); err != nil {
		return nil, fmt.Errorf("vault auth: %w", err)
	}

	bundle := &SecretBundle{
		Claims: make(map[string]string),
		TTL:    v.ttl,
	}

	for _, ref := range refs {
		secret, err := v.client.KVv2("secret").Get(ctx, ref.Path)
		if err != nil {
			return nil, fmt.Errorf("reading vault path %q: %w", ref.Path, err)
		}
		if secret == nil || secret.Data == nil {
			return nil, fmt.Errorf("vault path %q returned no data", ref.Path)
		}

		val, ok := secret.Data[ref.Key]
		if !ok {
			return nil, fmt.Errorf("vault key %q not found at path %q", ref.Key, ref.Path)
		}

		strVal, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("vault key %q at path %q is not a string", ref.Key, ref.Path)
		}

		alias := ref.Alias
		if alias == "" {
			alias = ref.Key
		}
		bundle.Claims[alias] = strVal
	}

	return bundle, nil
}

// ensureAuth authenticates to Vault using the configured method.
func (v *VaultSource) ensureAuth(ctx context.Context) error {
	// If we already have a valid token, skip.
	if v.client.Token() != "" {
		return nil
	}

	switch v.cfg.AuthMethod {
	case VaultAuthJWT:
		return v.authJWT(ctx)
	case VaultAuthTLS:
		return v.authTLS(ctx)
	default:
		return fmt.Errorf("unsupported vault auth method: %q", v.cfg.AuthMethod)
	}
}

func (v *VaultSource) authJWT(ctx context.Context) error {
	if v.cfg.JWTTokenFunc == nil {
		return fmt.Errorf("JWT auth configured but no token function provided")
	}

	mount := v.cfg.JWTMount
	if mount == "" {
		mount = "jwt"
	}

	token := v.cfg.JWTTokenFunc()
	path := fmt.Sprintf("auth/%s/login", mount)
	secret, err := v.client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"role": v.cfg.Role,
		"jwt":  token,
	})
	if err != nil {
		return fmt.Errorf("vault JWT login: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("vault JWT login returned no auth")
	}

	v.client.SetToken(secret.Auth.ClientToken)
	return nil
}

func (v *VaultSource) authTLS(ctx context.Context) error {
	mount := v.cfg.TLSMount
	if mount == "" {
		mount = "cert"
	}

	path := fmt.Sprintf("auth/%s/login", mount)
	secret, err := v.client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"name": v.cfg.Role,
	})
	if err != nil {
		return fmt.Errorf("vault TLS login: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("vault TLS login returned no auth")
	}

	v.client.SetToken(secret.Auth.ClientToken)
	return nil
}
