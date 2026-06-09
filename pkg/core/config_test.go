package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.ListenAddr != ":8693" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":8693")
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "info")
	}
	if cfg.LogFormat != "json" {
		t.Errorf("LogFormat = %q, want %q", cfg.LogFormat, "json")
	}
	if cfg.DevMode {
		t.Error("DevMode should be false by default")
	}
	if cfg.Lock.Type != "awskms" {
		t.Errorf("Lock.Type = %q, want %q", cfg.Lock.Type, "awskms")
	}
	if cfg.Storage.Type != "badger" {
		t.Errorf("Storage.Type = %q, want %q", cfg.Storage.Type, "badger")
	}
	if cfg.Storage.Path != "/data/starfly" {
		t.Errorf("Storage.Path = %q, want %q", cfg.Storage.Path, "/data/starfly")
	}
	if cfg.Policy.BundlePath != "/etc/starfly/policies/" {
		t.Errorf("Policy.BundlePath = %q, want %q", cfg.Policy.BundlePath, "/etc/starfly/policies/")
	}
}

func TestLoadConfig_NoFile(t *testing.T) {
	// With no file and no env vars, we should get defaults.
	clearEnv(t)
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.ListenAddr != ":8693" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":8693")
	}
}

func TestLoadConfig_FromYAMLFile(t *testing.T) {
	clearEnv(t)

	content := `
listenAddr: ":9090"
logLevel: debug
lock:
  type: gcpckms
storage:
  type: badger
  path: /tmp/starfly-test
trustDomains:
  - name: spiffe://example.com
    enabled: true
    jwksURL: https://example.com/.well-known/jwks.json
`
	path := writeTemp(t, "config-*.yaml", content)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.ListenAddr != ":9090" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":9090")
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "debug")
	}
	if cfg.Lock.Type != "gcpckms" {
		t.Errorf("Lock.Type = %q, want %q", cfg.Lock.Type, "gcpckms")
	}
	if cfg.Storage.Path != "/tmp/starfly-test" {
		t.Errorf("Storage.Path = %q, want %q", cfg.Storage.Path, "/tmp/starfly-test")
	}
	if len(cfg.TrustDomains) != 1 {
		t.Fatalf("TrustDomains len = %d, want 1", len(cfg.TrustDomains))
	}
	td := cfg.TrustDomains[0]
	if td.Name != "spiffe://example.com" {
		t.Errorf("TrustDomain.Name = %q, want %q", td.Name, "spiffe://example.com")
	}
	if !td.Enabled {
		t.Error("TrustDomain.Enabled should be true")
	}
}

func TestLoadConfig_EnvOverridesFile(t *testing.T) {
	clearEnv(t)

	content := `
listenAddr: ":9090"
logLevel: warn
lock:
  type: dev
`
	path := writeTemp(t, "config-*.yaml", content)

	t.Setenv("STARFLY_LOG_LEVEL", "debug")
	t.Setenv("STARFLY_LOCK_TYPE", "gcpckms")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	// File value should stand for non-overridden fields.
	if cfg.ListenAddr != ":9090" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":9090")
	}
	// Env should override file.
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q (env override)", cfg.LogLevel, "debug")
	}
	if cfg.Lock.Type != "gcpckms" {
		t.Errorf("Lock.Type = %q, want %q (env override)", cfg.Lock.Type, "gcpckms")
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	clearEnv(t)
	_, err := LoadConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestLoadConfig_DevModeEnv(t *testing.T) {
	clearEnv(t)

	tests := []struct {
		envVal string
		want   bool
	}{
		{"true", true},
		{"TRUE", true},
		{"1", true},
		{"false", false},
		{"0", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run("STARFLY_DEV_MODE="+tt.envVal, func(t *testing.T) {
			if tt.envVal != "" {
				t.Setenv("STARFLY_DEV_MODE", tt.envVal)
			}
			cfg, err := LoadConfig("")
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			if cfg.DevMode != tt.want {
				t.Errorf("DevMode = %v, want %v", cfg.DevMode, tt.want)
			}
		})
	}
}

func TestValidate_ValidLockTypes(t *testing.T) {
	for _, st := range []string{"dev", "awskms", "gcpckms", "azurekeyvault"} {
		t.Run(st, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Lock.Type = st
			if st == "awskms" {
				cfg.Lock.AWSKMS.KeyID = "arn:aws:kms:us-east-1:123456789012:key/test"
			}
			if err := cfg.Validate(); err != nil {
				t.Errorf("Validate() rejected valid lock type %q: %v", st, err)
			}
		})
	}
}

func TestValidate_AWSKMSMissingKeyID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Lock.Type = "awskms"
	cfg.Lock.AWSKMS.KeyID = ""
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should reject awskms with empty keyId")
	}
}

func TestValidate_UnknownLockType(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Lock.Type = "shamir"
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should reject unknown lock type")
	}
}

func TestValidate_EmptyListenAddr(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenAddr = ""
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should reject empty listenAddr")
	}
}

func TestValidate_EmptyStoragePath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Storage.Path = ""
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should reject empty storage path")
	}
}

func TestValidate_TLSEnabled_MissingCertFile(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Lock.Type = "dev"
	cfg.TLS.Enabled = true
	cfg.TLS.KeyFile = "/path/to/key.pem"
	cfg.TLS.ClientCA = "/path/to/ca.pem"
	// CertFile is empty
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should reject TLS enabled with empty certFile")
	}
}

func TestValidate_TLSEnabled_MissingKeyFile(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Lock.Type = "dev"
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = "/path/to/cert.pem"
	cfg.TLS.ClientCA = "/path/to/ca.pem"
	// KeyFile is empty
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should reject TLS enabled with empty keyFile")
	}
}

func TestValidate_TLSEnabled_MissingClientCA(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Lock.Type = "dev"
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = "/path/to/cert.pem"
	cfg.TLS.KeyFile = "/path/to/key.pem"
	// ClientCA is empty
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should reject TLS enabled with empty clientCA")
	}
}

func TestValidate_TLSEnabled_AllFieldsPresent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Lock.Type = "dev"
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = "/path/to/cert.pem"
	cfg.TLS.KeyFile = "/path/to/key.pem"
	cfg.TLS.ClientCA = "/path/to/ca.pem"
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() rejected valid TLS config: %v", err)
	}
}

func TestDevMode_DisablesTLS(t *testing.T) {
	clearEnv(t)

	content := `
devMode: true
tls:
  enabled: true
  certFile: /path/to/cert.pem
  keyFile: /path/to/key.pem
  clientCA: /path/to/ca.pem
lock:
  type: dev
`
	path := writeTemp(t, "config-tls-*.yaml", content)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	// Dev mode should be set from YAML.
	if !cfg.DevMode {
		t.Fatal("expected DevMode to be true")
	}

	// Simulate what main.go does: force TLS off in dev mode.
	if cfg.DevMode {
		cfg.TLS.Enabled = false
	}

	if cfg.TLS.Enabled {
		t.Error("TLS.Enabled should be false in dev mode")
	}

	// Validation should pass with TLS disabled.
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() failed: %v", err)
	}
}

func TestLoadConfig_TLSEnvOverrides(t *testing.T) {
	clearEnv(t)

	t.Setenv("STARFLY_TLS_ENABLED", "true")
	t.Setenv("STARFLY_TLS_LISTEN_ADDR", ":9694")
	t.Setenv("STARFLY_TLS_CERT_FILE", "/env/cert.pem")
	t.Setenv("STARFLY_TLS_KEY_FILE", "/env/key.pem")
	t.Setenv("STARFLY_TLS_CLIENT_CA", "/env/ca.pem")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if !cfg.TLS.Enabled {
		t.Error("TLS.Enabled should be true from env")
	}
	if cfg.TLS.ListenAddr != ":9694" {
		t.Errorf("TLS.ListenAddr = %q, want %q", cfg.TLS.ListenAddr, ":9694")
	}
	if cfg.TLS.CertFile != "/env/cert.pem" {
		t.Errorf("TLS.CertFile = %q, want %q", cfg.TLS.CertFile, "/env/cert.pem")
	}
	if cfg.TLS.KeyFile != "/env/key.pem" {
		t.Errorf("TLS.KeyFile = %q, want %q", cfg.TLS.KeyFile, "/env/key.pem")
	}
	if cfg.TLS.ClientCA != "/env/ca.pem" {
		t.Errorf("TLS.ClientCA = %q, want %q", cfg.TLS.ClientCA, "/env/ca.pem")
	}
}

func TestDefaultConfig_TLSDefaults(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.TLS.Enabled {
		t.Error("TLS.Enabled should be false by default")
	}
	if cfg.TLS.ListenAddr != ":8694" {
		t.Errorf("TLS.ListenAddr = %q, want %q", cfg.TLS.ListenAddr, ":8694")
	}
}

func TestLoadConfig_PolicySigningEnvOverrides(t *testing.T) {
	clearEnv(t)

	t.Setenv("STARFLY_POLICY_SIGNING_KEY_FILE", "/etc/starfly/keys/policy.pub")
	t.Setenv("STARFLY_POLICY_SIGNING_KEY_ID", "custom-key-id")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.Policy.SigningKeyFile != "/etc/starfly/keys/policy.pub" {
		t.Errorf("Policy.SigningKeyFile = %q, want %q", cfg.Policy.SigningKeyFile, "/etc/starfly/keys/policy.pub")
	}
	if cfg.Policy.SigningKeyID != "custom-key-id" {
		t.Errorf("Policy.SigningKeyID = %q, want %q", cfg.Policy.SigningKeyID, "custom-key-id")
	}
}

func TestLoadConfig_PolicySigningDefaultsEmpty(t *testing.T) {
	clearEnv(t)

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.Policy.SigningKeyFile != "" {
		t.Errorf("Policy.SigningKeyFile = %q, want empty", cfg.Policy.SigningKeyFile)
	}
	if cfg.Policy.SigningKeyID != "" {
		t.Errorf("Policy.SigningKeyID = %q, want empty", cfg.Policy.SigningKeyID)
	}
}

// --- helpers ---

func clearEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"STARFLY_LISTEN_ADDR",
		"STARFLY_LOG_LEVEL",
		"STARFLY_LOG_FORMAT",
		"STARFLY_DEV_MODE",
		"STARFLY_LOCK_TYPE",
		"STARFLY_STORAGE_PATH",
		"STARFLY_POLICY_BUNDLE_PATH",
		"STARFLY_POLICY_SIGNING_KEY_FILE",
		"STARFLY_POLICY_SIGNING_KEY_ID",
		"STARFLY_TLS_ENABLED",
		"STARFLY_TLS_LISTEN_ADDR",
		"STARFLY_TLS_CERT_FILE",
		"STARFLY_TLS_KEY_FILE",
		"STARFLY_TLS_CLIENT_CA",
	} {
		t.Setenv(key, "")
	}
}

func writeTemp(t *testing.T, pattern, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, pattern)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	return path
}
