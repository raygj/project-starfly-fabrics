package core

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds all Starfly runtime configuration.
// Field names and nesting match the Helm values.yaml shape under "starfly:".
type Config struct {
	ListenAddr   string         `yaml:"listenAddr"`
	LogLevel     string         `yaml:"logLevel"`
	LogFormat    string         `yaml:"logFormat"`
	DevMode      bool           `yaml:"devMode"`
	Lock         LockConfig     `yaml:"lock"`
	Storage      StorageConfig  `yaml:"storage"`
	Policy       PolicyConfig   `yaml:"policy"`
	TrustDomains []TrustDomain  `yaml:"trustDomains"`
	RateLimit    RateLimitConfig `yaml:"rateLimit"`
	NATS         NATSConfig       `yaml:"nats"`
	Federation   FederationConfig `yaml:"federation"`
	Telemetry    TelemetryConfig  `yaml:"telemetry"`
	TLS          TLSConfig        `yaml:"tls"`
	Lifecycle    LifecycleConfig  `yaml:"lifecycle"`
}

// LifecycleConfig controls Temporal-based credential lifecycle automation.
type LifecycleConfig struct {
	Enabled  bool           `yaml:"enabled"`
	Temporal TemporalConfig `yaml:"temporal"`
}

// TemporalConfig holds Temporal server connection settings.
type TemporalConfig struct {
	HostPort  string `yaml:"hostPort"`  // e.g. "localhost:7233"; empty = disabled
	Namespace string `yaml:"namespace"` // default: "default"
	TaskQueue string `yaml:"taskQueue"` // default: "starfly-lifecycle"
}

// TLSConfig controls the mTLS listener for protected endpoints.
type TLSConfig struct {
	Enabled    bool   `yaml:"enabled"`    // default: false
	ListenAddr string `yaml:"listenAddr"` // default: ":8694"
	CertFile   string `yaml:"certFile"`   // server cert PEM
	KeyFile    string `yaml:"keyFile"`    // server key PEM
	ClientCA   string `yaml:"clientCA"`   // CA PEM for client cert verification
}

// AWSKMSConfig holds AWS KMS-specific configuration for envelope encryption.
type AWSKMSConfig struct {
	KeyID  string `yaml:"keyId"`  // KMS key ARN or alias
	Region string `yaml:"region"` // AWS region (uses SDK default if empty)
}

// LockConfig controls the auto-unlock mechanism.
type LockConfig struct {
	Type   string       `yaml:"type"` // "dev", "awskms", "gcpckms", "azurekeyvault"
	AWSKMS AWSKMSConfig `yaml:"awskms"`
}

// StorageConfig controls the backing store.
type StorageConfig struct {
	Type string `yaml:"type"` // "badger"
	Path string `yaml:"path"`
}

// PolicyConfig controls OPA policy evaluation.
type PolicyConfig struct {
	BundlePath    string `yaml:"bundlePath"`
	SigningKeyFile string `yaml:"signingKeyFile"` // PEM public key for bundle verification (empty = no verification)
	SigningKeyID   string `yaml:"signingKeyId"`   // Key ID in .signatures.json (default: "starfly")
}

// RateLimitConfig controls token-bucket rate limiting for the HTTP API.
type RateLimitConfig struct {
	GlobalRate     float64  `yaml:"globalRate"`     // requests per second (default: 100)
	GlobalBurst    int      `yaml:"globalBurst"`    // burst size (default: 100)
	PerIPRate      float64  `yaml:"perIPRate"`      // per-IP requests per second (default: 10)
	PerIPBurst     int      `yaml:"perIPBurst"`     // per-IP burst size (default: 10)
	TrustedProxies []string `yaml:"trustedProxies"` // CIDRs whose X-Forwarded-For header is trusted
}

// TelemetryConfig controls OpenTelemetry tracing.
type TelemetryConfig struct {
	OTLPEndpoint string `yaml:"otlpEndpoint"` // OTLP HTTP endpoint (e.g. "localhost:4318"). Empty = no-op.
}

// NATSConfig controls the embedded or external NATS signal bus.
type NATSConfig struct {
	Embedded     bool   `yaml:"embedded"`     // true = start in-process NATS server
	URL          string `yaml:"url"`          // external NATS URL (ignored when embedded)
	JetStreamDir string `yaml:"jetStreamDir"` // JetStream storage directory
}

// FederationConfig holds cross-fabric signal relay configuration.
// Peers are other Starfly fabrics that should receive relayed revocation signals.
// This is separate from JWKS-based trust federation (ADR-0011); it controls the
// signal relay path (ADR-0031).
type FederationConfig struct {
	Peers []FederationPeer `yaml:"peers"`
}

// FederationPeer defines the signal relay configuration for one peer fabric.
// Field names and YAML tags intentionally match federation.PeerSignalConfig so
// main.go can convert without mapping.
type FederationPeer struct {
	FabricID     string `yaml:"fabricId"`
	Endpoint     string `yaml:"endpoint"`
	Transport    string `yaml:"transport,omitempty"`
	MTLSSecret   string `yaml:"mtlsSecret,omitempty"`
}

// TrustDomain represents a federated trust domain.
type TrustDomain struct {
	Name    string `yaml:"name"`
	Enabled bool   `yaml:"enabled"`
	JWKSURL string `yaml:"jwksURL"`
	Issuer  string `yaml:"issuer"` // OIDC issuer URL for JWT validation
}

// validLockTypes enumerates the accepted lock backends.
var validLockTypes = map[string]bool{
	"dev":           true,
	"awskms":        true,
	"gcpckms":       true,
	"azurekeyvault": true,
}

// DefaultConfig returns a Config populated with production-safe defaults.
func DefaultConfig() *Config {
	return &Config{
		ListenAddr: ":8693",
		LogLevel:   "info",
		LogFormat:  "json",
		Lock: LockConfig{
			Type: "awskms",
		},
		Storage: StorageConfig{
			Type: "badger",
			Path: "/data/starfly",
		},
		Policy: PolicyConfig{
			BundlePath: "/etc/starfly/policies/",
		},
		RateLimit: RateLimitConfig{
			GlobalRate:  100,
			GlobalBurst: 100,
			PerIPRate:   10,
			PerIPBurst:  10,
		},
		NATS: NATSConfig{
			Embedded:     true,
			JetStreamDir: "/data/starfly/nats",
		},
		TLS: TLSConfig{
			ListenAddr: ":8694",
		},
	}
}

// LoadConfig builds a Config by layering: defaults → YAML file → env vars.
// CLI flag overrides are applied by the caller after LoadConfig returns.
func LoadConfig(configPath string) (*Config, error) {
	cfg := DefaultConfig()

	// Layer 2: YAML config file (if provided and exists).
	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config file: %w", err)
		}
	}

	// Layer 3: Environment variable overrides.
	applyEnv(cfg)

	return cfg, nil
}

// envStr sets *dest from the environment variable if present.
func envStr(key string, dest *string) {
	if v := os.Getenv(key); v != "" {
		*dest = v
	}
}

// envBool sets *dest from the environment variable if present ("true"/"1").
func envBool(key string, dest *bool) {
	if v := os.Getenv(key); v != "" {
		*dest = strings.EqualFold(v, "true") || v == "1"
	}
}

// envFloat sets *dest from the environment variable if parseable.
func envFloat(key string, dest *float64) {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			*dest = f
		}
	}
}

// applyEnv overlays environment variables onto the config.
func applyEnv(cfg *Config) {
	envStr("STARFLY_LISTEN_ADDR", &cfg.ListenAddr)
	envStr("STARFLY_LOG_LEVEL", &cfg.LogLevel)
	envStr("STARFLY_LOG_FORMAT", &cfg.LogFormat)
	envBool("STARFLY_DEV_MODE", &cfg.DevMode)
	envStr("STARFLY_LOCK_TYPE", &cfg.Lock.Type)
	envStr("STARFLY_LOCK_AWSKMS_KEY_ID", &cfg.Lock.AWSKMS.KeyID)
	envStr("STARFLY_LOCK_AWSKMS_REGION", &cfg.Lock.AWSKMS.Region)
	envStr("STARFLY_STORAGE_PATH", &cfg.Storage.Path)
	envStr("STARFLY_POLICY_BUNDLE_PATH", &cfg.Policy.BundlePath)
	envStr("STARFLY_POLICY_SIGNING_KEY_FILE", &cfg.Policy.SigningKeyFile)
	envStr("STARFLY_POLICY_SIGNING_KEY_ID", &cfg.Policy.SigningKeyID)
	envFloat("STARFLY_RATELIMIT_GLOBAL_RATE", &cfg.RateLimit.GlobalRate)
	envFloat("STARFLY_RATELIMIT_PER_IP_RATE", &cfg.RateLimit.PerIPRate)

	// NATS: setting URL implies external mode.
	if v := os.Getenv("STARFLY_NATS_URL"); v != "" {
		cfg.NATS.URL = v
		cfg.NATS.Embedded = false
	}
	envStr("STARFLY_NATS_JETSTREAM_DIR", &cfg.NATS.JetStreamDir)

	// TLS overrides.
	envBool("STARFLY_TLS_ENABLED", &cfg.TLS.Enabled)
	envStr("STARFLY_TLS_LISTEN_ADDR", &cfg.TLS.ListenAddr)
	envStr("STARFLY_TLS_CERT_FILE", &cfg.TLS.CertFile)
	envStr("STARFLY_TLS_KEY_FILE", &cfg.TLS.KeyFile)
	envStr("STARFLY_TLS_CLIENT_CA", &cfg.TLS.ClientCA)

	// OTel uses its own env var convention (not STARFLY_ prefix).
	envStr("OTEL_EXPORTER_OTLP_ENDPOINT", &cfg.Telemetry.OTLPEndpoint)

	// Lifecycle / Temporal overrides.
	envBool("STARFLY_LIFECYCLE_ENABLED", &cfg.Lifecycle.Enabled)
	envStr("STARFLY_LIFECYCLE_TEMPORAL_HOST_PORT", &cfg.Lifecycle.Temporal.HostPort)
	envStr("STARFLY_LIFECYCLE_TEMPORAL_NAMESPACE", &cfg.Lifecycle.Temporal.Namespace)
	envStr("STARFLY_LIFECYCLE_TEMPORAL_TASK_QUEUE", &cfg.Lifecycle.Temporal.TaskQueue)
}

// Validate checks that the config is internally consistent.
// Call after all layers (file, env, flags) have been applied.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listenAddr must not be empty")
	}
	if !validLockTypes[c.Lock.Type] {
		return fmt.Errorf("unknown lock type %q (valid: dev, awskms, gcpckms, azurekeyvault)", c.Lock.Type)
	}
	if c.Lock.Type == "awskms" && c.Lock.AWSKMS.KeyID == "" {
		return fmt.Errorf("lock.awskms.keyId must not be empty when lock type is awskms")
	}
	if c.Storage.Path == "" {
		return fmt.Errorf("storage.path must not be empty")
	}
	if c.TLS.Enabled {
		if c.TLS.CertFile == "" {
			return fmt.Errorf("tls.certFile must not be empty when TLS is enabled")
		}
		if c.TLS.KeyFile == "" {
			return fmt.Errorf("tls.keyFile must not be empty when TLS is enabled")
		}
		if c.TLS.ClientCA == "" {
			return fmt.Errorf("tls.clientCA must not be empty when TLS is enabled")
		}
		if c.TLS.ListenAddr == "" {
			return fmt.Errorf("tls.listenAddr must not be empty when TLS is enabled")
		}
	}
	return nil
}

// GenerateUnitID returns a short random hex string identifying this Starfly unit.
func GenerateUnitID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("unit-%d", 0)
	}
	return hex.EncodeToString(b)
}
