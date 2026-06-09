package core

import (
	"testing"
)

func TestGenerateUnitID(t *testing.T) {
	id := GenerateUnitID()
	if id == "" {
		t.Fatal("GenerateUnitID returned empty string")
	}
	if len(id) != 12 { // 6 bytes = 12 hex chars
		t.Errorf("GenerateUnitID length = %d, want 12", len(id))
	}

	id2 := GenerateUnitID()
	if id == id2 {
		t.Error("two GenerateUnitID calls should return different values")
	}
}

func TestAssuranceLevel_Nil(t *testing.T) {
	var a *ServerAttestation
	if got := a.AssuranceLevel(); got != "none" {
		t.Errorf("AssuranceLevel() = %q, want %q", got, "none")
	}
}

func TestAssuranceLevel_SoftwareOnly(t *testing.T) {
	a := &ServerAttestation{
		Platform: ServerAttestPlatform{Source: "aws", CredType: "iam-role"},
	}
	if got := a.AssuranceLevel(); got != "software" {
		t.Errorf("AssuranceLevel() = %q, want %q", got, "software")
	}
}

func TestAssuranceLevel_Hardware(t *testing.T) {
	a := &ServerAttestation{
		Platform: ServerAttestPlatform{Source: "aws", CredType: "iam-role"},
		Hardware: []*ServerAttestHardware{
			{Type: "tpm", Nonce: []byte("test")},
		},
	}
	if got := a.AssuranceLevel(); got != "hardware" {
		t.Errorf("AssuranceLevel() = %q, want %q", got, "hardware")
	}
}

func TestEnvFloat(t *testing.T) {
	var dest float64

	// Valid float.
	t.Setenv("TEST_FLOAT", "42.5")
	envFloat("TEST_FLOAT", &dest)
	if dest != 42.5 {
		t.Errorf("envFloat = %f, want 42.5", dest)
	}

	// Invalid float (should not change dest).
	dest = 0
	t.Setenv("TEST_FLOAT_BAD", "not-a-number")
	envFloat("TEST_FLOAT_BAD", &dest)
	if dest != 0 {
		t.Errorf("envFloat with invalid value = %f, want 0", dest)
	}

	// Empty env var (should not change dest).
	dest = 99
	t.Setenv("TEST_FLOAT_EMPTY", "")
	envFloat("TEST_FLOAT_EMPTY", &dest)
	if dest != 99 {
		t.Errorf("envFloat with empty value = %f, want 99", dest)
	}
}

func TestValidate_TLSEnabled_EmptyListenAddr(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Lock.Type = "dev"
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = "/path/to/cert.pem"
	cfg.TLS.KeyFile = "/path/to/key.pem"
	cfg.TLS.ClientCA = "/path/to/ca.pem"
	cfg.TLS.ListenAddr = ""
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should reject TLS enabled with empty listenAddr")
	}
}

func TestLoadConfig_NATSURLOverride(t *testing.T) {
	clearEnv(t)

	t.Setenv("STARFLY_NATS_URL", "nats://external:4222")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.NATS.URL != "nats://external:4222" {
		t.Errorf("NATS.URL = %q, want nats://external:4222", cfg.NATS.URL)
	}
	if cfg.NATS.Embedded {
		t.Error("NATS.Embedded should be false when URL is set")
	}
}

func TestLoadConfig_LifecycleEnvOverrides(t *testing.T) {
	clearEnv(t)

	t.Setenv("STARFLY_LIFECYCLE_ENABLED", "true")
	t.Setenv("STARFLY_LIFECYCLE_TEMPORAL_HOST_PORT", "temporal:7233")
	t.Setenv("STARFLY_LIFECYCLE_TEMPORAL_NAMESPACE", "custom-ns")
	t.Setenv("STARFLY_LIFECYCLE_TEMPORAL_TASK_QUEUE", "custom-queue")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if !cfg.Lifecycle.Enabled {
		t.Error("Lifecycle.Enabled should be true")
	}
	if cfg.Lifecycle.Temporal.HostPort != "temporal:7233" {
		t.Errorf("Lifecycle.Temporal.HostPort = %q, want temporal:7233", cfg.Lifecycle.Temporal.HostPort)
	}
	if cfg.Lifecycle.Temporal.Namespace != "custom-ns" {
		t.Errorf("Lifecycle.Temporal.Namespace = %q, want custom-ns", cfg.Lifecycle.Temporal.Namespace)
	}
	if cfg.Lifecycle.Temporal.TaskQueue != "custom-queue" {
		t.Errorf("Lifecycle.Temporal.TaskQueue = %q, want custom-queue", cfg.Lifecycle.Temporal.TaskQueue)
	}
}

func TestLoadConfig_OTelEndpointOverride(t *testing.T) {
	clearEnv(t)

	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel:4318")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.Telemetry.OTLPEndpoint != "http://otel:4318" {
		t.Errorf("Telemetry.OTLPEndpoint = %q, want http://otel:4318", cfg.Telemetry.OTLPEndpoint)
	}
}

func TestLoadConfig_RateLimitEnvOverrides(t *testing.T) {
	clearEnv(t)

	t.Setenv("STARFLY_RATELIMIT_GLOBAL_RATE", "200.5")
	t.Setenv("STARFLY_RATELIMIT_PER_IP_RATE", "50.0")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.RateLimit.GlobalRate != 200.5 {
		t.Errorf("RateLimit.GlobalRate = %f, want 200.5", cfg.RateLimit.GlobalRate)
	}
	if cfg.RateLimit.PerIPRate != 50.0 {
		t.Errorf("RateLimit.PerIPRate = %f, want 50.0", cfg.RateLimit.PerIPRate)
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	clearEnv(t)

	content := `{{{{ invalid yaml`
	path := writeTemp(t, "bad-config-*.yaml", content)

	_, err := LoadConfig(path)
	if err == nil {
		t.Error("LoadConfig should fail on invalid YAML")
	}
}

func TestLoadConfig_EnvStoragePath(t *testing.T) {
	clearEnv(t)

	t.Setenv("STARFLY_STORAGE_PATH", "/custom/storage")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.Storage.Path != "/custom/storage" {
		t.Errorf("Storage.Path = %q, want /custom/storage", cfg.Storage.Path)
	}
}

func TestLoadConfig_ListenAddrEnvOverride(t *testing.T) {
	clearEnv(t)

	t.Setenv("STARFLY_LISTEN_ADDR", ":9999")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.ListenAddr != ":9999" {
		t.Errorf("ListenAddr = %q, want :9999", cfg.ListenAddr)
	}
}

func TestLoadConfig_LogFormatEnvOverride(t *testing.T) {
	clearEnv(t)

	t.Setenv("STARFLY_LOG_FORMAT", "text")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.LogFormat != "text" {
		t.Errorf("LogFormat = %q, want text", cfg.LogFormat)
	}
}

func TestLoadConfig_LockAWSKMSEnvOverrides(t *testing.T) {
	clearEnv(t)

	t.Setenv("STARFLY_LOCK_AWSKMS_KEY_ID", "arn:aws:kms:us-east-1:123:key/abc")
	t.Setenv("STARFLY_LOCK_AWSKMS_REGION", "us-west-2")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.Lock.AWSKMS.KeyID != "arn:aws:kms:us-east-1:123:key/abc" {
		t.Errorf("Lock.AWSKMS.KeyID = %q", cfg.Lock.AWSKMS.KeyID)
	}
	if cfg.Lock.AWSKMS.Region != "us-west-2" {
		t.Errorf("Lock.AWSKMS.Region = %q", cfg.Lock.AWSKMS.Region)
	}
}

func TestLoadConfig_NATSJetStreamDirEnvOverride(t *testing.T) {
	clearEnv(t)

	t.Setenv("STARFLY_NATS_JETSTREAM_DIR", "/custom/js")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.NATS.JetStreamDir != "/custom/js" {
		t.Errorf("NATS.JetStreamDir = %q, want /custom/js", cfg.NATS.JetStreamDir)
	}
}

func TestLoadConfig_PolicyBundlePathEnvOverride(t *testing.T) {
	clearEnv(t)

	t.Setenv("STARFLY_POLICY_BUNDLE_PATH", "/custom/policies")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.Policy.BundlePath != "/custom/policies" {
		t.Errorf("Policy.BundlePath = %q, want /custom/policies", cfg.Policy.BundlePath)
	}
}
