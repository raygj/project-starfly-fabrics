package lifecycle

import "time"

// Finding represents a compliance check result.
type Finding struct {
	ID              string    `json:"id"`
	Severity        string    `json:"severity"` // "info", "warning", "critical"
	Category        string    `json:"category"` // "ttl", "dpop", "delegation", "blast-radius", "performance", "revocation-health"
	Subject         string    `json:"subject"`
	Description     string    `json:"description"`
	Recommendation  string    `json:"recommendation"`
	AutoRemediable  bool      `json:"auto_remediable"`
	DetectedAt      time.Time `json:"detected_at"`
}

// ScanReport is the output of a compliance scan workflow.
type ScanReport struct {
	TotalCredentials int       `json:"total_credentials"`
	Compliant        int       `json:"compliant"`
	NonCompliant     int       `json:"non_compliant"`
	Findings         []Finding `json:"findings"`
	Duration         time.Duration `json:"duration"`
	Timestamp        time.Time `json:"timestamp"`
}

// ScanParams configures a compliance scan workflow run.
type ScanParams struct {
	// Scope limits the scan to specific trust domains (empty = all).
	Scope []string `json:"scope,omitempty"`

	// EmitFindings controls whether SSF events are emitted for each finding.
	EmitFindings bool `json:"emit_findings"`

	// AutoRemediate enables automatic remediation of critical findings.
	// Off by default — report-only mode is the safe default.
	AutoRemediate bool `json:"auto_remediate"`
}

// DefaultScanParams returns sensible defaults for compliance scanning.
func DefaultScanParams() ScanParams {
	return ScanParams{
		EmitFindings:  true,
		AutoRemediate: false,
	}
}

// PerformanceMetrics captures current system performance for baseline comparison.
type PerformanceMetrics struct {
	ExchangeP99ms       float64   `json:"exchange_p99_ms"`
	RevocationLookupMs  float64   `json:"revocation_lookup_ms"`
	SignalCascadeS      float64   `json:"signal_cascade_s"`
	RevocationIndexSize int       `json:"revocation_index_size"`
	Timestamp           time.Time `json:"timestamp"`
}

// PerformanceThresholds defines acceptable performance bounds.
type PerformanceThresholds struct {
	ExchangeP99ms      float64 `json:"exchange_p99_ms" yaml:"exchangeP99Ms"`       // default: 15
	RevocationLookupMs float64 `json:"revocation_lookup_ms" yaml:"revocationLookupMs"` // default: 1
	SignalCascadeS     float64 `json:"signal_cascade_s" yaml:"signalCascadeS"`       // default: 2
}

// DefaultPerformanceThresholds returns the P5-007 baseline targets.
func DefaultPerformanceThresholds() PerformanceThresholds {
	return PerformanceThresholds{
		ExchangeP99ms:      15,
		RevocationLookupMs: 1,
		SignalCascadeS:     2,
	}
}

// CompliancePolicy defines the rules for compliance evaluation.
type CompliancePolicy struct {
	MaxTTL              time.Duration         `json:"max_ttl" yaml:"maxTtl"`
	RequireDPoP         bool                  `json:"require_dpop" yaml:"requireDPoP"`
	MaxDelegationDepth  int                   `json:"max_delegation_depth" yaml:"maxDelegationDepth"`
	MaxBlastRadius      string                `json:"max_blast_radius" yaml:"maxBlastRadius"`
	Performance         PerformanceThresholds `json:"performance" yaml:"performance"`
}

// DefaultCompliancePolicy returns sensible compliance defaults.
func DefaultCompliancePolicy() CompliancePolicy {
	return CompliancePolicy{
		MaxTTL:             5 * time.Minute,
		RequireDPoP:        false,
		MaxDelegationDepth: 5,
		MaxBlastRadius:     "namespace",
		Performance:        DefaultPerformanceThresholds(),
	}
}

// CredentialContext is metadata about an active credential for compliance checking.
type CredentialContext struct {
	TrustDomain     string    `json:"trust_domain"`
	SubjectID       string    `json:"subject_id"`
	TokenType       string    `json:"token_type"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	HasDPoP         bool      `json:"has_dpop"`
	DelegationDepth int       `json:"delegation_depth"`
	BlastRadius     string    `json:"blast_radius"`
	Capabilities    []string  `json:"capabilities"`
}
