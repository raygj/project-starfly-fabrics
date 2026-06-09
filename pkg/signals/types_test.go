package signals

import (
	"testing"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

func TestNewSecurityEvent(t *testing.T) {
	subID := &core.SubjectIdentifier{
		Format:   "spiffe",
		SpiffeID: "spiffe://example.com/workload-1",
	}

	evt := NewSecurityEvent("starfly-unit-1", "receiver.example.com", subID)

	if evt.Issuer != "starfly-unit-1" {
		t.Errorf("Issuer = %q, want %q", evt.Issuer, "starfly-unit-1")
	}
	if evt.Audience != "receiver.example.com" {
		t.Errorf("Audience = %q, want %q", evt.Audience, "receiver.example.com")
	}
	if evt.JTI == "" {
		t.Error("JTI should not be empty")
	}
	if evt.IssuedAt == 0 {
		t.Error("IssuedAt should not be zero")
	}
	if evt.SubjectID == nil {
		t.Fatal("SubjectID should not be nil")
	}
	if evt.SubjectID.Format != "spiffe" {
		t.Errorf("SubjectID.Format = %q, want %q", evt.SubjectID.Format, "spiffe")
	}
	if evt.Events == nil {
		t.Error("Events map should be initialized")
	}
}

func TestAddEvent(t *testing.T) {
	evt := NewSecurityEvent("issuer", "audience", &core.SubjectIdentifier{
		Format: "iss_sub",
		Email:  "test@example.com",
	})

	claims := map[string]interface{}{
		"change_type":       ChangeTypeRevoke,
		"credential_type":   "jwt",
		"reason_admin":      ReasonPolicy,
	}
	AddEvent(evt, EventCredentialChange, claims)

	if len(evt.Events) != 1 {
		t.Fatalf("Events count = %d, want 1", len(evt.Events))
	}

	eventClaims, ok := evt.Events[EventCredentialChange]
	if !ok {
		t.Fatal("EventCredentialChange not found in Events")
	}
	if eventClaims["change_type"] != ChangeTypeRevoke {
		t.Errorf("change_type = %v, want %q", eventClaims["change_type"], ChangeTypeRevoke)
	}
}

func TestGenerateJTI_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		jti := generateJTI()
		if jti == "" {
			t.Fatal("generateJTI returned empty string")
		}
		if len(jti) != 32 { // 16 bytes = 32 hex chars
			t.Errorf("JTI length = %d, want 32", len(jti))
		}
		if seen[jti] {
			t.Fatalf("duplicate JTI generated: %s", jti)
		}
		seen[jti] = true
	}
}

func TestEventTypes(t *testing.T) {
	types := EventTypes()
	if len(types) == 0 {
		t.Fatal("EventTypes() returned empty list")
	}

	// Verify key CAEP/RISC types are present.
	want := map[string]bool{
		EventCredentialChange:       false,
		EventSessionRevoked:         false,
		EventDeviceComplianceChange: false,
		EventAccountDisabled:        false,
		EventTokenRevoked:           false,
	}

	for _, et := range types {
		if _, ok := want[et]; ok {
			want[et] = true
		}
	}

	for et, found := range want {
		if !found {
			t.Errorf("EventTypes() missing %q", et)
		}
	}
}

func TestRevocationEntry(t *testing.T) {
	// Verify struct can be constructed (compile-time check mostly).
	entry := core.RevocationEntry{
		SubjectID: "wimse://example.com/ns/default/sa/app",
		Reason:    "session-revoked",
	}
	if entry.SubjectID == "" {
		t.Error("SubjectID should not be empty")
	}
}
