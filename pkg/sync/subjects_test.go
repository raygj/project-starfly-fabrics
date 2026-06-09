package sync

import (
	"strings"
	"testing"
)

func TestSignalConstants_NonEmpty(t *testing.T) {
	signals := []struct {
		name  string
		value string
	}{
		{"SignalIdentityMinted", SignalIdentityMinted},
		{"SignalIdentityRevoked", SignalIdentityRevoked},
		{"SignalIdentityExpired", SignalIdentityExpired},
		{"SignalFabricRotation", SignalFabricRotation},
		{"SignalFabricSoul", SignalFabricSoul},
		{"SignalFabricSOS", SignalFabricSOS},
		{"SignalFabricHealth", SignalFabricHealth},
		{"SignalPolicyUpdated", SignalPolicyUpdated},
		{"SignalCAEPSessionRevoked", SignalCAEPSessionRevoked},
		{"SignalCAEPCredentialChange", SignalCAEPCredentialChange},
		{"SignalCAEPTokenClaimsChange", SignalCAEPTokenClaimsChange},
	}

	for _, s := range signals {
		t.Run(s.name, func(t *testing.T) {
			if s.value == "" {
				t.Errorf("%s is empty", s.name)
			}
			// No leading/trailing dots.
			if strings.HasPrefix(s.value, ".") || strings.HasSuffix(s.value, ".") {
				t.Errorf("%s = %q has leading/trailing dot", s.name, s.value)
			}
			// No spaces.
			if strings.Contains(s.value, " ") {
				t.Errorf("%s = %q contains spaces", s.name, s.value)
			}
		})
	}
}

func TestSignalConstants_UsableInFlash(t *testing.T) {
	// Verify that signal constants work with the signalSubject method.
	// The subject format is: starfly.{trust_domain}.{signal_type}
	bus := &Bus{trustDomain: "example.com", unitID: "test"}

	subject := bus.signalSubject(SignalIdentityMinted)
	want := "starfly.example.com.identity.minted"
	if subject != want {
		t.Errorf("signalSubject(%q) = %q, want %q", SignalIdentityMinted, subject, want)
	}

	subject = bus.signalSubject(SignalFabricSoul)
	want = "starfly.example.com.fabric.soul"
	if subject != want {
		t.Errorf("signalSubject(%q) = %q, want %q", SignalFabricSoul, subject, want)
	}
}
