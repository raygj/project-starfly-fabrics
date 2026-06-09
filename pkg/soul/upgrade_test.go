package soul

import (
	"context"
	"testing"
)

func specManifest() *SoulManifest {
	m := NewManifest("test-fabric", 1)
	m.Identity.SigningKeys = []SigningKeyRef{
		{KMSKeyID: "arn:key/1", Algorithm: "RS256", KID: "key-1", Status: "active"},
	}
	m.TrustDomains = []TrustDomainSpec{
		{Name: "prod.acme.com", Issuer: "https://idp.acme.com", Enabled: true},
		{Name: "123456789012", Type: "aws-sts", Enabled: true},
	}
	return m
}

func TestConverge_NoOp(t *testing.T) {
	current := specManifest()
	spec := specManifest()

	plan, err := Converge(current, spec, WithImportRevocations(false))
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}

	// Should only have the reset revocations action (no domain/key changes).
	for _, a := range plan.Actions {
		if a.Type == ActionAddTrustDomain || a.Type == ActionRemoveTrustDomain ||
			a.Type == ActionUpdateTrustDomain || a.Type == ActionRotateSigningKey {
			t.Errorf("unexpected action: %s — %s", a.Type, a.Description)
		}
	}
}

func TestConverge_AddTrustDomain(t *testing.T) {
	current := specManifest()
	spec := specManifest()
	spec.TrustDomains = append(spec.TrustDomains, TrustDomainSpec{
		Name: "new-domain.com", Type: "oidc", Enabled: true,
	})

	plan, err := Converge(current, spec)
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}

	found := findAction(plan, ActionAddTrustDomain, "new-domain.com")
	if !found {
		t.Error("expected AddTrustDomain action for new-domain.com")
	}
}

func TestConverge_RemoveTrustDomain(t *testing.T) {
	current := specManifest()
	spec := specManifest()
	// Remove the second trust domain from spec.
	spec.TrustDomains = spec.TrustDomains[:1]

	plan, err := Converge(current, spec)
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}

	found := findAction(plan, ActionRemoveTrustDomain, "123456789012")
	if !found {
		t.Error("expected RemoveTrustDomain action for 123456789012")
	}
}

func TestConverge_UpdateTrustDomain(t *testing.T) {
	current := specManifest()
	spec := specManifest()
	// Change the issuer of first domain.
	spec.TrustDomains[0].Issuer = "https://new-idp.acme.com"

	plan, err := Converge(current, spec)
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}

	found := findAction(plan, ActionUpdateTrustDomain, "prod.acme.com")
	if !found {
		t.Error("expected UpdateTrustDomain action for prod.acme.com")
	}
}

func TestConverge_RotateSigningKey(t *testing.T) {
	current := specManifest()
	spec := specManifest()
	// Change the KMS key ID.
	spec.Identity.SigningKeys = []SigningKeyRef{
		{KMSKeyID: "arn:key/2", Algorithm: "RS256", KID: "key-2", Status: "active"},
	}

	plan, err := Converge(current, spec)
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}

	found := findAction(plan, ActionRotateSigningKey, "key-2")
	if !found {
		t.Error("expected RotateSigningKey action for key-2")
	}
}

func TestConverge_ImportRevocations(t *testing.T) {
	current := specManifest()
	current.Revocations = RevocationSnapshot{Count: 500}
	spec := specManifest()

	plan, err := Converge(current, spec, WithImportRevocations(true))
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}

	found := findAction(plan, ActionImportRevocations, "")
	if !found {
		t.Error("expected ImportRevocations action")
	}
}

func TestConverge_ResetRevocations(t *testing.T) {
	current := specManifest()
	current.Revocations = RevocationSnapshot{Count: 500}
	spec := specManifest()

	plan, err := Converge(current, spec, WithImportRevocations(false))
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}

	found := findAction(plan, ActionResetRevocations, "")
	if !found {
		t.Error("expected ResetRevocations action")
	}
	// Should NOT have import action.
	foundImport := findAction(plan, ActionImportRevocations, "")
	if foundImport {
		t.Error("should not have ImportRevocations when reset is requested")
	}
}

func TestConverge_NilCurrent(t *testing.T) {
	spec := specManifest()

	plan, err := Converge(nil, spec)
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}

	// All spec domains should be added.
	addCount := 0
	for _, a := range plan.Actions {
		if a.Type == ActionAddTrustDomain {
			addCount++
		}
	}
	if addCount != 2 {
		t.Errorf("expected 2 AddTrustDomain actions, got %d", addCount)
	}
}

func TestConverge_SSFStreams(t *testing.T) {
	current := specManifest()
	current.SSFStreams = []SSFStreamSpec{
		{StreamID: "stream-old", Transmitter: "https://old.example.com"},
	}

	spec := specManifest()
	spec.SSFStreams = []SSFStreamSpec{
		{StreamID: "stream-new", Transmitter: "https://new.example.com"},
	}

	plan, err := Converge(current, spec)
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}

	foundAdd := findAction(plan, ActionAddSSFStream, "stream-new")
	foundRemove := findAction(plan, ActionRemoveSSFStream, "stream-old")
	if !foundAdd {
		t.Error("expected AddSSFStream for stream-new")
	}
	if !foundRemove {
		t.Error("expected RemoveSSFStream for stream-old")
	}
}

func TestConvergencePlan_IsEmpty(t *testing.T) {
	plan := &ConvergencePlan{}
	if !plan.IsEmpty() {
		t.Error("empty plan should return IsEmpty=true")
	}

	plan.Actions = append(plan.Actions, ConvergenceAction{Type: ActionResetRevocations})
	if plan.IsEmpty() {
		t.Error("non-empty plan should return IsEmpty=false")
	}
}

func TestApply_EmptyPlan(t *testing.T) {
	plan := &ConvergencePlan{}
	if err := Apply(context.Background(), plan); err != nil {
		t.Fatalf("Apply empty plan: %v", err)
	}
}

func TestApply_NonEmptyPlan(t *testing.T) {
	plan := &ConvergencePlan{
		Actions: []ConvergenceAction{
			{Type: ActionAddTrustDomain, Description: "add domain", Target: "test.com"},
		},
	}
	// Should not panic or error — just logs.
	if err := Apply(context.Background(), plan); err != nil {
		t.Fatalf("Apply: %v", err)
	}
}

func findAction(plan *ConvergencePlan, actionType ActionType, target string) bool {
	for _, a := range plan.Actions {
		if a.Type == actionType {
			if target == "" || a.Target == target {
				return true
			}
		}
	}
	return false
}
