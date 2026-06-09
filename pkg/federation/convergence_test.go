package federation

import (
	"testing"

	"github.com/starfly-fabrics/starfly/pkg/soul"
)

// TestConvergence_AddPeer verifies that adding a peer to spec triggers ActionAddPeer.
func TestConvergence_AddPeer(t *testing.T) {
	current := soul.NewManifest("test-fabric", 1)
	current.Identity.SigningKeys = []soul.SigningKeyRef{{KID: "k1", Status: "active"}}

	spec := soul.NewManifest("test-fabric", 0)
	spec.Identity.SigningKeys = []soul.SigningKeyRef{{KID: "k1", Status: "active"}}
	spec.Federation.Peers = []soul.FederationPeer{
		{FabricID: "eu-west-1"},
		{FabricID: "ap-southeast-1"},
	}

	plan, err := soul.Converge(current, spec)
	if err != nil {
		t.Fatalf("Converge error: %v", err)
	}

	addPeerCount := countActions(plan, soul.ActionAddPeer)
	if addPeerCount != 2 {
		t.Errorf("expected 2 add_peer actions, got %d", addPeerCount)
	}
}

// TestConvergence_RemovePeer verifies that removing a peer from spec triggers ActionRemovePeer.
func TestConvergence_RemovePeer(t *testing.T) {
	current := soul.NewManifest("test-fabric", 1)
	current.Identity.SigningKeys = []soul.SigningKeyRef{{KID: "k1", Status: "active"}}
	current.Federation.Peers = []soul.FederationPeer{
		{FabricID: "eu-west-1"},
		{FabricID: "ap-southeast-1"},
	}

	spec := soul.NewManifest("test-fabric", 0)
	spec.Identity.SigningKeys = []soul.SigningKeyRef{{KID: "k1", Status: "active"}}
	spec.Federation.Peers = []soul.FederationPeer{
		{FabricID: "eu-west-1"}, // keep this one
	}

	plan, err := soul.Converge(current, spec)
	if err != nil {
		t.Fatalf("Converge error: %v", err)
	}

	removePeerCount := countActions(plan, soul.ActionRemovePeer)
	if removePeerCount != 1 {
		t.Errorf("expected 1 remove_peer action, got %d", removePeerCount)
	}

	// eu-west-1 should NOT be removed.
	for _, a := range plan.Actions {
		if a.Type == soul.ActionRemovePeer && a.Target == "eu-west-1" {
			t.Error("eu-west-1 should not be removed — it's in the spec")
		}
	}
}

// TestConvergence_NoPeerChange verifies no actions when peers match.
func TestConvergence_NoPeerChange(t *testing.T) {
	current := soul.NewManifest("test-fabric", 1)
	current.Identity.SigningKeys = []soul.SigningKeyRef{{KID: "k1", Status: "active"}}
	current.Federation.Peers = []soul.FederationPeer{
		{FabricID: "eu-west-1"},
	}

	spec := soul.NewManifest("test-fabric", 0)
	spec.Identity.SigningKeys = []soul.SigningKeyRef{{KID: "k1", Status: "active"}}
	spec.Federation.Peers = []soul.FederationPeer{
		{FabricID: "eu-west-1"},
	}

	plan, err := soul.Converge(current, spec)
	if err != nil {
		t.Fatalf("Converge error: %v", err)
	}

	peerActions := countActions(plan, soul.ActionAddPeer) + countActions(plan, soul.ActionRemovePeer)
	if peerActions != 0 {
		t.Errorf("expected 0 peer actions when peers match, got %d", peerActions)
	}
}

// TestConvergence_EmptyToFederated verifies going from no federation to federated.
func TestConvergence_EmptyToFederated(t *testing.T) {
	current := soul.NewManifest("test-fabric", 1)
	current.Identity.SigningKeys = []soul.SigningKeyRef{{KID: "k1", Status: "active"}}
	// No federation peers in current.

	spec := soul.NewManifest("test-fabric", 0)
	spec.Identity.SigningKeys = []soul.SigningKeyRef{{KID: "k1", Status: "active"}}
	spec.Federation.Peers = []soul.FederationPeer{
		{FabricID: "peer-1"},
	}

	plan, err := soul.Converge(current, spec)
	if err != nil {
		t.Fatalf("Converge error: %v", err)
	}

	if countActions(plan, soul.ActionAddPeer) != 1 {
		t.Errorf("expected 1 add_peer, got %d", countActions(plan, soul.ActionAddPeer))
	}
}

func countActions(plan *soul.ConvergencePlan, actionType soul.ActionType) int {
	n := 0
	for _, a := range plan.Actions {
		if a.Type == actionType {
			n++
		}
	}
	return n
}
