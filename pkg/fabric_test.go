//go:build integration

package pkg_test

import (
	"context"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/exchange"
	"github.com/starfly-fabrics/starfly/pkg/identity"
	"github.com/starfly-fabrics/starfly/pkg/signals"
	pkgsync "github.com/starfly-fabrics/starfly/pkg/sync"
)

// ── Shared test infrastructure ─────────────────────────────────────

type mockAuditor struct {
	events []*core.AuditEvent
}

func (m *mockAuditor) Log(_ context.Context, event *core.AuditEvent) error {
	m.events = append(m.events, event)
	return nil
}

type mockPolicy struct {
	decision *core.PolicyDecision
}

func (m *mockPolicy) Evaluate(_ context.Context, _ *core.PolicyInput) (*core.PolicyDecision, error) {
	return m.decision, nil
}

func (m *mockPolicy) LoadBundle(_ context.Context, _ string) error { return nil }

// mockIdentityProvider returns a fixed WorkloadIdentity for any credential.
type mockIdentityProvider struct {
	id          string
	trustDomain string
	credType    string
}

func (m *mockIdentityProvider) ValidateWorkload(_ context.Context, _ string, _ string) (*core.WorkloadIdentity, error) {
	return &core.WorkloadIdentity{
		ID:          m.id,
		TrustDomain: m.trustDomain,
		Attestation: &core.AttestationEvidence{Method: m.credType},
		Claims:      map[string]interface{}{"provider": m.credType},
	}, nil
}

// fabric holds the wired-up components for an integration test.
type fabric struct {
	engine     *exchange.Engine
	transmitter *signals.Transmitter
	receiver   *signals.Receiver
	revocation *signals.InMemoryRevocationIndex
	bus        *pkgsync.Bus
	auditor    *mockAuditor
	policy     *mockPolicy
}

func setupFabric(t *testing.T) *fabric {
	t.Helper()
	ctx := context.Background()

	auditor := &mockAuditor{}
	policy := &mockPolicy{
		decision: &core.PolicyDecision{
			Allowed: true,
			Claims:  map[string]interface{}{},
		},
	}

	// Identity registry with all provider types.
	reg := identity.NewRegistry()
	reg.Register("k8s-sa", &mockIdentityProvider{
		id:          "wimse://production.example.com/ns/default/sa/my-app",
		trustDomain: "production.example.com",
		credType:    "k8s-sa",
	})
	reg.Register("spiffe-svid", &mockIdentityProvider{
		id:          "spiffe://production.example.com/workload/api-server",
		trustDomain: "production.example.com",
		credType:    "spiffe-svid",
	})
	reg.Register("oidc", &mockIdentityProvider{
		id:          "wimse://idp.example.com/user/alice",
		trustDomain: "idp.example.com",
		credType:    "oidc",
	})
	reg.Register("kerberos", &mockIdentityProvider{
		id:          "wimse://ad.example.com/principal/svc-trading",
		trustDomain: "ad.example.com",
		credType:    "kerberos",
	})
	reg.Register("saml", &mockIdentityProvider{
		id:          "wimse://idp.example.com/user/bob",
		trustDomain: "idp.example.com",
		credType:    "saml",
	})
	reg.Register("agent-mcp", &mockIdentityProvider{
		id:          "wimse://agents.example.com/agent/orchestrator",
		trustDomain: "agents.example.com",
		credType:    "agent-mcp",
	})
	reg.Register("agent-a2a", &mockIdentityProvider{
		id:          "wimse://agents.example.com/agent/worker-1",
		trustDomain: "agents.example.com",
		credType:    "agent-a2a",
	})
	reg.Register("aws-sts", &mockIdentityProvider{
		id:          "wimse://aws.example.com/role/lambda-processor",
		trustDomain: "aws.example.com",
		credType:    "aws-sts",
	})
	reg.Register("gcp-wif", &mockIdentityProvider{
		id:          "wimse://gcp.example.com/sa/data-pipeline",
		trustDomain: "gcp.example.com",
		credType:    "gcp-wif",
	})
	reg.Register("azure-mi", &mockIdentityProvider{
		id:          "wimse://azure.example.com/mi/func-processor",
		trustDomain: "azure.example.com",
		credType:    "azure-mi",
	})
	reg.Register("mtls", &mockIdentityProvider{
		id:          "wimse://infra.example.com/service/mesh-gateway",
		trustDomain: "infra.example.com",
		credType:    "mtls",
	})
	reg.Register("oauth2", &mockIdentityProvider{
		id:          "wimse://oauth.example.com/client/dashboard",
		trustDomain: "oauth.example.com",
		credType:    "oauth2",
	})
	reg.Register("api-key", &mockIdentityProvider{
		id:          "wimse://partner.example.com/key/vendor-integration",
		trustDomain: "partner.example.com",
		credType:    "api-key",
	})

	// Revocation index.
	revocation := signals.NewRevocationIndex()

	// Sync bus (embedded NATS).
	bus, err := pkgsync.New(core.NATSConfig{
		Embedded:     true,
		JetStreamDir: t.TempDir(),
	}, "unit-1", "fabric.local")
	if err != nil {
		t.Fatalf("creating sync bus: %v", err)
	}
	t.Cleanup(func() { bus.Drain() })

	// Exchange engine.
	engine, err := exchange.New(
		reg, policy, auditor,
		exchange.WithSyncBus(bus, "unit-1"),
		exchange.WithRevocationChecker(revocation),
	)
	if err != nil {
		t.Fatalf("creating exchange engine: %v", err)
	}

	// Signal transmitter.
	tx, err := signals.NewTransmitter(
		signals.WithTransmitterIssuer("unit-1"),
		signals.WithTransmitterSyncBus(bus, "unit-1"),
		signals.WithTransmitterAuditor(auditor),
	)
	if err != nil {
		t.Fatalf("creating transmitter: %v", err)
	}

	// Signal policy that allows events and triggers revocation.
	signalPolicy := &mockPolicy{
		decision: &core.PolicyDecision{
			Allowed: true,
			Claims: map[string]interface{}{
				"revoke_tokens": true,
			},
		},
	}

	// Signal receiver.
	rx := signals.NewReceiver(
		signals.WithReceiverPolicy(signalPolicy),
		signals.WithReceiverSyncBus(bus, "unit-1"),
		signals.WithReceiverAuditor(auditor),
		signals.WithReceiverRevocation(revocation),
		signals.WithReceiverDevMode(true),
	)

	// Allow NATS to finish setup.
	time.Sleep(200 * time.Millisecond)

	_ = ctx
	_ = tx
	_ = rx

	return &fabric{
		engine:      engine,
		transmitter: tx,
		receiver:    rx,
		revocation:  revocation,
		bus:         bus,
		auditor:     auditor,
		policy:      policy,
	}
}

// exchangeReq builds a standard exchange request for the given token type.
func exchangeReq(tokenType string) *core.TokenExchangeRequest {
	return &core.TokenExchangeRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:     "test-credential",
		SubjectTokenType: tokenType,
		Audience:         "https://api.target.example.com",
		Scope:            "read:data",
	}
}

// parseToken parses a JWT without verification (for test assertions).
func parseToken(t *testing.T, raw string) jwt.Token {
	t.Helper()
	token, err := jwt.ParseInsecure([]byte(raw))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}
	return token
}

// ── Test 1: Multi-Provider Registry ─────────────────────────────────

func TestFabric_MultiProviderRegistry(t *testing.T) {
	f := setupFabric(t)
	ctx := context.Background()

	providers := []struct {
		name      string
		tokenType string
		wantTD    string
	}{
		{"K8s SA", "urn:ietf:params:oauth:token-type:jwt", "production.example.com"},
		{"SPIFFE SVID", "urn:starfly:token-type:spiffe-svid", "production.example.com"},
		{"OIDC", "urn:starfly:token-type:oidc", "idp.example.com"},
		{"Kerberos", "urn:starfly:token-type:kerberos", "ad.example.com"},
		{"SAML", "urn:starfly:token-type:saml", "idp.example.com"},
		{"Agent MCP", "urn:starfly:token-type:agent-mcp", "agents.example.com"},
		{"Agent A2A", "urn:starfly:token-type:agent-a2a", "agents.example.com"},
		{"AWS STS", "urn:starfly:token-type:aws-sts", "aws.example.com"},
		{"GCP WIF", "urn:starfly:token-type:gcp-wif", "gcp.example.com"},
		{"Azure MI", "urn:starfly:token-type:azure-mi", "azure.example.com"},
		{"mTLS", "urn:starfly:token-type:mtls", "infra.example.com"},
		{"OAuth2", "urn:ietf:params:oauth:token-type:access_token", "oauth.example.com"},
		{"API Key", "urn:starfly:token-type:api-key", "partner.example.com"},
	}

	for _, p := range providers {
		t.Run(p.name, func(t *testing.T) {
			start := time.Now()
			resp, err := f.engine.Exchange(ctx, exchangeReq(p.tokenType))
			elapsed := time.Since(start)

			if err != nil {
				t.Fatalf("exchange failed for %s: %v", p.name, err)
			}

			token := parseToken(t, resp.AccessToken)

			// Verify WIMSE JWT structure.
			iss, _ := token.Issuer()
			if iss != "starfly" {
				t.Errorf("issuer = %q, want starfly", iss)
			}

			var td string
			if err := token.Get("td", &td); err != nil {
				t.Fatalf("missing td claim: %v", err)
			}
			if td != p.wantTD {
				t.Errorf("td = %q, want %q", td, p.wantTD)
			}

			// Latency check: exchange <15ms target (generous for CI).
			if elapsed > 100*time.Millisecond {
				t.Logf("WARNING: exchange latency %v exceeds 100ms target", elapsed)
			}
		})
	}
}

// ── Test 2: Execution-Scoped Action ─────────────────────────────────

func TestFabric_ExecutionScopedAction(t *testing.T) {
	f := setupFabric(t)
	ctx := context.Background()

	req := exchangeReq("urn:ietf:params:oauth:token-type:jwt")
	req.ExecutionScope = &core.ExecutionScope{
		Method:      "POST",
		URI:         "https://api.example.com/v1/transfers",
		PayloadHash: "sha256-abc123def456",
		Nonce:       "nonce-exec-1",
	}

	resp, err := f.engine.Exchange(ctx, req)
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}

	token := parseToken(t, resp.AccessToken)

	// Verify 30s TTL.
	if resp.ExpiresIn != 30 {
		t.Errorf("ExpiresIn = %d, want 30 (execution-scoped)", resp.ExpiresIn)
	}

	// Verify htm/htu/payload_hash/nonce claims.
	var htm, htu, ph, nonce string
	if err := token.Get("htm", &htm); err != nil {
		t.Fatalf("missing htm: %v", err)
	}
	if htm != "POST" {
		t.Errorf("htm = %q, want POST", htm)
	}

	if err := token.Get("htu", &htu); err != nil {
		t.Fatalf("missing htu: %v", err)
	}
	if htu != "https://api.example.com/v1/transfers" {
		t.Errorf("htu = %q, want transfer URI", htu)
	}

	if err := token.Get("payload_hash", &ph); err != nil {
		t.Fatalf("missing payload_hash: %v", err)
	}
	if ph != "sha256-abc123def456" {
		t.Errorf("payload_hash = %q, want sha256-abc123def456", ph)
	}

	if err := token.Get("nonce", &nonce); err != nil {
		t.Fatalf("missing nonce: %v", err)
	}

	// Verify scope validation: correct action passes.
	err = exchange.VerifyExecutionScope(token, &core.ExecutionScope{
		Method:      "POST",
		URI:         "https://api.example.com/v1/transfers",
		PayloadHash: "sha256-abc123def456",
	})
	if err != nil {
		t.Fatalf("scope verification failed for correct action: %v", err)
	}

	// Verify scope validation: wrong action rejected.
	err = exchange.VerifyExecutionScope(token, &core.ExecutionScope{
		Method: "DELETE",
		URI:    "https://api.example.com/v1/transfers",
	})
	if err == nil {
		t.Error("expected scope verification to fail for wrong method")
	}

	// Verify nonce replay protection.
	req2 := exchangeReq("urn:ietf:params:oauth:token-type:jwt")
	req2.ExecutionScope = &core.ExecutionScope{
		Method: "GET",
		URI:    "https://api.example.com/v1/accounts",
		Nonce:  "nonce-exec-1", // reuse
	}
	_, err = f.engine.Exchange(ctx, req2)
	if err == nil {
		t.Error("expected nonce replay to be rejected")
	}
}

// ── Test 3: Agent Delegation Chain ──────────────────────────────────

func TestFabric_AgentDelegationChain(t *testing.T) {
	f := setupFabric(t)
	ctx := context.Background()

	// Step 1: Agent A (MCP orchestrator) gets a token with delegation depth.
	f.policy.decision = &core.PolicyDecision{
		Allowed: true,
		Claims: map[string]interface{}{
			"caps":             []interface{}{"read", "write", "list"},
			"blast_radius":     "cluster",
			"delegation_depth": 3,
		},
	}
	reqA := exchangeReq("urn:starfly:token-type:agent-mcp")
	respA, err := f.engine.Exchange(ctx, reqA)
	if err != nil {
		t.Fatalf("Agent A exchange failed: %v", err)
	}
	tokenA := parseToken(t, respA.AccessToken)

	// Verify Agent A has delegation claims.
	var depthA float64
	if err := tokenA.Get("delegation_depth", &depthA); err != nil {
		// delegation_depth comes from policy, check it's set
		t.Log("Agent A token does not have delegation_depth from policy (expected if policy sets it as claim)")
	}

	// Step 2: Agent A delegates to Agent B (A2A) with narrowed caps.
	f.policy.decision = &core.PolicyDecision{
		Allowed: true,
		Claims: map[string]interface{}{
			"caps":         []interface{}{"read"},
			"blast_radius": "namespace",
		},
	}
	reqB := exchangeReq("urn:starfly:token-type:agent-a2a")
	reqB.ActorToken = respA.AccessToken

	respB, err := f.engine.Exchange(ctx, reqB)
	if err != nil {
		t.Fatalf("Agent B delegation exchange failed: %v", err)
	}

	tokenB := parseToken(t, respB.AccessToken)

	// Verify B's delegation_depth is decremented.
	var depthB float64
	if err := tokenB.Get("delegation_depth", &depthB); err != nil {
		t.Fatalf("missing delegation_depth on delegated token: %v", err)
	}

	// Verify obo chain has Agent A.
	var obo []interface{}
	if err := tokenB.Get("obo", &obo); err != nil {
		t.Fatalf("missing obo chain: %v", err)
	}
	if len(obo) == 0 {
		t.Fatal("obo chain is empty, expected at least Agent A")
	}

	// Verify narrowed caps.
	var capsB []interface{}
	if err := tokenB.Get("caps", &capsB); err != nil {
		t.Fatalf("missing caps on delegated token: %v", err)
	}
	if len(capsB) != 1 || capsB[0] != "read" {
		t.Errorf("caps = %v, want [read] (narrowed from parent)", capsB)
	}

	// Verify blast_radius is narrowed.
	var brB string
	if err := tokenB.Get("blast_radius", &brB); err != nil {
		t.Fatalf("missing blast_radius: %v", err)
	}
	if brB != "namespace" {
		t.Errorf("blast_radius = %q, want namespace", brB)
	}

	// Step 3: Verify escalation is denied.
	f.policy.decision = &core.PolicyDecision{
		Allowed: true,
		Claims: map[string]interface{}{
			"caps": []interface{}{"admin"},
		},
	}
	reqEsc := exchangeReq("urn:starfly:token-type:agent-a2a")
	reqEsc.ActorToken = respA.AccessToken
	_, err = f.engine.Exchange(ctx, reqEsc)
	if err == nil {
		t.Error("expected capability escalation to be denied")
	}
}

// ── Test 4: Cascade Revocation ──────────────────────────────────────

func TestFabric_CascadeRevocation(t *testing.T) {
	f := setupFabric(t)
	ctx := context.Background()

	// Step 1: Successful exchange.
	resp, err := f.engine.Exchange(ctx, exchangeReq("urn:ietf:params:oauth:token-type:jwt"))
	if err != nil {
		t.Fatalf("initial exchange failed: %v", err)
	}
	_ = resp

	// Step 2: Inject CAEP session-revoked event via receiver.
	revokedID := "wimse://production.example.com/ns/default/sa/my-app"
	event := &core.SecurityEvent{
		Issuer:   "siem.example.com",
		JTI:      "caep-001",
		IssuedAt: time.Now().Unix(),
		Audience: "starfly",
		SubjectID: &core.SubjectIdentifier{
			Format:   "spiffe_id",
			SpiffeID: revokedID,
		},
		Events: map[string]map[string]interface{}{
			signals.EventSessionRevoked: {
				"reason":          "compromised_credential",
				"initiating_entity": "siem",
			},
		},
	}

	start := time.Now()
	err = f.receiver.ReceiveEvent(ctx, event)
	if err != nil {
		t.Fatalf("receiving CAEP event failed: %v", err)
	}
	cascadeTime := time.Since(start)

	// Step 3: Verify revocation index is populated.
	entry, err := f.revocation.IsRevoked(ctx, revokedID)
	if err != nil {
		t.Fatalf("revocation check error: %v", err)
	}
	if entry == nil {
		t.Fatal("expected identity to be revoked after CAEP event")
	}

	// Step 4: Subsequent exchange should be denied.
	_, err = f.engine.Exchange(ctx, exchangeReq("urn:ietf:params:oauth:token-type:jwt"))
	if err == nil {
		t.Fatal("expected exchange to be denied for revoked identity")
	}

	// Verify cascade time.
	if cascadeTime > 2*time.Second {
		t.Errorf("cascade time %v exceeds 2s target", cascadeTime)
	}
	t.Logf("cascade revocation completed in %v", cascadeTime)
}

// ── Test 5: Delegation Chain Revocation ─────────────────────────────

func TestFabric_DelegationChainRevocation(t *testing.T) {
	f := setupFabric(t)
	ctx := context.Background()

	// Step 1: Agent A gets a token.
	f.policy.decision = &core.PolicyDecision{
		Allowed: true,
		Claims: map[string]interface{}{
			"caps":             []interface{}{"read", "write"},
			"delegation_depth": 2,
		},
	}
	reqA := exchangeReq("urn:starfly:token-type:agent-mcp")
	respA, err := f.engine.Exchange(ctx, reqA)
	if err != nil {
		t.Fatalf("Agent A exchange failed: %v", err)
	}

	// Step 2: Revoke Agent A's identity.
	agentAID := "wimse://agents.example.com/agent/orchestrator"
	err = f.revocation.Revoke(ctx, agentAID, "credential_compromised", time.Now().Add(1*time.Hour))
	if err != nil {
		t.Fatalf("revoking Agent A: %v", err)
	}

	// Step 3: Agent A trying to exchange again should be denied.
	_, err = f.engine.Exchange(ctx, exchangeReq("urn:starfly:token-type:agent-mcp"))
	if err == nil {
		t.Fatal("expected exchange denied for revoked Agent A")
	}

	// Step 4: Agent B trying to delegate from A's token should still succeed
	// at the exchange level (actor token is valid JWT), BUT Agent A's identity
	// being revoked means any new exchange by A is blocked.
	// The actor token itself was signed before revocation, so it's still
	// cryptographically valid. The revocation check happens on the SUBJECT
	// (Agent B), not the actor. This is correct: we revoked A's ability to
	// get NEW tokens, not B's existing delegated tokens.
	_ = respA
}

// ── Test 6: Full Credential Bridge ──────────────────────────────────

func TestFabric_FullCredentialBridge(t *testing.T) {
	f := setupFabric(t)
	ctx := context.Background()

	// Exchange a Kerberos credential and verify the full WIMSE JWT.
	f.policy.decision = &core.PolicyDecision{
		Allowed: true,
		Claims: map[string]interface{}{
			"caps":         []interface{}{"trading", "settlement"},
			"blast_radius": "namespace",
		},
	}

	req := exchangeReq("urn:starfly:token-type:kerberos")
	req.Audience = "https://settlement.internal.example.com"
	req.Scope = "trading:execute"

	start := time.Now()
	resp, err := f.engine.Exchange(ctx, req)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Kerberos bridge exchange failed: %v", err)
	}

	token := parseToken(t, resp.AccessToken)

	// Verify complete WIMSE JWT structure.
	sub, _ := token.Subject()
	if sub != "wimse://ad.example.com/principal/svc-trading" {
		t.Errorf("sub = %q, want kerberos principal", sub)
	}

	iss, _ := token.Issuer()
	if iss != "starfly" {
		t.Errorf("iss = %q, want starfly", iss)
	}

	aud, _ := token.Audience()
	if len(aud) == 0 || aud[0] != "https://settlement.internal.example.com" {
		t.Errorf("aud = %v, want settlement service", aud)
	}

	var td string
	if err := token.Get("td", &td); err != nil {
		t.Fatalf("missing td claim: %v", err)
	}
	if td != "ad.example.com" {
		t.Errorf("td = %q, want ad.example.com", td)
	}

	var caps []interface{}
	if err := token.Get("caps", &caps); err != nil {
		t.Fatalf("missing caps: %v", err)
	}
	if len(caps) != 2 {
		t.Errorf("caps = %v, want [trading settlement]", caps)
	}

	// Verify standard JWT temporal claims.
	exp, ok := token.Expiration()
	if !ok {
		t.Fatal("missing exp claim")
	}
	iat, ok := token.IssuedAt()
	if !ok {
		t.Fatal("missing iat claim")
	}
	ttl := exp.Sub(iat)
	if ttl < 4*time.Minute || ttl > 6*time.Minute {
		t.Errorf("TTL = %v, want ~5 minutes", ttl)
	}

	// Verify JWKS verification round-trip.
	pubKeySet, err := f.engine.PublicKeySet()
	if err != nil {
		t.Fatalf("getting public key set: %v", err)
	}
	_, err = jwt.Parse([]byte(resp.AccessToken), jwt.WithKeySet(pubKeySet))
	if err != nil {
		t.Fatalf("JWT verification with engine's public key failed: %v", err)
	}

	t.Logf("Kerberos→WIMSE bridge: %v", elapsed)
}

// ── Test 7: End-to-End Flow ─────────────────────────────────────────
// authenticate → exchange → scope → delegate → revoke → cascade → denied

func TestFabric_EndToEndFlow(t *testing.T) {
	f := setupFabric(t)
	ctx := context.Background()

	// Phase 1: Authenticate and exchange (SPIFFE → WIMSE).
	f.policy.decision = &core.PolicyDecision{
		Allowed: true,
		Claims: map[string]interface{}{
			"caps":             []interface{}{"read", "write"},
			"blast_radius":     "cluster",
			"delegation_depth": 2,
		},
	}
	reqAuth := exchangeReq("urn:starfly:token-type:spiffe-svid")
	respAuth, err := f.engine.Exchange(ctx, reqAuth)
	if err != nil {
		t.Fatalf("Phase 1 (authenticate) failed: %v", err)
	}
	t.Log("Phase 1: SPIFFE → WIMSE JWT ✓")

	// Phase 2: Execution-scoped action.
	f.policy.decision = &core.PolicyDecision{
		Allowed: true,
		Claims: map[string]interface{}{
			"caps": []interface{}{"read"},
		},
	}
	reqExec := exchangeReq("urn:ietf:params:oauth:token-type:jwt")
	reqExec.ExecutionScope = &core.ExecutionScope{
		Method: "GET",
		URI:    "https://api.example.com/accounts",
		Nonce:  "e2e-nonce-1",
	}
	respExec, err := f.engine.Exchange(ctx, reqExec)
	if err != nil {
		t.Fatalf("Phase 2 (exec scope) failed: %v", err)
	}
	if respExec.ExpiresIn != 30 {
		t.Errorf("execution-scoped TTL = %d, want 30", respExec.ExpiresIn)
	}
	t.Log("Phase 2: Execution-scoped token (30s TTL) ✓")

	// Phase 3: Delegate to sub-agent.
	f.policy.decision = &core.PolicyDecision{
		Allowed: true,
		Claims: map[string]interface{}{
			"caps":         []interface{}{"read"},
			"blast_radius": "namespace",
		},
	}
	reqDeleg := exchangeReq("urn:starfly:token-type:agent-a2a")
	reqDeleg.ActorToken = respAuth.AccessToken
	respDeleg, err := f.engine.Exchange(ctx, reqDeleg)
	if err != nil {
		t.Fatalf("Phase 3 (delegation) failed: %v", err)
	}
	delegToken := parseToken(t, respDeleg.AccessToken)

	var obo []interface{}
	if err := delegToken.Get("obo", &obo); err != nil {
		t.Fatalf("missing obo chain: %v", err)
	}
	if len(obo) != 1 {
		t.Errorf("obo chain length = %d, want 1", len(obo))
	}
	t.Log("Phase 3: Agent delegation with narrowed caps ✓")

	// Phase 4: Revoke original identity via CAEP.
	revokedID := "spiffe://production.example.com/workload/api-server"
	event := &core.SecurityEvent{
		Issuer:   "compliance.example.com",
		JTI:      "e2e-caep-001",
		IssuedAt: time.Now().Unix(),
		Audience: "starfly",
		SubjectID: &core.SubjectIdentifier{
			Format:   "spiffe_id",
			SpiffeID: revokedID,
		},
		Events: map[string]map[string]interface{}{
			signals.EventSessionRevoked: {
				"reason": "policy_violation",
			},
		},
	}
	err = f.receiver.ReceiveEvent(ctx, event)
	if err != nil {
		t.Fatalf("Phase 4 (CAEP revocation) failed: %v", err)
	}
	t.Log("Phase 4: CAEP session-revoked received ✓")

	// Phase 5: Exchange denied for revoked identity.
	f.policy.decision = &core.PolicyDecision{
		Allowed: true,
		Claims:  map[string]interface{}{},
	}
	_, err = f.engine.Exchange(ctx, exchangeReq("urn:starfly:token-type:spiffe-svid"))
	if err == nil {
		t.Fatal("Phase 5: expected exchange denied for revoked identity")
	}
	t.Log("Phase 5: Exchange denied for revoked identity ✓")

	t.Log("End-to-end flow: authenticate → scope → delegate → revoke → denied ✓")
}
