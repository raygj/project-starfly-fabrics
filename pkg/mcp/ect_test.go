package mcp

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

func TestGenerateECT_BasicClaims(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	req := &ECTRequest{
		Claims: &VerifiedClaims{
			Subject:  "wimse://dev.local/agent/data-bot",
			Issuer:   "starfly-unit-1",
			Audience: "https://mcp.example.com/tools/sql-query",
			ToolID:   "sql-query",
			Execution: &core.ExecutionScope{
				ExecAct:    "query",
				InputHash:  "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
				Target:     "postgresql://analytics.prod:5432/metrics",
				WorkflowID: "a0b1c2d3-e4f5-6789-abcd-ef0123456789",
			},
		},
		ToolID:       "sql-query",
		ResponseBody: []byte(`{"rows": 42}`),
		DurationMS:   45,
	}

	ect, err := GenerateECT(req, "wimse://prod/tools/sql-query", privKey, "test-kid")
	if err != nil {
		t.Fatalf("GenerateECT: %v", err)
	}

	// Verify the signed token is parseable.
	parsed, err := jwt.Parse([]byte(ect.SignedToken),
		jwt.WithKey(jwa.RS256(), &privKey.PublicKey),
		jwt.WithValidate(true),
	)
	if err != nil {
		t.Fatalf("parse ECT: %v", err)
	}

	// Check standard claims.
	iss, _ := parsed.Issuer()
	if iss != "wimse://prod/tools/sql-query" {
		t.Errorf("iss = %q", iss)
	}
	if ect.JTI == "" {
		t.Error("jti should be set")
	}

	// Check ECT-specific claims.
	var execAct string
	if err := parsed.Get("exec_act", &execAct); err != nil {
		t.Fatalf("get exec_act: %v", err)
	}
	if execAct != "query" {
		t.Errorf("exec_act = %q, want %q", execAct, "query")
	}

	var inpHash string
	if err := parsed.Get("inp_hash", &inpHash); err != nil {
		t.Fatalf("get inp_hash: %v", err)
	}
	if inpHash != "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg" {
		t.Errorf("inp_hash = %q", inpHash)
	}

	// out_hash should be set from response body.
	var outHash string
	if err := parsed.Get("out_hash", &outHash); err != nil {
		t.Fatalf("get out_hash: %v", err)
	}
	if outHash == "" {
		t.Error("out_hash should be set")
	}
	// Verify out_hash matches computed value.
	if outHash != computeInputHash([]byte(`{"rows": 42}`)) {
		t.Errorf("out_hash mismatch: got %q", outHash)
	}

	// Check workflow ID.
	var wid string
	if err := parsed.Get("wid", &wid); err != nil {
		t.Fatalf("get wid: %v", err)
	}
	if wid != "a0b1c2d3-e4f5-6789-abcd-ef0123456789" {
		t.Errorf("wid = %q", wid)
	}

	// Check par is empty array (no parents).
	var par []interface{}
	if err := parsed.Get("par", &par); err != nil {
		t.Fatalf("get par: %v", err)
	}
	if len(par) != 0 {
		t.Errorf("par = %v, want empty", par)
	}

	// Check extensions.
	var ext map[string]interface{}
	if err := parsed.Get("ext", &ext); err != nil {
		t.Fatalf("get ext: %v", err)
	}
	if ext["starfly.tool_id"] != "sql-query" {
		t.Errorf("ext[starfly.tool_id] = %v", ext["starfly.tool_id"])
	}
}

func TestGenerateECT_WithParents(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	req := &ECTRequest{
		Claims: &VerifiedClaims{
			Subject: "wimse://dev.local/agent/test",
			Execution: &core.ExecutionScope{
				ExecAct: "generate-report",
			},
		},
		ToolID:    "report-gen",
		ParentIDs: []string{"parent-jti-001", "parent-jti-002"},
	}

	ect, err := GenerateECT(req, "wimse://prod/tools/report-gen", privKey, "")
	if err != nil {
		t.Fatalf("GenerateECT: %v", err)
	}

	parsed, err := jwt.Parse([]byte(ect.SignedToken),
		jwt.WithKey(jwa.RS256(), &privKey.PublicKey),
		jwt.WithValidate(true),
	)
	if err != nil {
		t.Fatalf("parse ECT: %v", err)
	}

	var par []interface{}
	if err := parsed.Get("par", &par); err != nil {
		t.Fatalf("get par: %v", err)
	}
	if len(par) != 2 {
		t.Fatalf("par length = %d, want 2", len(par))
	}
	if par[0] != "parent-jti-001" || par[1] != "parent-jti-002" {
		t.Errorf("par = %v", par)
	}
}

func TestGenerateECT_NoResponseBody(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	req := &ECTRequest{
		Claims: &VerifiedClaims{
			Subject:   "wimse://dev.local/agent/test",
			Execution: &core.ExecutionScope{ExecAct: "notify"},
		},
		ToolID: "notifier",
	}

	ect, err := GenerateECT(req, "wimse://prod/tools/notifier", privKey, "kid-1")
	if err != nil {
		t.Fatalf("GenerateECT: %v", err)
	}

	if ect.OutputHash != "" {
		t.Errorf("out_hash should be empty for no response body, got %q", ect.OutputHash)
	}
}

func TestMiddleware_ECTGeneration(t *testing.T) {
	privKey, _ := testKeys(t)

	registry := NewRegistry()
	_ = registry.Register(&ToolEntry{
		ToolID:      "test-tool",
		ResourceURI: "https://mcp.example.com/tools/test",
	})

	cfg := Config{
		JWKSResolver:      &mockJWKSResolver{key: &privKey.PublicKey},
		Registry:          registry,
		RevocationChecker: &mockRevocationIndex{},
		Policy:            &mockPolicyEngine{decision: &core.PolicyDecision{Allowed: true}},
		SigningKey:         privKey,
		SigningKeyID:       "test-kid-1",
		Issuer:             "wimse://test.local",
	}

	// Token with execution claims so ECT generation triggers.
	body := []byte(`{"query":"SELECT 1"}`)
	token := signToken(t, privKey, map[string]interface{}{
		"sub":      "wimse://dev.local/agent/test",
		"iss":      "starfly-unit-1",
		"aud":      []string{"https://mcp.example.com/tools/test"},
		"exp":      time.Now().Add(5 * time.Minute),
		"iat":      time.Now(),
		"exec_act": "query",
		"inp_hash": computeInputHash(body),
	})

	// Handler that writes a response body.
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	})

	handler := Middleware(cfg)(inner)

	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/tools/test-tool/call", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// Check Execution-Context header is set.
	ectHeader := w.Header().Get("Execution-Context")
	if ectHeader == "" {
		t.Fatal("expected Execution-Context response header")
	}

	// Verify the ECT is a valid JWT.
	parsed, err := jwt.Parse([]byte(ectHeader),
		jwt.WithKey(jwa.RS256(), &privKey.PublicKey),
		jwt.WithValidate(true),
	)
	if err != nil {
		t.Fatalf("parse ECT from header: %v", err)
	}

	// Check it has out_hash (computed from response body).
	var outHash string
	if err := parsed.Get("out_hash", &outHash); err != nil {
		t.Fatalf("get out_hash: %v", err)
	}
	if outHash == "" {
		t.Error("ECT should have out_hash from response body")
	}
	if outHash != computeInputHash([]byte(`{"result":"ok"}`)) {
		t.Errorf("out_hash mismatch")
	}
}

func TestMiddleware_NoECTWithoutSigningKey(t *testing.T) {
	privKey, _ := testKeys(t)

	registry := NewRegistry()
	_ = registry.Register(&ToolEntry{
		ToolID:      "test-tool",
		ResourceURI: "https://mcp.example.com/tools/test",
	})

	// No SigningKey in config — ECT generation should be skipped.
	cfg := Config{
		JWKSResolver:      &mockJWKSResolver{key: &privKey.PublicKey},
		Registry:          registry,
		RevocationChecker: &mockRevocationIndex{},
		Policy:            &mockPolicyEngine{decision: &core.PolicyDecision{Allowed: true}},
	}

	token := signToken(t, privKey, map[string]interface{}{
		"sub":      "wimse://dev.local/agent/test",
		"iss":      "starfly-unit-1",
		"aud":      []string{"https://mcp.example.com/tools/test"},
		"exp":      time.Now().Add(5 * time.Minute),
		"iat":      time.Now(),
		"exec_act": "query",
	})

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := Middleware(cfg)(inner)

	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/tools/test-tool/call", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	// No Execution-Context header when signing key is absent.
	if h := w.Header().Get("Execution-Context"); h != "" {
		t.Error("expected no Execution-Context header without signing key")
	}
}

func TestResponseCapture(t *testing.T) {
	w := httptest.NewRecorder()
	rc := newResponseCapture(w)

	rc.WriteHeader(http.StatusCreated)
	_, _ = rc.Write([]byte("hello"))
	_, _ = rc.Write([]byte(" world"))

	if rc.statusCode != http.StatusCreated {
		t.Errorf("statusCode = %d, want 201", rc.statusCode)
	}
	if string(rc.body) != "hello world" {
		t.Errorf("body = %q, want %q", string(rc.body), "hello world")
	}
	if w.Body.String() != "hello world" {
		t.Errorf("underlying writer body = %q", w.Body.String())
	}
}
