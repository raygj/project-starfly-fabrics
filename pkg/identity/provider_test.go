package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/starfly-fabrics/starfly/pkg/core"
)

// testEnv holds the shared test infrastructure.
type testEnv struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	jwksServer *httptest.Server
	issuer     string
	td         core.TrustDomain
}

func newTestEnv(t testing.TB) *testEnv {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	pubJWK, err := jwk.Import(privKey.Public())
	if err != nil {
		t.Fatalf("importing public key: %v", err)
	}
	if err := pubJWK.Set(jwk.KeyIDKey, "test-key-1"); err != nil {
		t.Fatalf("setting kid: %v", err)
	}
	if err := pubJWK.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		t.Fatalf("setting alg: %v", err)
	}

	keySet := jwk.NewSet()
	if err := keySet.AddKey(pubJWK); err != nil {
		t.Fatalf("adding key to set: %v", err)
	}

	jwksBytes, err := json.Marshal(keySet)
	if err != nil {
		t.Fatalf("marshaling JWKS: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	}))
	t.Cleanup(srv.Close)

	issuer := "https://kubernetes.default.svc.cluster.local"
	td := core.TrustDomain{
		Name:    "production.example.com",
		Enabled: true,
		JWKSURL: srv.URL,
		Issuer:  issuer,
	}

	return &testEnv{
		privateKey: privKey,
		publicKey:  &privKey.PublicKey,
		jwksServer: srv,
		issuer:     issuer,
		td:         td,
	}
}

// mintToken creates a signed JWT with the given claims.
func (te *testEnv) mintToken(t testing.TB, opts ...func(jwt.Token)) []byte {
	t.Helper()

	token, err := jwt.NewBuilder().
		Issuer(te.issuer).
		Audience([]string{"starfly"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	if err != nil {
		t.Fatalf("building token: %v", err)
	}

	// K8s SA claims
	if err := token.Set("kubernetes.io", map[string]interface{}{
		"namespace": "default",
		"serviceaccount": map[string]interface{}{
			"name": "my-app",
			"uid":  "sa-uid-123",
		},
		"pod": map[string]interface{}{
			"name": "my-app-abc123",
			"uid":  "pod-uid-456",
		},
		"node": map[string]interface{}{
			"name": "node-1",
			"uid":  "node-uid-789",
		},
	}); err != nil {
		t.Fatalf("setting kubernetes.io claim: %v", err)
	}
	if err := token.Set("sub", "system:serviceaccount:default:my-app"); err != nil {
		t.Fatalf("setting sub claim: %v", err)
	}

	for _, opt := range opts {
		opt(token)
	}

	privJWK, err := jwk.Import(te.privateKey)
	if err != nil {
		t.Fatalf("importing private key: %v", err)
	}
	if err := privJWK.Set(jwk.KeyIDKey, "test-key-1"); err != nil {
		t.Fatalf("setting kid: %v", err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), privJWK))
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	return signed
}

// mintTokenWithKey signs with a specific key (for wrong-key tests).
func (te *testEnv) mintTokenWithKey(t testing.TB, key *rsa.PrivateKey) []byte {
	t.Helper()

	token, err := jwt.NewBuilder().
		Issuer(te.issuer).
		Audience([]string{"starfly"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	if err != nil {
		t.Fatalf("building token: %v", err)
	}

	if err := token.Set("kubernetes.io", map[string]interface{}{
		"namespace": "default",
		"serviceaccount": map[string]interface{}{
			"name": "my-app",
		},
	}); err != nil {
		t.Fatalf("setting kubernetes.io claim: %v", err)
	}
	if err := token.Set("sub", "system:serviceaccount:default:my-app"); err != nil {
		t.Fatalf("setting sub claim: %v", err)
	}

	privJWK, err := jwk.Import(key)
	if err != nil {
		t.Fatalf("importing private key: %v", err)
	}
	if err := privJWK.Set(jwk.KeyIDKey, "test-key-1"); err != nil {
		t.Fatalf("setting kid: %v", err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), privJWK))
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	return signed
}

func TestValidateWorkload(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()

	provider, err := New(ctx, []core.TrustDomain{te.td}, false)
	if err != nil {
		t.Fatalf("creating provider: %v", err)
	}

	tests := []struct {
		name      string
		token     string
		credType  string
		wantErr   string
		wantID    string
		wantTD    string
		wantNS    string
		wantSA    string
		wantPod   string
		wantNode  string
	}{
		{
			name:     "valid SA token",
			token:    string(te.mintToken(t)),
			credType: "k8s-sa",
			wantID:   "wimse://production.example.com/ns/default/sa/my-app",
			wantTD:   "production.example.com",
			wantNS:   "default",
			wantSA:   "my-app",
			wantPod:  "my-app-abc123",
			wantNode: "node-1",
		},
		{
			name: "expired token",
			token: string(te.mintToken(t, func(tok jwt.Token) {
				_ = tok.Set(jwt.ExpirationKey, time.Now().Add(-time.Hour))
			})),
			credType: "k8s-sa",
			wantErr:  "token validation failed",
		},
		{
			name: "wrong audience",
			token: string(te.mintToken(t, func(tok jwt.Token) {
				_ = tok.Set(jwt.AudienceKey, []string{"wrong-audience"})
			})),
			credType: "k8s-sa",
			// Audience is not enforced at the provider level (no configured
			// expected audience). Token is otherwise valid, so validation passes.
			wantID:   "wimse://production.example.com/ns/default/sa/my-app",
			wantTD:   "production.example.com",
			wantNS:   "default",
			wantSA:   "my-app",
			wantPod:  "my-app-abc123",
			wantNode: "node-1",
		},
		{
			name:     "malformed JWT",
			token:    "not-a-jwt-at-all",
			credType: "k8s-sa",
			wantErr:  "malformed JWT",
		},
		{
			name: "unknown issuer",
			token: string(te.mintToken(t, func(tok jwt.Token) {
				_ = tok.Set(jwt.IssuerKey, "https://unknown.cluster.local")
			})),
			credType: "k8s-sa",
			wantErr:  "unknown issuer",
		},
		{
			name:     "unsupported cred type",
			token:    string(te.mintToken(t)),
			credType: "aws-iam",
			wantErr:  "unsupported credential type",
		},
		{
			name: "wrong signing key",
			token: func() string {
				wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				return string(te.mintTokenWithKey(t, wrongKey))
			}(),
			credType: "k8s-sa",
			wantErr:  "token validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := provider.ValidateWorkload(ctx, tt.token, tt.credType)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if id.ID != tt.wantID {
				t.Errorf("ID = %q, want %q", id.ID, tt.wantID)
			}
			if id.TrustDomain != tt.wantTD {
				t.Errorf("TrustDomain = %q, want %q", id.TrustDomain, tt.wantTD)
			}
			if id.Attestation.Method != "k8s-sa" {
				t.Errorf("Attestation.Method = %q, want %q", id.Attestation.Method, "k8s-sa")
			}
			if id.Attestation.Namespace != tt.wantNS {
				t.Errorf("Attestation.Namespace = %q, want %q", id.Attestation.Namespace, tt.wantNS)
			}
			if ns, _ := id.Claims["namespace"].(string); ns != tt.wantNS {
				t.Errorf("Claims[namespace] = %q, want %q", ns, tt.wantNS)
			}
			if sa, _ := id.Claims["serviceaccount"].(string); sa != tt.wantSA {
				t.Errorf("Claims[serviceaccount] = %q, want %q", sa, tt.wantSA)
			}
			if tt.wantPod != "" {
				if pod, _ := id.Claims["pod"].(string); pod != tt.wantPod {
					t.Errorf("Claims[pod] = %q, want %q", pod, tt.wantPod)
				}
			}
			if tt.wantNode != "" {
				if node, _ := id.Claims["node"].(string); node != tt.wantNode {
					t.Errorf("Claims[node] = %q, want %q", node, tt.wantNode)
				}
			}
		})
	}
}


func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
