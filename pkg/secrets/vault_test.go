package secrets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVaultSource_Name(t *testing.T) {
	vs, err := NewVaultSource(VaultConfig{Address: "http://localhost:8200"})
	if err != nil {
		t.Fatalf("NewVaultSource: %v", err)
	}
	if vs.Name() != "vault" {
		t.Errorf("Name() = %q, want vault", vs.Name())
	}
}

func TestVaultSource_Available_Healthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"initialized":  true,
				"sealed":       false,
				"standby":      false,
				"server_time_utc": 0,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	vs, err := NewVaultSource(VaultConfig{
		Address:    srv.URL,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewVaultSource: %v", err)
	}

	if !vs.Available(context.Background()) {
		t.Error("expected vault to be available")
	}
}

func TestVaultSource_Available_Sealed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"initialized": true,
				"sealed":      true,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	vs, err := NewVaultSource(VaultConfig{
		Address:    srv.URL,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewVaultSource: %v", err)
	}

	if vs.Available(context.Background()) {
		t.Error("expected sealed vault to be unavailable")
	}
}

func TestVaultSource_Available_Unreachable(t *testing.T) {
	vs, err := NewVaultSource(VaultConfig{
		Address: "http://127.0.0.1:1", // unreachable
	})
	if err != nil {
		t.Fatalf("NewVaultSource: %v", err)
	}

	if vs.Available(context.Background()) {
		t.Error("expected unreachable vault to be unavailable")
	}
}

func TestVaultSource_Fetch_KVv2(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/secret/data/app/db":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"password": "vault-secret",
						"host":     "db.vault.internal",
					},
					"metadata": map[string]interface{}{
						"version": 1,
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	vs, err := NewVaultSource(VaultConfig{
		Address:    srv.URL,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewVaultSource: %v", err)
	}
	// Pre-set token to skip auth.
	vs.client.SetToken("test-token")

	bundle, err := vs.Fetch(context.Background(), []SecretRef{
		{Source: "vault", Path: "app/db", Key: "password", Alias: "db_pass"},
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if bundle.Claims["db_pass"] != "vault-secret" {
		t.Errorf("db_pass = %q, want vault-secret", bundle.Claims["db_pass"])
	}
}

func TestVaultSource_Fetch_MissingKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/secret/data/app/db":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"password": "vault-secret",
					},
					"metadata": map[string]interface{}{
						"version": 1,
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	vs, err := NewVaultSource(VaultConfig{
		Address:    srv.URL,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewVaultSource: %v", err)
	}
	vs.client.SetToken("test-token")

	_, err = vs.Fetch(context.Background(), []SecretRef{
		{Source: "vault", Path: "app/db", Key: "nonexistent"},
	})
	if err == nil {
		t.Error("expected error for missing key")
	}
}

func TestVaultSource_NewWithNamespaceAndTTL(t *testing.T) {
	vs, err := NewVaultSource(VaultConfig{
		Address:   "http://localhost:8200",
		Namespace: "team-alpha",
		TTL:       10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewVaultSource: %v", err)
	}
	if vs.ttl != 10*time.Minute {
		t.Errorf("TTL = %v, want 10m", vs.ttl)
	}
}

func TestVaultSource_Fetch_NoData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/secret/data/empty":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"data":     nil,
					"metadata": map[string]interface{}{"version": 1},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	vs, err := NewVaultSource(VaultConfig{
		Address:    srv.URL,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewVaultSource: %v", err)
	}
	vs.client.SetToken("test-token")

	_, err = vs.Fetch(context.Background(), []SecretRef{
		{Source: "vault", Path: "empty", Key: "anything"},
	})
	if err == nil {
		t.Error("expected error for nil data")
	}
}

func TestVaultSource_Fetch_NonStringValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/secret/data/typed":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"count": 42,
					},
					"metadata": map[string]interface{}{"version": 1},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	vs, err := NewVaultSource(VaultConfig{
		Address:    srv.URL,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewVaultSource: %v", err)
	}
	vs.client.SetToken("test-token")

	_, err = vs.Fetch(context.Background(), []SecretRef{
		{Source: "vault", Path: "typed", Key: "count"},
	})
	if err == nil {
		t.Error("expected error for non-string value")
	}
}

func TestVaultSource_Fetch_AliasDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/secret/data/app/db":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"password": "vault-secret",
					},
					"metadata": map[string]interface{}{"version": 1},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	vs, err := NewVaultSource(VaultConfig{
		Address:    srv.URL,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewVaultSource: %v", err)
	}
	vs.client.SetToken("test-token")

	bundle, err := vs.Fetch(context.Background(), []SecretRef{
		{Source: "vault", Path: "app/db", Key: "password"},
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if bundle.Claims["password"] != "vault-secret" {
		t.Errorf("password = %q, want vault-secret", bundle.Claims["password"])
	}
}

func TestVaultSource_EnsureAuth_UnsupportedMethod(t *testing.T) {
	vs, err := NewVaultSource(VaultConfig{
		Address:    "http://localhost:8200",
		AuthMethod: VaultAuthMethod("unsupported"),
	})
	if err != nil {
		t.Fatalf("NewVaultSource: %v", err)
	}
	err = vs.ensureAuth(context.Background())
	if err == nil {
		t.Error("expected error for unsupported auth method")
	}
}

func TestVaultSource_EnsureAuth_AlreadyAuthed(t *testing.T) {
	vs, err := NewVaultSource(VaultConfig{Address: "http://localhost:8200"})
	if err != nil {
		t.Fatalf("NewVaultSource: %v", err)
	}
	vs.client.SetToken("existing-token")
	if err := vs.ensureAuth(context.Background()); err != nil {
		t.Errorf("ensureAuth with existing token: %v", err)
	}
}

func TestVaultSource_AuthJWT_NoTokenFunc(t *testing.T) {
	vs, err := NewVaultSource(VaultConfig{
		Address:    "http://localhost:8200",
		AuthMethod: VaultAuthJWT,
	})
	if err != nil {
		t.Fatalf("NewVaultSource: %v", err)
	}
	err = vs.authJWT(context.Background())
	if err == nil {
		t.Error("expected error when JWTTokenFunc is nil")
	}
}

func TestVaultSource_AuthTLS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/cert/login":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token": "tls-token-xyz",
					"policies":     []string{"default"},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	vs, err := NewVaultSource(VaultConfig{
		Address:    srv.URL,
		HTTPClient: srv.Client(),
		AuthMethod: VaultAuthTLS,
		Role:       "starfly",
	})
	if err != nil {
		t.Fatalf("NewVaultSource: %v", err)
	}

	err = vs.authTLS(context.Background())
	if err != nil {
		t.Fatalf("authTLS: %v", err)
	}
	if vs.client.Token() != "tls-token-xyz" {
		t.Errorf("token = %q, want tls-token-xyz", vs.client.Token())
	}
}

func TestVaultSource_AuthTLS_CustomMount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/custom-tls/login":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token": "custom-tls-token",
					"policies":     []string{"default"},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	vs, err := NewVaultSource(VaultConfig{
		Address:    srv.URL,
		HTTPClient: srv.Client(),
		AuthMethod: VaultAuthTLS,
		TLSMount:   "custom-tls",
		Role:       "starfly",
	})
	if err != nil {
		t.Fatalf("NewVaultSource: %v", err)
	}

	err = vs.authTLS(context.Background())
	if err != nil {
		t.Fatalf("authTLS: %v", err)
	}
	if vs.client.Token() != "custom-tls-token" {
		t.Errorf("token = %q, want custom-tls-token", vs.client.Token())
	}
}

func TestVaultSource_AuthTLS_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	vs, err := NewVaultSource(VaultConfig{
		Address:    srv.URL,
		HTTPClient: srv.Client(),
		AuthMethod: VaultAuthTLS,
		Role:       "starfly",
	})
	if err != nil {
		t.Fatalf("NewVaultSource: %v", err)
	}

	err = vs.authTLS(context.Background())
	if err == nil {
		t.Error("expected error for failed TLS auth")
	}
}

func TestVaultSource_AuthTLS_NoAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"auth": nil,
		})
	}))
	defer srv.Close()

	vs, err := NewVaultSource(VaultConfig{
		Address:    srv.URL,
		HTTPClient: srv.Client(),
		AuthMethod: VaultAuthTLS,
		Role:       "starfly",
	})
	if err != nil {
		t.Fatalf("NewVaultSource: %v", err)
	}

	err = vs.authTLS(context.Background())
	if err == nil {
		t.Error("expected error when TLS login returns no auth")
	}
}

func TestVaultSource_AuthJWT_CustomMount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/custom-jwt/login":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token": "custom-jwt-token",
					"policies":     []string{"default"},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	vs, err := NewVaultSource(VaultConfig{
		Address:      srv.URL,
		HTTPClient:   srv.Client(),
		AuthMethod:   VaultAuthJWT,
		JWTMount:     "custom-jwt",
		Role:         "starfly",
		JWTTokenFunc: func() string { return "my-jwt" },
	})
	if err != nil {
		t.Fatalf("NewVaultSource: %v", err)
	}

	err = vs.authJWT(context.Background())
	if err != nil {
		t.Fatalf("authJWT: %v", err)
	}
	if vs.client.Token() != "custom-jwt-token" {
		t.Errorf("token = %q, want custom-jwt-token", vs.client.Token())
	}
}

func TestVaultSource_AuthJWT_NoAuthReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"auth": nil,
		})
	}))
	defer srv.Close()

	vs, err := NewVaultSource(VaultConfig{
		Address:      srv.URL,
		HTTPClient:   srv.Client(),
		AuthMethod:   VaultAuthJWT,
		Role:         "starfly",
		JWTTokenFunc: func() string { return "jwt" },
	})
	if err != nil {
		t.Fatalf("NewVaultSource: %v", err)
	}

	err = vs.authJWT(context.Background())
	if err == nil {
		t.Error("expected error when JWT login returns no auth")
	}
}

func TestVaultSource_Fetch_ReadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	vs, err := NewVaultSource(VaultConfig{
		Address:    srv.URL,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewVaultSource: %v", err)
	}
	vs.client.SetToken("test-token")

	_, err = vs.Fetch(context.Background(), []SecretRef{
		{Source: "vault", Path: "missing", Key: "k"},
	})
	if err == nil {
		t.Error("expected error for server error")
	}
}

func TestVaultSource_AuthJWT(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/jwt/login":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token": "jwt-token-abc",
					"policies":     []string{"default"},
				},
			})
		case "/v1/secret/data/test":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"val": "fetched",
					},
					"metadata": map[string]interface{}{"version": 1},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	vs, err := NewVaultSource(VaultConfig{
		Address:      srv.URL,
		HTTPClient:   srv.Client(),
		AuthMethod:   VaultAuthJWT,
		Role:         "starfly",
		JWTTokenFunc: func() string { return "my-jwt" },
	})
	if err != nil {
		t.Fatalf("NewVaultSource: %v", err)
	}

	bundle, err := vs.Fetch(context.Background(), []SecretRef{
		{Source: "vault", Path: "test", Key: "val"},
	})
	if err != nil {
		t.Fatalf("Fetch with JWT auth: %v", err)
	}
	if bundle.Claims["val"] != "fetched" {
		t.Errorf("val = %q, want fetched", bundle.Claims["val"])
	}
}
