package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// requireBearerAuth validates Authorization: Bearer against the server's JWKS.
// Returns true if auth succeeds or JWKS is not configured (test/dev shortcut).
// Returns false after writing a 401 when auth is required but fails.
func (s *Server) requireBearerAuth(w http.ResponseWriter, r *http.Request) bool {
	if s.jwks == nil {
		return true
	}
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, errorResponse{
			Error:            "unauthorized",
			ErrorDescription: "Authorization Bearer token required",
		})
		return false
	}
	keySet, err := s.jwks.PublicKeySet()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{
			Error:            "server_error",
			ErrorDescription: "internal error",
		})
		return false
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if _, err := jwt.Parse([]byte(tokenStr), jwt.WithKeySet(keySet)); err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{
			Error:            "unauthorized",
			ErrorDescription: "invalid token",
		})
		return false
	}
	return true
}

// encryptionKeyRequest is the JSON body for the encryption key registration endpoint.
type encryptionKeyRequest struct {
	PublicKey json.RawMessage `json:"public_key"`
}

// handleEncryptionKeyRegister handles POST /v1/identity/agent/encryption-key.
// The agent authenticates with a WIMSE JWT Bearer token and registers its
// public encryption key for JWE secret delivery.
func (s *Server) handleEncryptionKeyRegister(w http.ResponseWriter, r *http.Request) {
	if s.encryptionKeyStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "encryption key store not configured",
		})
		return
	}

	// Extract Bearer token.
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "missing or invalid Authorization header",
		})
		return
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Verify JWT against engine's JWKS.
	if s.jwks == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "JWKS provider not configured",
		})
		return
	}
	keySet, err := s.jwks.PublicKeySet()
	if err != nil {
		slog.Error("failed to get public key set", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "internal error",
		})
		return
	}

	token, err := jwt.Parse([]byte(tokenString), jwt.WithKeySet(keySet))
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "invalid token",
		})
		return
	}

	subject, ok := token.Subject()
	if !ok || subject == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "token has no subject",
		})
		return
	}

	// Parse request body.
	var req encryptionKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
		return
	}

	// Parse and validate JWK from raw JSON.
	key, err := jwk.ParseKey(req.PublicKey)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid JWK",
		})
		return
	}
	if err := validateEncryptionJWK(key); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid JWK: " + err.Error(),
		})
		return
	}

	// Register the key.
	if err := s.encryptionKeyStore.Register(r.Context(), subject, key); err != nil {
		slog.Error("encryption key registration failed", "error", err, "subject", subject)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "registration failed",
		})
		return
	}

	slog.Info("encryption key registered", "subject", subject)
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

// validateEncryptionJWK rejects keys that cannot be used for JWE encryption.
// Only EC (P-256/P-384/P-521) and OKP (X25519/Ed25519) public keys are accepted.
// RSA and symmetric keys are rejected.
//
// jwx v3 stores the crv field as jwa.EllipticCurveAlgorithm (a struct),
// not a string, so we read via Get and compare using .String().
func validateEncryptionJWK(key jwk.Key) error {
	switch key.KeyType() {
	case jwa.EC():
		var crv jwa.EllipticCurveAlgorithm
		if err := key.Get("crv", &crv); err != nil || crv.String() == "" {
			return fmt.Errorf("EC key missing crv")
		}
		switch crv.String() {
		case "P-256", "P-384", "P-521":
		default:
			return fmt.Errorf("unsupported EC curve %q", crv.String())
		}
		return nil
	case jwa.OKP():
		var crv jwa.EllipticCurveAlgorithm
		if err := key.Get("crv", &crv); err != nil || crv.String() == "" {
			return fmt.Errorf("OKP key missing crv")
		}
		switch crv.String() {
		case "X25519", "Ed25519":
		default:
			return fmt.Errorf("unsupported OKP curve %q", crv.String())
		}
		return nil
	default:
		return fmt.Errorf("unsupported key type %q: only EC and OKP public keys are accepted", key.KeyType())
	}
}
