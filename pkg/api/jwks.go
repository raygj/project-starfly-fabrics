package api

import (
	"net/http"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// JWKSProvider returns the active signing key set. Implemented by exchange.Engine.
type JWKSProvider interface {
	PublicKeySet() (jwk.Set, error)
}

// handleJWKS returns the JWK Set containing all active signing public keys.
// Consuming services use this to verify WIMSE JWTs without out-of-band key distribution.
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if s.jwks == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "jwks provider not configured",
		})
		return
	}

	set, err := s.jwks.PublicKeySet()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to retrieve signing keys",
		})
		return
	}

	if s.devMode {
		w.Header().Set("Cache-Control", "no-store")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=3600")
	}

	writeJSON(w, http.StatusOK, set)
}
