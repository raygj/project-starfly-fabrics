package api

import (
	"context"
	"log/slog"
	"net/http"
)

// mtlsMiddleware extracts the peer certificate identity from TLS-verified
// connections and adds it to the request context. This is a defense-in-depth
// check — the TLS layer already enforces client certificate verification.
func mtlsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := extractPeerIdentity(r)
		if identity == nil {
			// TLS layer should have rejected this, but defense-in-depth.
			slog.Warn("mtls: no peer certificate", "remote_addr", r.RemoteAddr)
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "client certificate required",
			})
			return
		}

		slog.Debug("mtls: peer authenticated",
			"subject", identity.Subject,
			"spiffe_uris", identity.SPIFFEURIs,
			"serial", identity.Serial,
			"remote_addr", r.RemoteAddr,
		)

		ctx := context.WithValue(r.Context(), peerIdentityKey, identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
