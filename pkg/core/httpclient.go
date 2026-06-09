package core

import (
	"net/http"
	"time"
)

// DefaultHTTPTimeout is the default timeout for outbound HTTP requests.
// Used by all Starfly packages that create HTTP clients. Operators can
// override per-package via each package's config struct or functional options.
const DefaultHTTPTimeout = 10 * time.Second

// NewDefaultHTTPClient returns an *http.Client with DefaultHTTPTimeout.
// Use this instead of &http.Client{Timeout: 10 * time.Second} to keep
// the default centralized and easy to find.
func NewDefaultHTTPClient() *http.Client {
	return &http.Client{Timeout: DefaultHTTPTimeout}
}
