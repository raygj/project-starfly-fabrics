package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// DiscoverJWKS fetches the OIDC discovery document and returns the jwks_uri.
func DiscoverJWKS(ctx context.Context, issuer string) (string, error) {
	discoveryURL := issuer + "/.well-known/openid-configuration"

	client := core.NewDefaultHTTPClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", fmt.Errorf("oidc discovery: building request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("oidc discovery: fetching %s: %w", discoveryURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oidc discovery: %s returned %d", discoveryURL, resp.StatusCode)
	}

	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("oidc discovery: decoding response: %w", err)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("oidc discovery: jwks_uri not found in %s", discoveryURL)
	}

	return doc.JWKSURI, nil
}
