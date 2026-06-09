package agent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultGCPMetadataEndpoint = "http://metadata.google.internal"
	gcpFlavorHeader            = "Metadata-Flavor"
	gcpFlavorValue             = "Google"
	gcpProjectIDPath           = "/computeMetadata/v1/project/project-id"
	gcpZonePath                = "/computeMetadata/v1/instance/zone"
	gcpInstanceNamePath        = "/computeMetadata/v1/instance/name"
	gcpServiceAccountPath      = "/computeMetadata/v1/instance/service-accounts/default/email"
	gcpIdentityTokenPath       = "/computeMetadata/v1/instance/service-accounts/default/identity"
)

// GCPAttestor discovers GCP workload identity via the metadata server.
// It fetches an identity token and populates metadata with project_id,
// zone, instance_name, and service_account.
type GCPAttestor struct {
	endpoint   string
	audience   string // Required for identity token request.
	httpClient *http.Client
}

// NewGCPAttestor creates a GCPAttestor. Pass an empty endpoint to use
// the default GCP metadata server. Audience is required for the identity
// token request.
func NewGCPAttestor(endpoint, audience string) *GCPAttestor {
	if endpoint == "" {
		endpoint = defaultGCPMetadataEndpoint
	}
	return &GCPAttestor{
		endpoint: endpoint,
		audience: audience,
		httpClient: &http.Client{
			Timeout: 2 * time.Second,
		},
	}
}

func (g *GCPAttestor) Name() string { return "gcp-metadata" }

// Available checks if the GCP metadata server is reachable.
func (g *GCPAttestor) Available(ctx context.Context) bool {
	_, err := g.getMetadata(ctx, gcpProjectIDPath)
	return err == nil
}

// Attest fetches an identity token and instance metadata from the GCP metadata server.
func (g *GCPAttestor) Attest(ctx context.Context) (*AttestationResult, error) {
	// Fetch identity token.
	tokenURL := gcpIdentityTokenPath + "?audience=" + g.audience + "&format=full"
	token, err := g.getMetadata(ctx, tokenURL)
	if err != nil {
		return nil, fmt.Errorf("fetching gcp identity token: %w", err)
	}

	metadata := map[string]string{}

	if projectID, err := g.getMetadata(ctx, gcpProjectIDPath); err == nil {
		metadata["project_id"] = projectID
	}
	if zone, err := g.getMetadata(ctx, gcpZonePath); err == nil {
		// Zone returns "projects/123/zones/us-central1-a" — extract the zone name.
		parts := strings.Split(zone, "/")
		metadata["zone"] = parts[len(parts)-1]
	}
	if name, err := g.getMetadata(ctx, gcpInstanceNamePath); err == nil {
		metadata["instance_name"] = name
	}
	if sa, err := g.getMetadata(ctx, gcpServiceAccountPath); err == nil {
		metadata["service_account"] = sa
	}

	return &AttestationResult{
		Source:     "gcp-metadata",
		Credential: []byte(token),
		CredType:   "urn:starfly:token-type:gcp-wif",
		Metadata:   metadata,
	}, nil
}

// getMetadata fetches a value from the GCP metadata server.
func (g *GCPAttestor) getMetadata(ctx context.Context, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.endpoint+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(gcpFlavorHeader, gcpFlavorValue)

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata server returned %d: %s", resp.StatusCode, string(body))
	}
	return strings.TrimSpace(string(body)), nil
}
