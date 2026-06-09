package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	defaultAzureIMDSEndpoint = "http://169.254.169.254"
	azureMetadataHeader      = "Metadata"
	azureAPIVersion          = "2021-02-01"
	azureInstancePath        = "/metadata/instance"
	azureTokenPath           = "/metadata/identity/oauth2/token"
)

// AzureAttestor discovers Azure workload identity via IMDS.
// It fetches a managed identity token and populates metadata with
// subscription_id, resource_group, vm_name, and location.
type AzureAttestor struct {
	endpoint   string
	resource   string // Token audience/resource (e.g., "https://management.azure.com/")
	httpClient *http.Client
}

// NewAzureAttestor creates an AzureAttestor. Pass an empty endpoint to use
// the default Azure IMDS address. Resource is the token audience.
func NewAzureAttestor(endpoint, resource string) *AzureAttestor {
	if endpoint == "" {
		endpoint = defaultAzureIMDSEndpoint
	}
	if resource == "" {
		resource = "https://management.azure.com/"
	}
	return &AzureAttestor{
		endpoint: endpoint,
		resource: resource,
		httpClient: &http.Client{
			Timeout: 2 * time.Second,
		},
	}
}

func (a *AzureAttestor) Name() string { return "azure-imds" }

// Available checks if Azure IMDS is reachable.
func (a *AzureAttestor) Available(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		a.endpoint+azureInstancePath+"?api-version="+azureAPIVersion, nil)
	if err != nil {
		return false
	}
	req.Header.Set(azureMetadataHeader, "true")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Attest fetches a managed identity token and instance metadata from Azure IMDS.
func (a *AzureAttestor) Attest(ctx context.Context) (*AttestationResult, error) {
	// Fetch managed identity token.
	tokenURL := a.endpoint + azureTokenPath +
		"?api-version=" + azureAPIVersion +
		"&resource=" + a.resource
	token, err := a.getAzureToken(ctx, tokenURL)
	if err != nil {
		return nil, fmt.Errorf("fetching azure token: %w", err)
	}

	// Fetch instance metadata.
	metadata, err := a.getInstanceMetadata(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching azure instance metadata: %w", err)
	}

	return &AttestationResult{
		Source:     "azure-imds",
		Credential: []byte(token),
		CredType:   "urn:starfly:token-type:azure-mi",
		Metadata:   metadata,
	}, nil
}

func (a *AzureAttestor) getAzureToken(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(azureMetadataHeader, "true")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("parsing token response: %w", err)
	}
	return tokenResp.AccessToken, nil
}

func (a *AzureAttestor) getInstanceMetadata(ctx context.Context) (map[string]string, error) {
	url := a.endpoint + azureInstancePath + "?api-version=" + azureAPIVersion
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(azureMetadataHeader, "true")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("instance metadata returned %d", resp.StatusCode)
	}

	var instance struct {
		Compute struct {
			SubscriptionID string `json:"subscriptionId"`
			ResourceGroup  string `json:"resourceGroupName"`
			Name           string `json:"name"`
			Location       string `json:"location"`
		} `json:"compute"`
	}
	if err := json.Unmarshal(body, &instance); err != nil {
		return nil, fmt.Errorf("parsing instance metadata: %w", err)
	}

	return map[string]string{
		"subscription_id": instance.Compute.SubscriptionID,
		"resource_group":  instance.Compute.ResourceGroup,
		"vm_name":         instance.Compute.Name,
		"location":        instance.Compute.Location,
	}, nil
}
