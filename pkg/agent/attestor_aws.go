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
	defaultAWSIMDSEndpoint = "http://169.254.169.254"
	awsTokenPath           = "/latest/api/token"
	awsIdentityDocPath     = "/latest/dynamic/instance-identity/document"
	awsTokenTTLHeader      = "X-aws-ec2-metadata-token-ttl-seconds"
	awsTokenHeader         = "X-aws-ec2-metadata-token"
)

// AWSAttestor discovers AWS instance identity via IMDSv2.
// It fetches the instance identity document and populates metadata
// with account_id, instance_id, region, and instance_type.
type AWSAttestor struct {
	endpoint   string
	httpClient *http.Client
}

// NewAWSAttestor creates an AWSAttestor. Pass an empty endpoint to use
// the default AWS IMDS address (169.254.169.254).
func NewAWSAttestor(endpoint string) *AWSAttestor {
	if endpoint == "" {
		endpoint = defaultAWSIMDSEndpoint
	}
	return &AWSAttestor{
		endpoint: endpoint,
		httpClient: &http.Client{
			Timeout: 2 * time.Second,
		},
	}
}

func (a *AWSAttestor) Name() string { return "aws-imds" }

// Available checks if AWS IMDS v2 is reachable by requesting a session token.
func (a *AWSAttestor) Available(ctx context.Context) bool {
	_, err := a.getToken(ctx)
	return err == nil
}

// Attest fetches the instance identity document from IMDS v2.
func (a *AWSAttestor) Attest(ctx context.Context) (*AttestationResult, error) {
	token, err := a.getToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws imds token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+awsIdentityDocPath, nil)
	if err != nil {
		return nil, fmt.Errorf("creating identity doc request: %w", err)
	}
	req.Header.Set(awsTokenHeader, token)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching identity document: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("reading identity document: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("imds returned %d: %s", resp.StatusCode, string(body))
	}

	var doc struct {
		AccountID    string `json:"accountId"`
		InstanceID   string `json:"instanceId"`
		Region       string `json:"region"`
		InstanceType string `json:"instanceType"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parsing identity document: %w", err)
	}

	return &AttestationResult{
		Source:     "aws-imds",
		Credential: body,
		CredType:   "urn:starfly:token-type:aws-sts",
		Metadata: map[string]string{
			"account_id":    doc.AccountID,
			"instance_id":   doc.InstanceID,
			"region":        doc.Region,
			"instance_type": doc.InstanceType,
		},
	}, nil
}

// getToken performs the IMDSv2 PUT request to obtain a session token.
func (a *AWSAttestor) getToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, a.endpoint+awsTokenPath, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(awsTokenTTLHeader, "21600")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	token, err := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("imds token request returned %d", resp.StatusCode)
	}
	return string(token), nil
}
