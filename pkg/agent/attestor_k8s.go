package agent

import (
	"context"
	"fmt"
	"os"
	"strings"
)

const (
	defaultSATokenPath     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultSANamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// K8sAttestor reads the Kubernetes ServiceAccount token from the
// projected volume mount. Returns the token as a platform credential
// along with namespace and pod metadata from the downward API.
type K8sAttestor struct {
	tokenPath     string
	namespacePath string
}

// NewK8sAttestor creates a K8sAttestor. Pass empty strings to use
// the default K8s projected volume paths.
func NewK8sAttestor(tokenPath, namespacePath string) *K8sAttestor {
	if tokenPath == "" {
		tokenPath = defaultSATokenPath
	}
	if namespacePath == "" {
		namespacePath = defaultSANamespacePath
	}
	return &K8sAttestor{
		tokenPath:     tokenPath,
		namespacePath: namespacePath,
	}
}

func (k *K8sAttestor) Name() string { return "k8s-sa" }

func (k *K8sAttestor) Available(_ context.Context) bool {
	_, err := os.Stat(k.tokenPath)
	return err == nil
}

func (k *K8sAttestor) Attest(_ context.Context) (*AttestationResult, error) {
	token, err := os.ReadFile(k.tokenPath)
	if err != nil {
		return nil, fmt.Errorf("reading SA token from %s: %w", k.tokenPath, err)
	}

	metadata := map[string]string{}

	if ns, err := os.ReadFile(k.namespacePath); err == nil {
		metadata["namespace"] = strings.TrimSpace(string(ns))
	}

	if pod := os.Getenv("POD_NAME"); pod != "" {
		metadata["pod_name"] = pod
	}

	if node := os.Getenv("NODE_NAME"); node != "" {
		metadata["node_name"] = node
	}

	return &AttestationResult{
		Source:     "k8s-sa",
		Credential: token,
		CredType:   "urn:ietf:params:oauth:token-type:jwt",
		Metadata:   metadata,
	}, nil
}
