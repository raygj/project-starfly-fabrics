package policy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/keys"
	"github.com/starfly-fabrics/starfly/pkg/core"
)

// VerifyBundle checks the cryptographic signature of an OPA bundle directory.
// When cfg.SigningKeyFile is empty, verification is skipped (returns nil).
// When set, the bundle directory must contain a valid .signatures.json whose
// JWT(s) verify against the configured public key, and every file hash must
// match. Returns an error describing the first verification failure.
func VerifyBundle(bundlePath string, cfg core.PolicyConfig) error {
	if cfg.SigningKeyFile == "" {
		return nil
	}

	keyPEM, err := os.ReadFile(cfg.SigningKeyFile)
	if err != nil {
		return fmt.Errorf("reading signing key %q: %w", cfg.SigningKeyFile, err)
	}

	keyID := cfg.SigningKeyID
	if keyID == "" {
		keyID = "starfly"
	}

	// Detect signing algorithm from PEM key type.
	alg, err := detectKeyAlgorithm(keyPEM)
	if err != nil {
		return fmt.Errorf("detecting key algorithm: %w", err)
	}

	kc, err := keys.NewKeyConfig(string(keyPEM), alg, "")
	if err != nil {
		return fmt.Errorf("parsing signing key: %w", err)
	}

	publicKeys := map[string]*keys.Config{
		keyID: kc,
	}

	// Load .signatures.json from bundle directory.
	sigPath := filepath.Join(bundlePath, ".signatures.json")
	sigData, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("reading bundle signatures %q: %w", sigPath, err)
	}

	var sc bundle.SignaturesConfig
	if err := json.Unmarshal(sigData, &sc); err != nil {
		return fmt.Errorf("parsing .signatures.json: %w", err)
	}

	// Verify JWT signatures and extract verified file list.
	vc := bundle.NewVerificationConfig(publicKeys, keyID, "", nil)
	verifiedFiles, err := bundle.VerifyBundleSignature(sc, vc)
	if err != nil {
		return fmt.Errorf("bundle signature verification failed: %w", err)
	}

	// Verify each file on disk against the signed hashes.
	err = filepath.Walk(bundlePath, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if fi.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(bundlePath, path)
		// Skip the signatures file itself.
		if relPath == ".signatures.json" {
			return nil
		}

		// Only verify policy-relevant files.
		if !strings.HasSuffix(fi.Name(), ".rego") && fi.Name() != "data.json" {
			return nil
		}

		// Use forward slashes for OPA bundle paths.
		bundleRelPath := filepath.ToSlash(relPath)

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("reading %q for verification: %w", relPath, readErr)
		}

		if err := bundle.VerifyBundleFile(bundleRelPath, *bytes.NewBuffer(data), verifiedFiles); err != nil {
			return fmt.Errorf("file %q failed integrity check: %w", relPath, err)
		}

		// Remove from map to track that we've seen it.
		delete(verifiedFiles, bundleRelPath)

		return nil
	})
	if err != nil {
		return err
	}

	// Check that all signed files were found on disk (detect deletions).
	for name := range verifiedFiles {
		if name == ".signatures.json" {
			continue
		}
		return fmt.Errorf("signed file %q missing from bundle directory", name)
	}

	return nil
}

// detectKeyAlgorithm determines the JWA signing algorithm from a PEM-encoded
// public key. Returns "ES256", "ES384", "RS256", etc.
func detectKeyAlgorithm(pemData []byte) (string, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return "", fmt.Errorf("no PEM block found in signing key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing public key: %w", err)
	}

	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return "ES256", nil
		case elliptic.P384():
			return "ES384", nil
		case elliptic.P521():
			return "ES512", nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve: %v", k.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		return "RS256", nil
	default:
		return "", fmt.Errorf("unsupported key type: %T", pub)
	}
}
