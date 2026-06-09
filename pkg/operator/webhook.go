package operator

import (
	"fmt"
	"net/url"

	v1alpha1 "github.com/starfly-fabrics/starfly/pkg/operator/api/v1alpha1"
)

// ValidateFabric validates a StarlightFabric CR spec.
// Returns a list of validation errors. An empty list means the spec is valid.
func ValidateFabric(fabric *v1alpha1.StarlightFabric) []string {
	var errs []string

	if fabric.Name == "" {
		errs = append(errs, "metadata.name is required")
	}

	errs = append(errs, validateTrustDomains(fabric.Spec.TrustDomains)...)
	errs = append(errs, validateSigningKeys(fabric.Spec.SigningKeys)...)
	errs = append(errs, validateSSFStreams(fabric.Spec.SSFStreams)...)
	errs = append(errs, validateAnchor(fabric.Spec.Anchor)...)

	return errs
}

func validateTrustDomains(domains []v1alpha1.TrustDomainSpec) []string {
	var errs []string
	seen := make(map[string]bool)

	for i, td := range domains {
		if td.Name == "" {
			errs = append(errs, fmt.Sprintf("spec.trustDomains[%d].name is required", i))
			continue
		}
		if seen[td.Name] {
			errs = append(errs, fmt.Sprintf("spec.trustDomains[%d].name %q is duplicate", i, td.Name))
		}
		seen[td.Name] = true

		switch td.Type {
		case "oidc", "spiffe", "aws-sts", "kerberos", "saml":
			// valid
		case "":
			errs = append(errs, fmt.Sprintf("spec.trustDomains[%d].type is required", i))
		default:
			errs = append(errs, fmt.Sprintf("spec.trustDomains[%d].type %q is not supported", i, td.Type))
		}
	}
	return errs
}

func validateSigningKeys(keys []v1alpha1.SigningKeySpec) []string {
	var errs []string
	seen := make(map[string]bool)

	for i, sk := range keys {
		if sk.KID == "" {
			errs = append(errs, fmt.Sprintf("spec.signingKeys[%d].kid is required", i))
			continue
		}
		if seen[sk.KID] {
			errs = append(errs, fmt.Sprintf("spec.signingKeys[%d].kid %q is duplicate", i, sk.KID))
		}
		seen[sk.KID] = true

		switch sk.Algorithm {
		case "ES256", "RS256", "EdDSA":
			// valid
		case "":
			errs = append(errs, fmt.Sprintf("spec.signingKeys[%d].algorithm is required", i))
		default:
			errs = append(errs, fmt.Sprintf("spec.signingKeys[%d].algorithm %q is not supported", i, sk.Algorithm))
		}

		if sk.KMSKeyID == "" {
			errs = append(errs, fmt.Sprintf("spec.signingKeys[%d].kmsKeyId is required", i))
		}
	}
	return errs
}

func validateSSFStreams(streams []v1alpha1.SSFStreamSpec) []string {
	var errs []string
	seen := make(map[string]bool)

	for i, ss := range streams {
		if ss.StreamID == "" {
			errs = append(errs, fmt.Sprintf("spec.ssfStreams[%d].streamId is required", i))
			continue
		}
		if seen[ss.StreamID] {
			errs = append(errs, fmt.Sprintf("spec.ssfStreams[%d].streamId %q is duplicate", i, ss.StreamID))
		}
		seen[ss.StreamID] = true

		if ss.Transmitter == "" {
			errs = append(errs, fmt.Sprintf("spec.ssfStreams[%d].transmitter is required", i))
		} else if u, err := url.Parse(ss.Transmitter); err != nil || u.Scheme == "" {
			errs = append(errs, fmt.Sprintf("spec.ssfStreams[%d].transmitter %q is not a valid URL", i, ss.Transmitter))
		}
	}
	return errs
}

func validateAnchor(anchor *v1alpha1.AnchorSpec) []string {
	if anchor == nil {
		return nil
	}

	var errs []string
	switch anchor.Type {
	case "s3", "gcs":
		if anchor.Bucket == "" {
			errs = append(errs, "spec.anchor.bucket is required for s3/gcs anchor")
		}
	case "filesystem":
		if anchor.Path == "" {
			errs = append(errs, "spec.anchor.path is required for filesystem anchor")
		}
	case "":
		errs = append(errs, "spec.anchor.type is required")
	default:
		errs = append(errs, fmt.Sprintf("spec.anchor.type %q is not supported", anchor.Type))
	}
	return errs
}
