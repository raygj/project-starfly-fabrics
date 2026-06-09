package soul

import (
	"fmt"
	"strings"
)

// GenerateTopology produces a Markdown document describing the fabric topology
// from a SoulManifest. It includes trust domains, signing keys, SSF streams,
// and revocation statistics. A nil manifest returns a minimal "no data" doc.
func GenerateTopology(manifest *SoulManifest) string {
	if manifest == nil {
		return "# Fabric Topology\n\nNo manifest data available.\n"
	}

	var b strings.Builder

	b.WriteString("# Fabric Topology\n\n")

	// Metadata section.
	b.WriteString("## Metadata\n\n")
	b.WriteString("| Field | Value |\n")
	b.WriteString("| ----- | ----- |\n")
	fmt.Fprintf(&b, "| Fabric ID | `%s` |\n", manifest.Metadata.FabricID)
	fmt.Fprintf(&b, "| Sequence | %d |\n", manifest.Metadata.Sequence)
	fmt.Fprintf(&b, "| Generated At | %s |\n", manifest.Metadata.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"))
	b.WriteString("\n")

	// Trust domains table.
	b.WriteString("## Trust Domains\n\n")
	if len(manifest.TrustDomains) == 0 {
		b.WriteString("No trust domains configured.\n\n")
	} else {
		b.WriteString("| Name | Type | Issuer | Enabled |\n")
		b.WriteString("| ---- | ---- | ------ | ------- |\n")
		for _, td := range manifest.TrustDomains {
			fmt.Fprintf(&b, "| %s | %s | %s | %v |\n", td.Name, td.Type, td.Issuer, td.Enabled)
		}
		b.WriteString("\n")
	}

	// Signing keys table.
	b.WriteString("## Signing Keys\n\n")
	if len(manifest.Identity.SigningKeys) == 0 {
		b.WriteString("No signing keys configured.\n\n")
	} else {
		b.WriteString("| KID | Algorithm | Status |\n")
		b.WriteString("| --- | --------- | ------ |\n")
		for _, k := range manifest.Identity.SigningKeys {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", k.KID, k.Algorithm, k.Status)
		}
		b.WriteString("\n")
	}

	// SSF streams table.
	b.WriteString("## SSF Streams\n\n")
	if len(manifest.SSFStreams) == 0 {
		b.WriteString("No SSF streams configured.\n\n")
	} else {
		b.WriteString("| Stream ID | Transmitter | Events |\n")
		b.WriteString("| --------- | ----------- | ------ |\n")
		for _, s := range manifest.SSFStreams {
			events := strings.Join(s.EventsRequested, ", ")
			fmt.Fprintf(&b, "| %s | %s | %s |\n", s.StreamID, s.Transmitter, events)
		}
		b.WriteString("\n")
	}

	// Revocation stats.
	b.WriteString("## Revocations\n\n")
	b.WriteString("| Field | Value |\n")
	b.WriteString("| ----- | ----- |\n")
	fmt.Fprintf(&b, "| Count | %d |\n", manifest.Revocations.Count)
	hash := manifest.Revocations.Hash
	if hash == "" {
		hash = "(none)"
	}
	fmt.Fprintf(&b, "| Hash | `%s` |\n", hash)
	b.WriteString("\n")

	return b.String()
}

// GenerateRunbook produces a Markdown runbook for operational recovery and
// reference from a SoulManifest. A nil manifest returns a minimal stub.
func GenerateRunbook(manifest *SoulManifest) string {
	if manifest == nil {
		return "# Operational Runbook\n\nNo manifest data available.\n"
	}

	var b strings.Builder

	b.WriteString("# Operational Runbook\n\n")
	fmt.Fprintf(&b, "Fabric: `%s` | Sequence: %d\n\n", manifest.Metadata.FabricID, manifest.Metadata.Sequence)

	// Recovery section.
	b.WriteString("## Recovery\n\n")
	b.WriteString("To recover this fabric, restore from FSAnchor and reimport revocation index.\n\n")
	b.WriteString("Steps:\n\n")
	b.WriteString("1. Locate the FSAnchor archive for this fabric.\n")
	fmt.Fprintf(&b, "2. Restore the soul manifest at sequence %d.\n", manifest.Metadata.Sequence)
	fmt.Fprintf(&b, "3. Reimport the revocation index (%d entries, hash: `%s`).\n", manifest.Revocations.Count, manifest.Revocations.Hash)
	b.WriteString("4. Validate trust domain connectivity.\n")
	b.WriteString("5. Verify signing key availability in KMS.\n\n")

	// Trust domains section.
	b.WriteString("## Trust Domains\n\n")
	if len(manifest.TrustDomains) == 0 {
		b.WriteString("No trust domains configured.\n\n")
	} else {
		for _, td := range manifest.TrustDomains {
			status := "ENABLED"
			if !td.Enabled {
				status = "DISABLED"
			}
			fmt.Fprintf(&b, "- **%s** — type: `%s` [%s]\n", td.Name, td.Type, status)
		}
		b.WriteString("\n")
	}

	// Key rotation section.
	b.WriteString("## Key Rotation\n\n")
	if len(manifest.Identity.SigningKeys) == 0 {
		b.WriteString("No signing keys configured.\n\n")
	} else {
		var active, rotated []SigningKeyRef
		for _, k := range manifest.Identity.SigningKeys {
			switch k.Status {
			case "active":
				active = append(active, k)
			default:
				rotated = append(rotated, k)
			}
		}

		b.WriteString("### Active Keys\n\n")
		if len(active) == 0 {
			b.WriteString("No active keys.\n\n")
		} else {
			for _, k := range active {
				fmt.Fprintf(&b, "- `%s` — algorithm: %s\n", k.KID, k.Algorithm)
			}
			b.WriteString("\n")
		}

		b.WriteString("### Rotated / Revoked Keys\n\n")
		if len(rotated) == 0 {
			b.WriteString("No rotated or revoked keys.\n\n")
		} else {
			for _, k := range rotated {
				fmt.Fprintf(&b, "- `%s` — algorithm: %s, status: %s\n", k.KID, k.Algorithm, k.Status)
			}
			b.WriteString("\n")
		}
	}

	return b.String()
}

// GenerateChangelog produces a Markdown changelog from a SoulDiff.
// A nil diff returns a minimal "no changes" document.
func GenerateChangelog(diff *SoulDiff) string {
	if diff == nil {
		return "# Changelog\n\nNo diff data available.\n"
	}

	var b strings.Builder

	b.WriteString("# Changelog\n\n")
	fmt.Fprintf(&b, "Sequence %d -> %d\n\n", diff.FromSequence, diff.ToSequence)

	b.WriteString("```\n")
	b.WriteString(diff.Format())
	b.WriteString("```\n")

	return b.String()
}
