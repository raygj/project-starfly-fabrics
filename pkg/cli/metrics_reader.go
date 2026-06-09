package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// FabricStatus holds the parsed status of a Starfly fabric, derived from
// the Prometheus /metrics endpoint.
type FabricStatus struct {
	FabricID         string        `json:"fabric_id"`
	UnitsTotal       int           `json:"units_total"`
	UnitsHealthy     int           `json:"units_healthy"`
	ExchangeRate     float64       `json:"exchange_rate_per_min"`
	ExchangeP99      float64       `json:"exchange_p99_ms"`
	RevocationsActive int          `json:"revocations_active"`
	SoulSequence     uint64        `json:"soul_sequence"`
	SoulAge          time.Duration `json:"soul_age_seconds"`
	TrustDomains     int           `json:"trust_domains"`
}

// ReadMetrics fetches the Prometheus text exposition format from the given
// endpoint and parses it into a FabricStatus. It uses simple line parsing
// rather than requiring the prometheus/common/expfmt library.
func ReadMetrics(endpoint string) (*FabricStatus, error) {
	client := core.NewDefaultHTTPClient()
	resp, err := client.Get(endpoint) //nolint:gosec // user-supplied endpoint is intentional
	if err != nil {
		return nil, fmt.Errorf("fetching metrics: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metrics endpoint returned %d", resp.StatusCode)
	}

	return ParseMetrics(resp.Body)
}

// ParseMetrics parses a Prometheus text exposition format reader into a
// FabricStatus struct. Exported for testing.
func ParseMetrics(r io.Reader) (*FabricStatus, error) {
	s := &FabricStatus{}
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and empty lines.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Extract fabric ID from unit_info label.
		if strings.HasPrefix(line, "starfly_unit_info{") {
			s.FabricID = extractLabel(line, "trust_domain")
			continue
		}

		name, value := splitMetricLine(line)
		if name == "" {
			continue
		}

		switch name {
		case "starfly_fabric_units_total":
			s.UnitsTotal = int(parseFloat(value))
		case "starfly_fabric_units_healthy":
			s.UnitsHealthy = int(parseFloat(value))
		case "starfly_exchange_requests_total":
			// Accumulate total — rate is computed externally or approximated.
			s.ExchangeRate += parseFloat(value)
		case "starfly_exchange_duration_seconds":
			// Look for the 0.99 quantile bucket.
			if strings.Contains(line, "quantile=\"0.99\"") || strings.Contains(line, `le="0.99"`) {
				s.ExchangeP99 = parseFloat(value) * 1000 // seconds to ms
			}
		case "starfly_revocation_index_size":
			s.RevocationsActive = int(parseFloat(value))
		case "starfly_soul_manifest_sequence":
			s.SoulSequence = uint64(parseFloat(value))
		case "starfly_soul_anchor_age_seconds":
			s.SoulAge = time.Duration(parseFloat(value) * float64(time.Second))
		case "starfly_fabric_trust_domains_total":
			s.TrustDomains = int(parseFloat(value))
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading metrics: %w", err)
	}

	return s, nil
}

// FormatStatus produces a human-readable, terminal-formatted status string.
func FormatStatus(s *FabricStatus) string {
	var b strings.Builder

	// Fabric line.
	fabricID := s.FabricID
	if fabricID == "" {
		fabricID = "(unknown)"
	}
	healthStr := healthSummary(s.UnitsTotal, s.UnitsHealthy)
	fmt.Fprintf(&b, "Fabric: %s (%d units, %s)\n", ColorBold(fabricID), s.UnitsTotal, healthStr)

	// Exchange line.
	fmt.Fprintf(&b, "Exchanges: %s/min", formatNumber(s.ExchangeRate))
	if s.ExchangeP99 > 0 {
		fmt.Fprintf(&b, " (p99: %.1fms)", s.ExchangeP99)
	}
	b.WriteByte('\n')

	// Revocations line.
	revColor := ColorGreen
	if s.RevocationsActive > 0 {
		revColor = ColorYellow
	}
	fmt.Fprintf(&b, "Revocations: %s active\n", revColor(fmt.Sprintf("%d", s.RevocationsActive)))

	// Soul line.
	ageStr := HumanDuration(s.SoulAge)
	fmt.Fprintf(&b, "Soul: seq %d, %s\n", s.SoulSequence, ColorDim(ageStr))

	// Trust domains line.
	fmt.Fprintf(&b, "Trust domains: %d\n", s.TrustDomains)

	return b.String()
}

// FormatStatusJSON returns the FabricStatus as indented JSON.
func FormatStatusJSON(s *FabricStatus) ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// healthSummary returns "all healthy" or "N/M healthy" with color.
func healthSummary(total, healthy int) string {
	if total == 0 {
		return ColorDim("no units")
	}
	if healthy == total {
		return ColorGreen("all healthy")
	}
	return ColorYellow(fmt.Sprintf("%d/%d healthy", healthy, total))
}

// formatNumber formats a float as a comma-separated integer string.
func formatNumber(f float64) string {
	n := int64(f)
	if n < 1000 {
		return strconv.FormatInt(n, 10)
	}
	// Simple comma formatting for thousands.
	s := strconv.FormatInt(n, 10)
	var result strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result.WriteByte(',')
		}
		result.WriteRune(c)
	}
	return result.String()
}

// splitMetricLine splits a Prometheus metric line into name and value.
// For lines with labels like `foo{bar="baz"} 42`, it returns ("foo", "42").
func splitMetricLine(line string) (string, string) {
	// Find value — always the last space-separated token.
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", ""
	}
	value := parts[len(parts)-1]

	// Name is before any '{' or space.
	name := parts[0]
	if idx := strings.IndexByte(name, '{'); idx >= 0 {
		name = name[:idx]
	}
	return name, value
}

// extractLabel extracts a label value from a Prometheus metric line.
// e.g., extractLabel(`foo{bar="baz",x="y"} 1`, "bar") returns "baz".
func extractLabel(line, label string) string {
	key := label + `="`
	idx := strings.Index(line, key)
	if idx < 0 {
		return ""
	}
	start := idx + len(key)
	end := strings.IndexByte(line[start:], '"')
	if end < 0 {
		return ""
	}
	return line[start : start+end]
}

// parseFloat parses a string to float64, returning 0 on error.
// Returns 0 on parse error — metric will show as zero rather than failing the CLI.
// This is intentional: malformed metric values surface as zeros in the status
// display, which is preferable to crashing the CLI on a single bad line.
func parseFloat(s string) float64 {
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

// ─────────────────────────────────────────────────────────────────────
// Federation Signal Status (Phase 13 — P13-008)
// ─────────────────────────────────────────────────────────────────────

// PeerSignalMetrics holds parsed signal gateway metrics for a single peer.
type PeerSignalMetrics struct {
	FabricID      string  `json:"fabric_id"`
	Transport     string  `json:"transport"`
	RelayedTotal  float64 `json:"relayed_total"`
	ReceivedTotal float64 `json:"received_total"`
	ErrorTotal    float64 `json:"error_total"`
	LagSeconds    float64 `json:"lag_seconds"`
	Reachable     float64 `json:"reachable"` // derived: 1=has traffic, 0=no traffic
}

// Status returns the health status string based on lag and reachability.
func (p *PeerSignalMetrics) Status() string {
	if p.Reachable == 0 || p.LagSeconds > 60 {
		return "down"
	}
	if p.Reachable < 1 || p.LagSeconds > 10 {
		return "degraded"
	}
	return "healthy"
}

// FederationSignalStatus holds parsed signal gateway state from Prometheus metrics.
type FederationSignalStatus struct {
	Peers []*PeerSignalMetrics `json:"peers"`
}

// ReadSignalMetrics fetches the Prometheus endpoint and parses federation
// signal gateway metrics.
func ReadSignalMetrics(endpoint string) (*FederationSignalStatus, error) {
	c := core.NewDefaultHTTPClient()
	resp2, err := c.Get(endpoint) //nolint:gosec // user-supplied endpoint is intentional
	if err != nil {
		return nil, fmt.Errorf("fetching metrics: %w", err)
	}
	defer func() { _ = resp2.Body.Close() }()

	if resp2.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metrics endpoint returned %d", resp2.StatusCode)
	}

	return ParseSignalMetrics(resp2.Body)
}

// ParseSignalMetrics parses Prometheus text exposition format and extracts
// federation signal gateway metrics. Exported for testing.
//
// Real metric names and labels (from pkg/metrics/metrics.go):
//
//	starfly_federation_relay_total{peer="...", result="ok|error"}
//	starfly_federation_received_total{peer="...", result="ok|error"}
//	starfly_federation_revocation_lag_seconds{peer="..."}
//	starfly_federation_sync_total{peer="...", result="ok|error"}
//	starfly_federation_sync_mismatches_total{peer="..."}
func ParseSignalMetrics(r io.Reader) (*FederationSignalStatus, error) {
	// Accumulate per-peer metrics keyed by peer label value.
	peers := make(map[string]*PeerSignalMetrics)

	getPeer := func(peerID string) *PeerSignalMetrics {
		p, ok := peers[peerID]
		if !ok {
			p = &PeerSignalMetrics{FabricID: peerID}
			peers[peerID] = p
		}
		return p
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		name, value := splitMetricLine(line)
		if name == "" {
			continue
		}

		peerID := extractLabel(line, "peer")

		switch name {
		case "starfly_federation_relay_total":
			if peerID == "" {
				continue
			}
			p := getPeer(peerID)
			result := extractLabel(line, "result")
			v := parseFloat(value)
			if result == "error" {
				p.ErrorTotal += v
			} else {
				p.RelayedTotal += v
			}

		case "starfly_federation_received_total":
			if peerID == "" {
				continue
			}
			p := getPeer(peerID)
			result := extractLabel(line, "result")
			if result != "error" {
				p.ReceivedTotal += parseFloat(value)
			}

		case "starfly_federation_revocation_lag_seconds":
			if peerID == "" {
				continue
			}
			p := getPeer(peerID)
			p.LagSeconds = parseFloat(value)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading metrics: %w", err)
	}

	// Convert map to sorted slice.
	result := &FederationSignalStatus{}
	for _, p := range peers {
		// Transport is always mTLS/HTTPS for federation peers.
		p.Transport = "https"
		// Derive reachability: a peer with any relayed or received traffic
		// and lag under the threshold is considered reachable.
		if p.RelayedTotal > 0 || p.ReceivedTotal > 0 {
			p.Reachable = 1
		}
		result.Peers = append(result.Peers, p)
	}

	// Sort by fabric ID for deterministic output.
	sortPeers(result.Peers)

	return result, nil
}

// sortPeers sorts peer metrics by FabricID for stable output.
func sortPeers(peers []*PeerSignalMetrics) {
	for i := 1; i < len(peers); i++ {
		for j := i; j > 0 && peers[j].FabricID < peers[j-1].FabricID; j-- {
			peers[j], peers[j-1] = peers[j-1], peers[j]
		}
	}
}

// FormatSignalStatus produces a human-readable, terminal-formatted signal
// gateway status string with ANSI colors.
func FormatSignalStatus(s *FederationSignalStatus) string {
	if s == nil || len(s.Peers) == 0 {
		return "No federation signal peers detected.\n"
	}

	var b strings.Builder
	b.WriteString(ColorBold("Federation Signal Gateway"))
	b.WriteByte('\n')

	// Compute header underline width.
	b.WriteString(strings.Repeat("\u2500", 78))
	b.WriteByte('\n')

	// Summary line.
	var healthy, degraded, down int
	for _, p := range s.Peers {
		switch p.Status() {
		case "healthy":
			healthy++
		case "degraded":
			degraded++
		default:
			down++
		}
	}
	summaryParts := []string{
		fmt.Sprintf("%d peers", len(s.Peers)),
	}
	if healthy > 0 {
		summaryParts = append(summaryParts, ColorGreen(fmt.Sprintf("%d healthy", healthy)))
	}
	if degraded > 0 {
		summaryParts = append(summaryParts, ColorYellow(fmt.Sprintf("%d degraded", degraded)))
	}
	if down > 0 {
		summaryParts = append(summaryParts, ColorRed(fmt.Sprintf("%d down", down)))
	}
	fmt.Fprintf(&b, "%s\n\n", strings.Join(summaryParts, ", "))

	for _, p := range s.Peers {
		status := p.Status()
		var statusColor func(string) string
		var statusIcon string

		switch status {
		case "healthy":
			statusColor = ColorGreen
			statusIcon = "OK"
		case "degraded":
			statusColor = ColorYellow
			statusIcon = "!!"
		default:
			statusColor = ColorRed
			statusIcon = "XX"
		}

		// Peer line: name, transport, status, counts, lag.
		fmt.Fprintf(&b, "  %s  %-7s  %s  relayed: %-6s  received: %-6s  lag: %s\n",
			ColorBold(fmt.Sprintf("%-20s", p.FabricID)),
			p.Transport,
			statusColor(fmt.Sprintf("[%s] %-8s", statusIcon, status)),
			formatNumber(p.RelayedTotal),
			formatNumber(p.ReceivedTotal),
			formatLag(p.LagSeconds, statusColor),
		)

		// Show error count if nonzero.
		if p.ErrorTotal > 0 {
			fmt.Fprintf(&b, "    %s\n", ColorRed(fmt.Sprintf("errors: %s", formatNumber(p.ErrorTotal))))
		}
	}

	return b.String()
}

// FormatSignalStatusJSON returns federation signal status as indented JSON.
func FormatSignalStatusJSON(s *FederationSignalStatus) ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// formatLag formats a lag value in seconds as a human-readable string.
func formatLag(lagSeconds float64, colorFn func(string) string) string {
	if lagSeconds <= 0 {
		return ColorDim("n/a")
	}
	s := fmt.Sprintf("%.1fs", lagSeconds)
	return colorFn(s)
}
