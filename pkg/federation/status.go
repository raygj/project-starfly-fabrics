package federation

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// FormatStatus returns a human-readable federation status string.
func FormatStatus(state *FederationState) string {
	if state == nil || len(state.Peers) == 0 {
		return "No federation peers configured.\n"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Federation Peers: %d total, %d healthy, %d stale, %d unreachable\n\n",
		state.PeerCount(), state.HealthyCount(), state.StaleCount(), state.UnreachableCount())

	for id, ps := range state.Peers {
		statusIcon := statusIcon(ps.Status)
		fmt.Fprintf(&b, "  %s %s\n", statusIcon, id)
		fmt.Fprintf(&b, "    Endpoint:   %s\n", ps.Config.JWKSEndpoint)
		fmt.Fprintf(&b, "    Status:     %s\n", ps.Status)
		fmt.Fprintf(&b, "    Keys:       %d\n", ps.KeyCount)

		if !ps.LastSeen.IsZero() {
			fmt.Fprintf(&b, "    Last Seen:  %s (%s ago)\n",
				ps.LastSeen.Format(time.RFC3339), formatDuration(ps.Age()))
		} else {
			fmt.Fprintf(&b, "    Last Seen:  never\n")
		}

		if ps.LastError != "" {
			fmt.Fprintf(&b, "    Last Error: %s\n", ps.LastError)
		}

		fmt.Fprintf(&b, "    Fetches:    %d successful, %d failed\n",
			ps.FetchCount, ps.ErrorCount)
		fmt.Fprintf(&b, "\n")
	}

	return b.String()
}

// FormatStatusJSON returns federation status as JSON.
func FormatStatusJSON(state *FederationState) ([]byte, error) {
	return json.MarshalIndent(state, "", "  ")
}

func statusIcon(status PeerStatus) string {
	switch status {
	case PeerHealthy:
		return "[OK]"
	case PeerStale:
		return "[!!]"
	case PeerUnreachable:
		return "[XX]"
	default:
		return "[??]"
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.0fm", d.Minutes())
	}
	return fmt.Sprintf("%.1fh", d.Hours())
}
