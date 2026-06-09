// Package boot provides formatted boot sequence output for the Starfly
// identity fabric. It renders a human-readable startup banner with timed
// steps, replacing raw slog.Info calls in the startup path.
//
// ANSI color output is controlled by the NO_COLOR environment variable
// (https://no-color.org/) and by whether stdout is a terminal.
package boot

import (
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

// BannerConfig holds the values rendered in the startup header.
type BannerConfig struct {
	Version  string
	FabricID string
	UnitID   string
	Port     string
}

// color returns true when ANSI escape sequences should be emitted.
// It returns false when the NO_COLOR env var is set (any value) or
// when stdout is not a terminal (piped output).
func color() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// ansi wraps text in an ANSI escape code pair when color is enabled.
func ansi(code int, text string) string {
	if !color() {
		return text
	}
	return fmt.Sprintf("\x1b[%dm%s\x1b[0m", code, text)
}

// ruler returns a line of U+2500 box-drawing characters.
func ruler(n int) string {
	return strings.Repeat("\u2500", n)
}

// Banner renders the startup header block.
//
// Output format:
//
//	starfly v0.3.0 — identity fabric for non-human identities
//	────────────────────────────────────────────────────────────
//	  fabric:    prod-us-east-1
//	  unit:      starfly-0
//	  port:      8693 (RFC 8693 — token exchange)
func Banner(cfg BannerConfig) string {
	version := cfg.Version
	if version == "" {
		version = "dev"
	}
	fabricID := cfg.FabricID
	if fabricID == "" {
		fabricID = "(none)"
	}
	unitID := cfg.UnitID
	if unitID == "" {
		unitID = "(none)"
	}
	port := cfg.Port
	if port == "" {
		port = "(none)"
	}

	title := fmt.Sprintf("starfly %s \u2014 identity fabric for non-human identities", version)
	line := ruler(60)
	portLine := fmt.Sprintf("  port:      %s (RFC 8693 \u2014 token exchange)", port)

	var b strings.Builder
	b.WriteString(ansi(1, title))
	b.WriteByte('\n')
	b.WriteString(line)
	b.WriteByte('\n')
	fmt.Fprintf(&b, "  fabric:    %s\n", fabricID)
	fmt.Fprintf(&b, "  unit:      %s\n", unitID)
	b.WriteString(portLine)
	b.WriteByte('\n')
	return b.String()
}

// Step renders a timed step line with a green checkmark.
// The name is left-padded to 24 characters; the duration is right-aligned.
//
// Example:
//
//	  ✓ config loaded         2ms
func Step(name string, dur time.Duration) string {
	check := ansi(32, "\u2713")
	durStr := ansi(90, formatDuration(dur))
	return fmt.Sprintf("  %s %-24s %s\n", check, name, durStr)
}

// StepWarn renders a step with a yellow warning indicator and an
// optional parenthetical warning message.
//
// Example:
//
//	  ⚠ nats connected        23ms  (dev mode)
func StepWarn(name string, dur time.Duration, warning string) string {
	warn := ansi(33, "\u26a0")
	durStr := ansi(90, formatDuration(dur))
	warnMsg := ansi(33, fmt.Sprintf("(%s)", warning))
	return fmt.Sprintf("  %s %-24s %s  %s\n", warn, name, durStr, warnMsg)
}

// Ready renders the final ready line with a horizontal rule and tagline.
//
// Example:
//
//	  ────────────────────────────────────────────────────────
//	  ready in 249ms — each drawn to the other's light
func Ready(totalDuration time.Duration) string {
	line := "  " + ruler(56)
	msg := fmt.Sprintf("  %s in %s \u2014 each drawn to the other's light",
		ansi(1, "ready"), ansi(90, formatDuration(totalDuration)))
	return line + "\n" + msg + "\n"
}

// Failed renders a boot failure line with a red X indicator.
//
// Example:
//
//	  ✗ policy loaded         — error: file not found
func Failed(component string, err error) string {
	x := ansi(31, "\u2717")
	errMsg := ansi(31, fmt.Sprintf("\u2014 error: %s", err.Error()))
	return fmt.Sprintf("  %s %-24s %s\n", x, component, errMsg)
}

// formatDuration renders a duration as a human-friendly string.
// Durations under 1s are shown in milliseconds; 1s+ in seconds with one decimal.
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}
