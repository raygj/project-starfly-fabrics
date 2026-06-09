// Package cli provides shared CLI formatting utilities for the Starfly
// command-line interface, including ANSI color helpers and human-friendly
// duration formatting.
package cli

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/term"
)

// noColor returns true when ANSI escape sequences should be suppressed.
// It checks the NO_COLOR env var (https://no-color.org/) and whether
// stdout is a terminal.
func noColor() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return true
	}
	return !term.IsTerminal(int(os.Stdout.Fd()))
}

// ansiWrap wraps text in an ANSI escape code pair when color is enabled.
func ansiWrap(code string, s string) string {
	if noColor() {
		return s
	}
	return fmt.Sprintf("\x1b[%sm%s\x1b[0m", code, s)
}

// ColorGreen returns the string wrapped in green ANSI color.
func ColorGreen(s string) string { return ansiWrap("32", s) }

// ColorYellow returns the string wrapped in yellow ANSI color.
func ColorYellow(s string) string { return ansiWrap("33", s) }

// ColorRed returns the string wrapped in red ANSI color.
func ColorRed(s string) string { return ansiWrap("31", s) }

// ColorDim returns the string wrapped in dim (gray) ANSI color.
func ColorDim(s string) string { return ansiWrap("90", s) }

// ColorBold returns the string wrapped in bold ANSI weight.
func ColorBold(s string) string { return ansiWrap("1", s) }

// HumanDuration converts a duration into a concise human-readable string
// relative to "now". Examples: "just now", "8s ago", "3m ago", "2h ago", "1d ago".
func HumanDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Second:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		days := int(d.Hours()) / 24
		return fmt.Sprintf("%dd ago", days)
	}
}
