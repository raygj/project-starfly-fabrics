package cli

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestHumanDuration_JustNow(t *testing.T) {
	got := HumanDuration(500 * time.Millisecond)
	if got != "just now" {
		t.Errorf("HumanDuration(500ms) = %q, want %q", got, "just now")
	}
}

func TestHumanDuration_Seconds(t *testing.T) {
	got := HumanDuration(8 * time.Second)
	if got != "8s ago" {
		t.Errorf("HumanDuration(8s) = %q, want %q", got, "8s ago")
	}
}

func TestHumanDuration_Minutes(t *testing.T) {
	got := HumanDuration(3 * time.Minute)
	if got != "3m ago" {
		t.Errorf("HumanDuration(3m) = %q, want %q", got, "3m ago")
	}
}

func TestHumanDuration_Hours(t *testing.T) {
	got := HumanDuration(2 * time.Hour)
	if got != "2h ago" {
		t.Errorf("HumanDuration(2h) = %q, want %q", got, "2h ago")
	}
}

func TestHumanDuration_Days(t *testing.T) {
	got := HumanDuration(48 * time.Hour)
	if got != "2d ago" {
		t.Errorf("HumanDuration(48h) = %q, want %q", got, "2d ago")
	}
}

func TestHumanDuration_Negative(t *testing.T) {
	got := HumanDuration(-5 * time.Second)
	if got != "5s ago" {
		t.Errorf("HumanDuration(-5s) = %q, want %q", got, "5s ago")
	}
}

func TestColorGreen_WithColor(t *testing.T) {
	// Ensure NO_COLOR is not set for this test.
	_ = os.Unsetenv("NO_COLOR")

	// We can only test ANSI output if stdout is a terminal, which it won't
	// be in CI. Instead, test the noColor/color logic directly.
	// When noColor() returns false, ANSI codes should be present.
	if noColor() {
		t.Skip("stdout is not a terminal; skipping ANSI test")
	}

	got := ColorGreen("ok")
	if !strings.Contains(got, "\x1b[32m") {
		t.Errorf("ColorGreen should contain ANSI green code, got %q", got)
	}
	if !strings.Contains(got, "ok") {
		t.Errorf("ColorGreen should contain original text, got %q", got)
	}
	if !strings.HasSuffix(got, "\x1b[0m") {
		t.Errorf("ColorGreen should end with reset code, got %q", got)
	}
}

func TestNoColor_DisablesANSI(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	got := ColorGreen("ok")
	if got != "ok" {
		t.Errorf("ColorGreen with NO_COLOR set = %q, want %q", got, "ok")
	}

	got = ColorRed("fail")
	if got != "fail" {
		t.Errorf("ColorRed with NO_COLOR set = %q, want %q", got, "fail")
	}

	got = ColorYellow("warn")
	if got != "warn" {
		t.Errorf("ColorYellow with NO_COLOR set = %q, want %q", got, "warn")
	}

	got = ColorDim("dim")
	if got != "dim" {
		t.Errorf("ColorDim with NO_COLOR set = %q, want %q", got, "dim")
	}

	got = ColorBold("bold")
	if got != "bold" {
		t.Errorf("ColorBold with NO_COLOR set = %q, want %q", got, "bold")
	}
}

func TestNoColor_EnvVarDetection(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	if !noColor() {
		t.Error("noColor() should return true when NO_COLOR is set (even empty)")
	}
}
