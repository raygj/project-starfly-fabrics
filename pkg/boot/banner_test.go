package boot

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestBanner_RendersAllFields(t *testing.T) {
	out := Banner(BannerConfig{
		Version:  "v0.3.0",
		FabricID: "prod-us-east-1",
		UnitID:   "starfly-0",
		Port:     "8693",
	})

	for _, want := range []string{"v0.3.0", "prod-us-east-1", "starfly-0", "8693"} {
		if !strings.Contains(out, want) {
			t.Errorf("Banner output missing %q:\n%s", want, out)
		}
	}

	if !strings.Contains(out, "identity fabric for non-human identities") {
		t.Errorf("Banner missing tagline:\n%s", out)
	}
	if !strings.Contains(out, "RFC 8693") {
		t.Errorf("Banner missing RFC reference:\n%s", out)
	}
	// Ruler uses U+2500 box-drawing character.
	if !strings.Contains(out, "\u2500\u2500\u2500") {
		t.Errorf("Banner missing box-drawing ruler:\n%s", out)
	}
}

func TestStep_FormatsCorrectly(t *testing.T) {
	// Force NO_COLOR so we get predictable output.
	t.Setenv("NO_COLOR", "1")

	out := Step("config loaded", 2*time.Millisecond)
	if !strings.Contains(out, "\u2713") {
		t.Errorf("Step missing checkmark: %q", out)
	}
	if !strings.Contains(out, "config loaded") {
		t.Errorf("Step missing name: %q", out)
	}
	if !strings.Contains(out, "2ms") {
		t.Errorf("Step missing duration: %q", out)
	}
}

func TestStep_AlignsDurations(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	s1 := Step("config loaded", 2*time.Millisecond)
	s2 := Step("nats connected", 23*time.Millisecond)
	s3 := Step("exchange engine ready", 150*time.Millisecond)

	// The duration column should start at the same position in each line.
	// Name is padded to 24 chars after "  X ", so duration starts at position 28.
	lines := []string{s1, s2, s3}
	positions := make([]int, len(lines))
	for i, line := range lines {
		// Find the position of the duration value (first digit after the padded name).
		trimmed := strings.TrimRight(line, "\n")
		// After "  X " (4 chars) and 24-char padded name, there's a space then duration.
		// Find index of "ms" to verify alignment.
		positions[i] = strings.Index(trimmed, "ms")
	}

	// All "ms" positions should be within a few chars of each other
	// (exact alignment depends on digit count).
	for i := 1; i < len(positions); i++ {
		diff := positions[i] - positions[0]
		if diff < -3 || diff > 3 {
			t.Errorf("Duration columns misaligned: line 0 at %d, line %d at %d\nLines:\n%s%s%s",
				positions[0], i, positions[i], s1, s2, s3)
		}
	}
}

func TestStepWarn_IncludesWarning(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	out := StepWarn("nats connected", 23*time.Millisecond, "dev mode")
	if !strings.Contains(out, "\u26a0") {
		t.Errorf("StepWarn missing warning indicator: %q", out)
	}
	if !strings.Contains(out, "nats connected") {
		t.Errorf("StepWarn missing name: %q", out)
	}
	if !strings.Contains(out, "23ms") {
		t.Errorf("StepWarn missing duration: %q", out)
	}
	if !strings.Contains(out, "(dev mode)") {
		t.Errorf("StepWarn missing warning message: %q", out)
	}
}

func TestReady_IncludesDuration(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	out := Ready(249 * time.Millisecond)
	if !strings.Contains(out, "249ms") {
		t.Errorf("Ready missing duration: %q", out)
	}
}

func TestReady_IncludesTagline(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	out := Ready(100 * time.Millisecond)
	if !strings.Contains(out, "each drawn to the other's light") {
		t.Errorf("Ready missing tagline: %q", out)
	}
	if !strings.Contains(out, "ready") {
		t.Errorf("Ready missing 'ready': %q", out)
	}
	// Should contain a box-drawing ruler.
	if !strings.Contains(out, "\u2500\u2500\u2500") {
		t.Errorf("Ready missing ruler: %q", out)
	}
}

func TestFailed_IncludesError(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	out := Failed("policy loaded", errors.New("file not found"))
	if !strings.Contains(out, "\u2717") {
		t.Errorf("Failed missing failure indicator: %q", out)
	}
	if !strings.Contains(out, "policy loaded") {
		t.Errorf("Failed missing component name: %q", out)
	}
	if !strings.Contains(out, "file not found") {
		t.Errorf("Failed missing error message: %q", out)
	}
}

func TestNoColor_DisablesANSI(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	out := Banner(BannerConfig{
		Version:  "v0.3.0",
		FabricID: "test-fabric",
		UnitID:   "unit-0",
		Port:     "8693",
	})
	if strings.Contains(out, "\x1b[") {
		t.Errorf("NO_COLOR set but output contains ANSI escape sequences:\n%s", out)
	}

	step := Step("test step", 5*time.Millisecond)
	if strings.Contains(step, "\x1b[") {
		t.Errorf("NO_COLOR set but Step output contains ANSI escapes: %q", step)
	}

	warn := StepWarn("test warn", 5*time.Millisecond, "warning")
	if strings.Contains(warn, "\x1b[") {
		t.Errorf("NO_COLOR set but StepWarn output contains ANSI escapes: %q", warn)
	}

	ready := Ready(100 * time.Millisecond)
	if strings.Contains(ready, "\x1b[") {
		t.Errorf("NO_COLOR set but Ready output contains ANSI escapes: %q", ready)
	}

	failed := Failed("test", errors.New("err"))
	if strings.Contains(failed, "\x1b[") {
		t.Errorf("NO_COLOR set but Failed output contains ANSI escapes: %q", failed)
	}
}

func TestZeroConfig_NoPanic(t *testing.T) {
	// An empty BannerConfig should not panic.
	out := Banner(BannerConfig{})
	if out == "" {
		t.Error("Banner returned empty string for zero config")
	}
	// Should contain fallback values.
	if !strings.Contains(out, "dev") {
		t.Errorf("zero-config Banner missing default version 'dev': %q", out)
	}
}
