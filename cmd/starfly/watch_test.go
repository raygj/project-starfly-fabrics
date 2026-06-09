package main

import (
	"strings"
	"testing"

	"github.com/starfly-fabrics/starfly/pkg/api"
)

func TestFormatEvent_Exchange(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	e := api.FabricEvent{
		Timestamp: "2026-03-07T14:32:07.123Z",
		Type:      "exchange",
		Subject:   "k8s-sa",
		Target:    "wimse://payments.prod/sa/api-gw",
		Duration:  1.2,
		Result:    "ok",
		UnitID:    "unit-0",
	}

	out := FormatEvent(e)

	for _, want := range []string{
		"14:32:07.123",
		"exchange",
		"k8s-sa",
		"payments.prod/sa/api-gw",
		"1.2ms",
		"✓",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("FormatEvent missing %q:\n%s", want, out)
		}
	}
}

func TestFormatEvent_Denial(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	e := api.FabricEvent{
		Timestamp: "2026-03-07T14:32:08.234Z",
		Type:      "denial",
		Subject:   "wimse://payments.prod/agent/bot-x",
		Result:    "denied",
		UnitID:    "unit-0",
	}

	out := FormatEvent(e)
	if !strings.Contains(out, "✗") {
		t.Errorf("denied event missing ✗:\n%s", out)
	}
	if !strings.Contains(out, "denial") {
		t.Errorf("denied event missing type:\n%s", out)
	}
}

func TestFormatEvent_CAEP(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	e := api.FabricEvent{
		Timestamp: "2026-03-07T14:32:07.789Z",
		Type:      "caep",
		Subject:   "agent-credential-revoked",
		Target:    "5 units",
		Duration:  870,
		Result:    "ok",
		UnitID:    "unit-0",
	}

	out := FormatEvent(e)
	if !strings.Contains(out, "caep") {
		t.Errorf("caep event missing type:\n%s", out)
	}
	if !strings.Contains(out, "✓") {
		t.Errorf("caep event missing checkmark:\n%s", out)
	}
}

func TestFormatEvent_NoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	e := api.FabricEvent{
		Timestamp: "2026-03-07T12:00:00Z",
		Type:      "exchange",
		Subject:   "test",
		Result:    "ok",
	}

	out := FormatEvent(e)
	if strings.Contains(out, "\x1b[") {
		t.Errorf("NO_COLOR set but output contains ANSI escapes:\n%s", out)
	}
}

func TestFormatEvent_LongTarget_Truncated(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	e := api.FabricEvent{
		Timestamp: "2026-03-07T12:00:00Z",
		Type:      "exchange",
		Subject:   "very-long-source-identity-name",
		Target:    "wimse://very-long-target-domain.example.com/ns/namespace/sa/service-account-name",
		Result:    "ok",
	}

	out := FormatEvent(e)
	// Target column should be capped at 50 chars.
	if strings.Contains(out, "service-account-name") {
		t.Errorf("long target should be truncated:\n%s", out)
	}
	if !strings.Contains(out, "...") {
		t.Errorf("truncated target should end with ...:\n%s", out)
	}
}
