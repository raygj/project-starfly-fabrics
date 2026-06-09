package operator

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestRegisterMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	RegisterMetrics(reg)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather error: %v", err)
	}
	_ = families
}
