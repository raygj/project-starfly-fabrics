//go:build dev

package main

import (
	"log/slog"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// DevModeAvailable indicates whether the binary was compiled with dev mode support.
const DevModeAvailable = true

// applyDevMode configures the config for development mode.
// Only available in binaries built with -tags dev.
func applyDevMode(cfg *core.Config) {
	cfg.DevMode = true
	cfg.Lock.Type = "dev"
	cfg.TLS.Enabled = false
	slog.Warn("running in DEVELOPMENT mode — do not use in production")
}
