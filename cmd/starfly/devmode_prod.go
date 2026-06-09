//go:build !dev

package main

import (
	"github.com/starfly-fabrics/starfly/pkg/core"
)

// DevModeAvailable indicates whether the binary was compiled with dev mode support.
const DevModeAvailable = false

// applyDevMode rejects dev mode in production binaries.
func applyDevMode(_ *core.Config) {
	panic("dev mode requested but binary was built without -tags dev")
}
