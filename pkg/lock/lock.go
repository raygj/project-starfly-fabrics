// Package lock provides envelope encryption for data at rest.
//
// The lock wraps the storage encryption key — all persisted state passes
// through Lock before write and Unlock after read. The New factory returns
// the appropriate Locker implementation based on config.
package lock

import (
	"fmt"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// New creates a Locker for the given configuration.
func New(cfg core.LockConfig) (core.Locker, error) {
	switch cfg.Type {
	case "dev":
		return &DevLocker{}, nil
	case "awskms":
		return NewKMSLocker(cfg.AWSKMS)
	case "gcpckms", "azurekeyvault":
		return nil, fmt.Errorf("lock type %q not yet implemented", cfg.Type)
	default:
		return nil, fmt.Errorf("unknown lock type %q", cfg.Type)
	}
}
