package lock

import (
	"encoding/base64"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// Compile-time check that DevLocker implements core.Locker.
var _ core.Locker = (*DevLocker)(nil)

// DevLocker is a development-only locker that base64-encodes data.
// It provides NO real encryption and must never be used in production.
type DevLocker struct{}

// Lock base64-encodes the input data.
func (d *DevLocker) Lock(data []byte) ([]byte, error) {
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(dst, data)
	return dst, nil
}

// Unlock base64-decodes the input data.
func (d *DevLocker) Unlock(data []byte) ([]byte, error) {
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(dst, data)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}
