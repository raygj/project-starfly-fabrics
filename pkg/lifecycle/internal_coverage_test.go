package lifecycle

import "testing"

func TestSlogAdapter_Methods(t *testing.T) {
	adapter := newSlogAdapter()

	adapter.Debug("test debug", "key", "value")
	adapter.Info("test info", "key", "value")
	adapter.Warn("test warn", "key", "value")
	adapter.Error("test error", "key", "value")
}
