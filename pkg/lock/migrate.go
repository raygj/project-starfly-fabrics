package lock

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/dgraph-io/badger/v4"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// MigrateResult summarises a completed lock migration.
type MigrateResult struct {
	KeyCount int
	Duration time.Duration
}

// Migrate re-encrypts every value in db from src to dst atomically.
// If any step fails before the final flush, the original data is untouched.
func Migrate(ctx context.Context, db *badger.DB, src, dst core.Locker,
	auditor core.Auditor, unitID string, logger *slog.Logger) (*MigrateResult, error) {

	start := time.Now()

	// Audit: migration started.
	if auditor != nil {
		_ = auditor.Log(ctx, &core.AuditEvent{
			Type:   "admin",
			Action: "lock_migration_started",
			UnitID: unitID,
		})
	}

	// Count total keys (read-only scan) for progress reporting.
	totalKeys := 0
	if err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			totalKeys++
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("counting keys: %w", err)
	}

	logger.Info("lock migration starting", "total_keys", totalKeys)

	if totalKeys == 0 {
		dur := time.Since(start)
		if auditor != nil {
			_ = auditor.Log(ctx, &core.AuditEvent{
				Type:   "admin",
				Action: "lock_migration_complete",
				UnitID: unitID,
				Metadata: map[string]interface{}{
					"key_count": 0,
					"duration":  dur.String(),
				},
			})
		}
		return &MigrateResult{KeyCount: 0, Duration: dur}, nil
	}

	// Re-encrypt all KV pairs via WriteBatch for atomic commit.
	wb := db.NewWriteBatch()
	defer wb.Cancel()

	processed := 0
	progressInterval := 100
	if totalKeys > 1000 {
		if p := totalKeys / 10; p > progressInterval {
			progressInterval = p
		}
	}

	err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = 100
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := item.KeyCopy(nil)

			if err := item.Value(func(val []byte) error {
				// Decrypt with old locker.
				plain, err := src.Unlock(val)
				if err != nil {
					return fmt.Errorf("unlock key %q: %w", string(key), err)
				}
				// Re-encrypt with new locker.
				cipher, err := dst.Lock(plain)
				if err != nil {
					return fmt.Errorf("lock key %q: %w", string(key), err)
				}
				return wb.Set(key, cipher)
			}); err != nil {
				return err
			}

			processed++
			if processed%progressInterval == 0 {
				logger.Info("lock migration progress",
					"processed", processed,
					"total", totalKeys,
				)
			}
		}
		return nil
	})
	if err != nil {
		if auditor != nil {
			_ = auditor.Log(ctx, &core.AuditEvent{
				Type:   "admin",
				Action: "lock_migration_failed",
				UnitID: unitID,
				Reason: err.Error(),
			})
		}
		return nil, fmt.Errorf("migrating keys: %w", err)
	}

	// Atomic commit — all or nothing.
	if err := wb.Flush(); err != nil {
		if auditor != nil {
			_ = auditor.Log(ctx, &core.AuditEvent{
				Type:   "admin",
				Action: "lock_migration_failed",
				UnitID: unitID,
				Reason: err.Error(),
			})
		}
		return nil, fmt.Errorf("flushing write batch: %w", err)
	}

	dur := time.Since(start)
	logger.Info("lock migration complete", "key_count", processed, "duration", dur)

	if auditor != nil {
		_ = auditor.Log(ctx, &core.AuditEvent{
			Type:   "admin",
			Action: "lock_migration_complete",
			UnitID: unitID,
			Metadata: map[string]interface{}{
				"key_count": processed,
				"duration":  dur.String(),
			},
		})
	}

	return &MigrateResult{KeyCount: processed, Duration: dur}, nil
}

// NewFromTypeAndKey creates a Locker from a type string and key identifier.
// This avoids duplicating factory logic in the CLI layer.
func NewFromTypeAndKey(lockType, key string) (core.Locker, error) {
	switch lockType {
	case "dev":
		return &DevLocker{}, nil
	case "awskms":
		return NewKMSLocker(core.AWSKMSConfig{KeyID: key})
	default:
		return nil, fmt.Errorf("unsupported lock type for migration: %q", lockType)
	}
}
