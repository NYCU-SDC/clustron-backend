package setup

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ory/dockertest/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type ResourceManager struct {
	mu     sync.Mutex
	logger *zap.Logger

	pool     dockertest.ClosablePool
	postgres *pgxpool.Pool

	cleanups []func()
}

// SetupPostgres ensures that a PostgreSQL container is running and returns a new transaction.
//
// The transaction is rolled back when the returned cleanup function is called,
// which should typically be deferred by the caller to ensure test data is cleaned up.
//
// Usage:
//
//	tx, rollback, err := rm.SetupPostgres()
//	defer rollback()
func (r *ResourceManager) SetupPostgres(t *testing.T) pgx.Tx {
	t.Helper()

	r.mu.Lock()
	if r.postgres == nil {

		pool, _, cleanup, err := setupPostgresWithMigrations(r.pool, r.logger)
		require.NoError(t, err, "Failed to set up PostgreSQL")

		r.postgres = pool
		r.cleanups = append(r.cleanups, cleanup)
	}
	r.mu.Unlock()

	tx, err := r.postgres.Begin(context.Background())
	require.NoError(t, err, "Failed to begin transaction")

	t.Cleanup(func() {
		err := tx.Rollback(context.Background())
		if err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			r.logger.Error("Failed to rollback transaction", zap.Error(err))
		}
	})

	return tx
}

// WithPostgresTx provides a convenient way to run a test within a PostgreSQL transaction.
//
// It automatically begins a new transaction from the shared pgx pool, passes it to the
// provided test function, and rolls it back after the function completes.
//
// This ensures isolation between tests and prevents any side effects from persisting.
//
// Usage:
//
//	func TestCreateUser(t *testing.T) {
//	    rm.WithPostgresTx(t, func(tx pgx.Tx) {
//	        _, err := tx.Exec(context.Background(), `INSERT INTO users (email) VALUES ($1)`, "test@example.com")
//	        require.NoError(t, err)
//	        ...
//	    })
//	}
//
// The transaction will always be rolled back, even if the test fails or panics.
func (r *ResourceManager) WithPostgresTx(t *testing.T, fn func(tx pgx.Tx)) {
	tx := r.SetupPostgres(t)

	fn(tx)
}

func (r *ResourceManager) Cleanup(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.postgres != nil {
		r.postgres.Close()
		r.postgres = nil
	}

	for i := len(r.cleanups) - 1; i >= 0; i-- {
		r.cleanups[i]()
	}
	r.cleanups = nil

	if r.pool != nil {
		if err := r.pool.Close(ctx); err != nil {
			r.logger.Error("Failed to close pool", zap.Error(err))
		}
	}
}

func NewResourceManager(logger *zap.Logger) (*ResourceManager, error) {
	ctx := context.Background()
	pool, err := dockertest.NewPool(ctx, "")
	if err != nil {
		return nil, err
	}

	return &ResourceManager{
		pool:     pool,
		logger:   logger,
		cleanups: make([]func(), 0),
	}, nil
}
