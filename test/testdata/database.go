package testdata

import (
	"clustron-backend/internal/user"
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"testing"
)

type DBTX interface {
	Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error)
	Query(context.Context, string, ...interface{}) (pgx.Rows, error)
	QueryRow(context.Context, string, ...interface{}) pgx.Row
}

type DBTestData struct {
	t    *testing.T
	pool DBTX

	UserQueries *user.Queries
}

func NewTestDataBuilder(t *testing.T, db DBTX) *DBTestData {
	return &DBTestData{t: t, pool: db}
}
