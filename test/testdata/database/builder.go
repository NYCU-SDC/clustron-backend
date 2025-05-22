package dbtestdata

import (
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

type Builder struct {
	t    *testing.T
	pool DBTX
}

func NewBuilder(t *testing.T, db DBTX) *Builder {
	return &Builder{t: t, pool: db}
}
