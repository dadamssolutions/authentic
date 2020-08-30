package session

import (
	"context"

	"github.com/jackc/pgx/v4"
)

type key int

var txKey key = 0

// NewTxContext adds a *sql.Tx to the context.
func NewTxContext(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, txKey, tx)
}

// TxFromContext looks for a transaction in the context.
// If there is no transaction found, then the return value will be nil.
func TxFromContext(ctx context.Context) pgx.Tx {
	tx, _ := ctx.Value(txKey).(pgx.Tx)
	return tx
}
