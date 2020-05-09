package session

import (
	"context"
	"database/sql"
)

type key int

var txKey key = 0

// NewTxContext adds a *sql.Tx to the context.
func NewTxContext(ctx context.Context, tx *sql.Tx) context.Context {
	return context.WithValue(ctx, txKey, tx)
}

// TxFromContext looks for a transaction in the context.
// If there is no transaction found, then the return value will be nil.
func TxFromContext(ctx context.Context) *sql.Tx {
	tx, _ := ctx.Value(txKey).(*sql.Tx)
	return tx
}
