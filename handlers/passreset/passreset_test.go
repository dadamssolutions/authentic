package passreset

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/dadamssolutions/authentic/handlers/session"
	"github.com/jackc/pgx/v4/pgxpool"
)

var passHand *Handler
var ctx context.Context
var db *pgxpool.Pool

func TestTokenGeneration(t *testing.T) {
	tx, _ := db.Begin(ctx)
	c := session.NewTxContext(ctx, tx)
	token := passHand.GenerateNewToken(c, "dadams")
	if token == nil {
		t.Error("Could not generate a new token")
	}
	// Create a request so we can validate the token which destroys it as well
	req := httptest.NewRequest(http.MethodGet, "/?"+token.Query(), nil)
	req = req.WithContext(session.NewTxContext(req.Context(), tx))
	passHand.ValidToken(req)
	tx.Commit(ctx)
}

func TestTokenValidation(t *testing.T) {
	var username string
	var err error
	tx, _ := db.Begin(ctx)
	c := session.NewTxContext(ctx, tx)
	token := passHand.GenerateNewToken(c, "dadams")
	req := httptest.NewRequest(http.MethodGet, "/?"+token.Query(), nil)
	req = req.WithContext(session.NewTxContext(req.Context(), tx))
	if username, err = passHand.ValidToken(req); err != nil || username != "dadams" {
		t.Error("Token should be valid right after it is created")
	}
	if username, err = passHand.ValidToken(req); err == nil || username != "" {
		t.Error("Token should not be valid twice")
	}
	tx.Commit(ctx)
}

func TestMain(m *testing.M) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	var err error
	ctx = context.Background()
	triesLeft := 5
	db, err = pgxpool.Connect(ctx, "postgres://authentic:authentic@db:5432/authentic_passreset?sslmode=disable")

	// Wait for the database to be ready.
	for triesLeft > 0 {
		if tx, err := db.Begin(ctx); err == nil {
			tx.Rollback(ctx)
			break
		}
		log.Printf("Database not ready, %d tries left", triesLeft)
		triesLeft--
		time.Sleep(10 * time.Second)
	}
	if err != nil {
		log.Fatal(err)
	}
	passHand = NewHandler(ctx, db, "pass_reset_tokens", time.Minute, bytes.Repeat([]byte("d"), 16))
	num := m.Run()
	os.Exit(num)
}
