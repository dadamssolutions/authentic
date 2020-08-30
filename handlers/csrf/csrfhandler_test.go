package csrf

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

var csrfHand *Handler
var ctx = context.Background()
var db, _ = pgxpool.Connect(ctx, "postgres://authentic:authentic@db:5432/authentic_csrfs?sslmode=disable")

func TestTokenGeneration(t *testing.T) {
	w := httptest.NewRecorder()
	tx, _ := db.Begin(ctx)
	// Create a request so we can validate the token which destroys it as well
	req, _ := http.NewRequest("POST", "", nil)
	req = req.WithContext(session.NewTxContext(req.Context(), tx))
	err := csrfHand.GenerateNewToken(w, req)
	if err != nil {
		t.Error("Could not generate a new token")
	}

	req.AddCookie(w.Result().Cookies()[0])
	csrfHand.ValidToken(req)
	tx.Commit(ctx)
}

func TestTokenValidation(t *testing.T) {
	w := httptest.NewRecorder()
	tx, _ := db.Begin(ctx)
	req, _ := http.NewRequest("POST", "", nil)
	req = req.WithContext(session.NewTxContext(req.Context(), tx))
	csrfHand.GenerateNewToken(w, req)
	req.AddCookie(w.Result().Cookies()[0])
	csrfHand.GenerateNewToken(w, req)
	if err := csrfHand.ValidToken(req); err != nil {
		t.Error("Token should be valid right after it is created")
	}
	if err := csrfHand.ValidToken(req); err == nil {
		t.Error("Token should not be valid after it is validated")
	}
	tx.Commit(ctx)
}

func TestMain(m *testing.M) {
	triesLeft := 5

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
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	csrfHand = NewHandler(ctx, db, time.Minute, bytes.Repeat([]byte("d"), 16))
	num := m.Run()
	os.Exit(num)
}
