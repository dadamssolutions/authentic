package authentic8

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestTxContext(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectCommit()

	server := httptest.NewServer(PutTxOnContext(db)(testHand))
	defer server.Close()
	server.URL += "/login/"

	client := server.Client()
	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)

	if err != nil || resp.StatusCode != http.StatusOK || mock.ExpectationsWereMet() != nil {
		t.Errorf("A simple request should begin transaction, call handler, and commit transaction")
	}
}

func TestTxPanic(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectRollback()

	server := httptest.NewServer(PutTxOnContext(db)(http.HandlerFunc(panicHandler)))
	defer server.Close()
	server.URL += "/login/"

	client := server.Client()
	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)

	if err != nil || resp.StatusCode != http.StatusInternalServerError || mock.ExpectationsWereMet() != nil {
		t.Errorf("If the handler panics, we should get an internal server error")
	}
}

func panicHandler(w http.ResponseWriter, r *http.Request) {
	panic("Panic handler called")
}
