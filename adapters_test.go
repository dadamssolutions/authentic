package authentic

import (
	"fmt"
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

func TestRedirectWithErrorOnContext(t *testing.T) {
	redirectCalled := false
	g := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectCalled = true
	})
	redirectHandler := RedirectIfErrorOnContext(g)(testHand)
	r, _ := http.NewRequest("GET", "/", nil)
	redirectHandler.ServeHTTP(&httptest.ResponseRecorder{}, r)
	if redirectCalled {
		t.Error("Redirect should not be called when there is no error on the context")
	}

	redirectHandler.ServeHTTP(&httptest.ResponseRecorder{}, r.WithContext(NewErrorContext(r.Context(), fmt.Errorf("New error"))))

	if !redirectCalled {
		t.Error("Redirect should be called when an error is on the context")
	}
}

func TestAdaptAndAbsorbError(t *testing.T) {
	num := 0
	g := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			num++
			h.ServeHTTP(w, r)
		})
	}
	adaptAndAbsorbError(testHand, g).ServeHTTP(&httptest.ResponseRecorder{}, httptest.NewRequest("GET", "/", nil))
	if num != 1 {
		t.Errorf("Adapter not called correct number of time: %v", num)
	}

	adaptAndAbsorbError(testHand, g, g, g).ServeHTTP(&httptest.ResponseRecorder{}, httptest.NewRequest("GET", "/", nil))
	if num != 4 {
		t.Errorf("Adapter not called correct number of time: %v", num)
	}
	eg := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r.WithContext(NewErrorContext(r.Context(), fmt.Errorf("New error"))))
		})
	}
	adaptAndAbsorbError(testHand, g, eg, g, g).ServeHTTP(&httptest.ResponseRecorder{}, httptest.NewRequest("GET", "/", nil))
	if num != 5 {
		t.Errorf("Adapter not called correct number of time: %v", num)
	}
}

func panicHandler(w http.ResponseWriter, r *http.Request) {
	panic("Panic handler called")
}
