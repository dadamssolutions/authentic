package authentic

import (
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dadamssolutions/authentic/handlers/session"
)

func TestUserLogOutHandler(t *testing.T) {
	err := addTestUserToDatabase(Member, true)
	if err != nil {
		t.Error(err)
	}
	ts := httptest.NewTLSServer(a.MustHaveAdapters(ctx, db, a.LogoutAdapter("/"))(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	req, _ := http.NewRequest("GET", ts.URL, nil)
	tx, _ := db.Begin(ctx)
	c := session.NewTxContext(ctx, tx)
	ses := a.sesHandler.CreateSession(c, "dadams", true)
	tx.Commit(ctx)

	// No cookie present so should just redirect
	resp, err := client.Do(req)
	if err == nil {
		t.Error("Request not redirected")
	}
	loc, err := resp.Location()
	if resp.StatusCode != http.StatusSeeOther || err != nil || loc.Path != "/" {
		t.Error("Logout with no user logged in should just redirect to \"/\"")
	}
	resp.Body.Close()

	// Cookie present. User should be logged out.
	req.AddCookie(ses.SessionCookie())
	resp, err = client.Do(req)
	if err == nil || len(resp.Cookies()) != 1 {
		log.Println(resp.Cookies())
		t.Error("Request not redirected")
	}

	tx, _ = db.Begin(ctx)
	c = session.NewTxContext(ctx, tx)
	newSession, _ := a.sesHandler.ParseSessionCookie(c, resp.Cookies()[0])
	if resp.StatusCode != http.StatusSeeOther || newSession.IsUserLoggedIn() {
		log.Println(newSession.IsUserLoggedIn())
		t.Error("User not logged out properly")
	}
	resp.Body.Close()
	tx.Commit(ctx)

	// Cookie present, but already logged out. User should be redirected
	resp, err = client.Do(req)
	if err == nil {
		t.Error("Request not redirected")
	}

	tx, _ = db.Begin(ctx)
	c = session.NewTxContext(ctx, tx)
	newSession, _ = a.sesHandler.ParseSessionCookie(c, resp.Cookies()[0])
	if resp.StatusCode != http.StatusSeeOther || newSession.IsUserLoggedIn() {
		log.Println(ses.IsUserLoggedIn())
		t.Error("User not logged out properly")
	}
	resp.Body.Close()
	tx.Commit(ctx)
	removeTestUserFromDatabase()
}
