package authentic8

import (
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUserLogOutHandler(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}
	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.LogoutAdapter("/"))(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	req, _ := http.NewRequest("GET", ts.URL, nil)
	tx, _ := db.Begin()
	ses := a.sesHandler.CreateSession(tx, "dadams", true)
	tx.Commit()

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

	tx, _ = db.Begin()
	newSession, _ := a.sesHandler.ParseSessionCookie(tx, resp.Cookies()[0])
	if resp.StatusCode != http.StatusSeeOther || newSession.IsUserLoggedIn() {
		log.Println(newSession.IsUserLoggedIn())
		t.Error("User not logged out properly")
	}
	resp.Body.Close()
	tx.Commit()

	// Cookie present, but already logged out. User should be redirected
	resp, err = client.Do(req)
	if err == nil {
		t.Error("Request not redirected")
	}

	tx, _ = db.Begin()
	newSession, _ = a.sesHandler.ParseSessionCookie(tx, resp.Cookies()[0])
	if resp.StatusCode != http.StatusSeeOther || newSession.IsUserLoggedIn() {
		log.Println(ses.IsUserLoggedIn())
		t.Error("User not logged out properly")
	}
	resp.Body.Close()
	tx.Commit()
	removeTestUserFromDatabase()
}
