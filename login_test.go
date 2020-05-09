package authentic8

import (
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dadamssolutions/authentic8/handlers/session"
)

func TestUserLogInHandlerNotLoggedIn(t *testing.T) {
	num = 0
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}

	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.LoginAdapter())(testHand))
	defer ts.Close()
	ts.URL = ts.URL + "/login/"
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	req, _ := http.NewRequest("GET", ts.URL, nil)

	// No cookie present so should just redirect
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		log.Println(err)
		log.Println(resp.Status)
		t.Error("Request redirected in error")
	}
	resp.Body.Close()

	removeTestUserFromDatabase()
}

func TestUserLogInHandlerLoggingIn(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}
	num = 0
	w := httptest.NewRecorder()

	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.LoginAdapter())(testHand))
	defer ts.Close()
	ts.URL = ts.URL + "/login/"
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("username", "dAdams")
	form.Set("password", strings.Repeat("d", 64))
	form.Set("remember", "false")

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	tx, _ := db.Begin()
	req = req.WithContext(session.NewTxContext(req.Context(), tx))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	a.csrfHandler.GenerateNewToken(w, req)
	req.AddCookie(w.Result().Cookies()[0])
	tx.Commit()

	// POST request should log user in
	resp, err := client.Do(req)
	loc, _ := resp.Location()
	if err == nil || len(resp.Cookies()) != 1 || resp.StatusCode != http.StatusSeeOther || loc.Path != a.RedirectAfterLogin {
		log.Println(err)
		log.Println(len(resp.Cookies()))
		log.Println(resp.Status)
		t.Error("Should be redirected after a successful login")
	}

	tx, _ = db.Begin()
	ses, _ := a.sesHandler.ParseSessionCookie(tx, resp.Cookies()[0])
	if ses == nil || ses.IsPersistent() || ses.Username() != "dadams" || !ses.IsUserLoggedIn() {
		t.Error("The cookie on a login response is not valid")
	}
	resp.Body.Close()
	tx.Commit()

	// Now user should be redirected when visiting login page
	req, _ = http.NewRequest(http.MethodGet, ts.URL, nil)
	req.AddCookie(ses.SessionCookie())
	resp, err = client.Do(req)
	redirectedURL, _ := resp.Location()

	if err == nil || redirectedURL.Path != a.RedirectAfterLogin || len(resp.Cookies()) != 1 {
		log.Println(err)
		log.Println(redirectedURL.Path)
		log.Println(len(resp.Cookies()))
		t.Error("Request should be redirected when user is logged in")
	}
	if resp.StatusCode != http.StatusSeeOther {
		t.Error("Login GET request with user logged in should redirect")
	}
	resp.Body.Close()

	tx, _ = db.Begin()
	// Log user out
	ses, _ = a.sesHandler.ParseSessionCookie(tx, resp.Cookies()[0])
	cookie := ses.SessionCookie()
	a.sesHandler.DestroySession(tx, ses)
	tx.Commit()

	// Now user should be asked to login, even with expired session cookie attached
	req, _ = http.NewRequest("GET", ts.URL, nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Error("Request redirected in error")
	}
	if resp.StatusCode != http.StatusOK || num != 1 {
		log.Println(resp.StatusCode, num)
		t.Error("Login GET request with no user logged in should not redirect")
	}
	resp.Body.Close()

	removeTestUserFromDatabase()
}

func TestUserLogInHandlerBadInfo(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}
	num = 0
	w := httptest.NewRecorder()

	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.LoginAdapter())(testHand))
	defer ts.Close()
	ts.URL = ts.URL + "/login/"
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("username", "Dadams")
	form.Set("password", strings.Repeat("e", 64))
	form.Set("remember", "false")

	tx, _ := db.Begin()
	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req = req.WithContext(session.NewTxContext(req.Context(), tx))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	a.csrfHandler.GenerateNewToken(w, req)
	req.AddCookie(w.Result().Cookies()[0])
	tx.Commit()

	// POST request should not log user in with wrong password
	resp, err := client.Do(req)
	loc, _ := resp.Location()
	tx, _ = db.Begin()
	ses, _ := a.sesHandler.ParseSessionCookie(tx, resp.Cookies()[0])
	tx.Commit()
	_, errs := ses.Flashes()
	if err == nil || len(resp.Cookies()) != 1 || loc.Path != a.LoginURL || ses.IsUserLoggedIn() || len(errs) != 1 {
		log.Println(resp.Status)
		log.Println(resp.Location())
		log.Println(errs)
		t.Error("Should be redirected to the login page after unsuccessful login attempt")
	}
	resp.Body.Close()

	w = httptest.NewRecorder()
	form.Set("username", "nadams")
	tx, _ = db.Begin()
	req, _ = http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req = req.WithContext(session.NewTxContext(req.Context(), tx))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	a.csrfHandler.GenerateNewToken(w, req)
	req.AddCookie(w.Result().Cookies()[0])
	tx.Commit()

	// POST request should not log user in
	resp, _ = client.Do(req)
	loc, _ = resp.Location()
	if resp.StatusCode != http.StatusSeeOther || len(resp.Cookies()) != 1 || loc.Path != a.LoginURL {
		t.Error("Should be redirected to the login page after unsuccessful login attempt")
	}

	resp.Body.Close()
	removeTestUserFromDatabase()
}

func TestUserLogInHandlerPersistent(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}
	num = 0
	w := httptest.NewRecorder()
	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.LoginAdapter())(testHand))
	defer ts.Close()
	ts.URL = ts.URL + "/login/"
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("username", "dadamS")
	form.Set("password", strings.Repeat("d", 64))
	form.Set("remember", "true")

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	tx, _ := db.Begin()
	req = req.WithContext(session.NewTxContext(req.Context(), tx))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	a.csrfHandler.GenerateNewToken(w, req)
	req.AddCookie(w.Result().Cookies()[0])
	tx.Commit()

	// POST request should log user in
	resp, err := client.Do(req)
	if err == nil || len(resp.Cookies()) != 1 || resp.StatusCode != http.StatusSeeOther {
		t.Error("Should be redirected after a successful login")
	}

	tx, _ = db.Begin()
	ses, err := a.sesHandler.ParseSessionCookie(tx, resp.Cookies()[0])
	if err != nil || !ses.IsPersistent() {
		t.Error("Session created should be persistent with 'Remember me'")
	}
	resp.Body.Close()
	cookie := ses.SessionCookie()
	a.sesHandler.DestroySession(tx, ses)
	tx.Commit()

	// Now user should be asked to login, even with expired session cookie attached
	req, _ = http.NewRequest("GET", ts.URL, nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Error("Request redirected in error")
	}
	if resp.StatusCode != http.StatusOK || num != 1 {
		t.Error("Login GET request with no user logged in should not redirect")
	}

	resp.Body.Close()
	removeTestUserFromDatabase()
}

func TestUserLogInHandlerBadPersistent(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}
	num = 0
	w := httptest.NewRecorder()

	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.LoginAdapter())(testHand))
	defer ts.Close()
	ts.URL = ts.URL + "/login/"
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("username", "dadaMs")
	form.Set("password", strings.Repeat("d", 64))
	form.Set("remember", "yes")

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	tx, _ := db.Begin()
	req = req.WithContext(session.NewTxContext(req.Context(), tx))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	a.csrfHandler.GenerateNewToken(w, req)
	req.AddCookie(w.Result().Cookies()[0])
	tx.Commit()

	// POST request should log user in
	resp, err := client.Do(req)
	if err == nil || len(resp.Cookies()) == 0 || resp.StatusCode != http.StatusSeeOther {
		t.Error("Should be redirected after a successful login")
	}

	tx, _ = db.Begin()
	ses, err := a.sesHandler.ParseSessionCookie(tx, resp.Cookies()[0])
	if err != nil || ses.IsPersistent() {
		t.Error("Session created should not be persistent with bad remember value")
	}

	resp.Body.Close()
	tx.Commit()
	removeTestUserFromDatabase()
}

func TestUserLogInHandlerNoCSRF(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}
	num = 0

	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.LoginAdapter())(testHand))
	defer ts.Close()
	ts.URL = ts.URL + "/login/"
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("username", "dadams")
	form.Set("password", strings.Repeat("d", 64))
	form.Set("remember", "yes")

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	// Don't set the CSRF header
	// req.Header.Set(csrfhandler.HeaderName, a.csrfHandler.GenerateNewToken())

	// POST request should not be valid because the CSRF token is not there
	resp, err := client.Do(req)
	loc, _ := resp.Location()
	if err == nil || resp.StatusCode != http.StatusSeeOther || loc.Path != "/login/" {
		log.Println(err)
		log.Println(resp.StatusCode)
		log.Println(loc.Path)
		log.Println(ts.URL)
		t.Error("Login attempt without CSRF token should redirect to login page")
	}

	resp.Body.Close()
	removeTestUserFromDatabase()
}
func TestUserNotValidatedCannotLogIn(t *testing.T) {
	err := addTestUserToDatabase(false)
	if err != nil {
		t.Error(err)
	}
	w := httptest.NewRecorder()

	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.LoginAdapter())(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("username", "dadams")
	form.Set("password", strings.Repeat("d", 64))
	form.Set("remember", "true")

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	tx, _ := db.Begin()
	req = req.WithContext(session.NewTxContext(req.Context(), tx))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	a.csrfHandler.GenerateNewToken(w, req)
	req.AddCookie(w.Result().Cookies()[0])
	tx.Commit()

	tx, _ = db.Begin()
	// POST request should log user in
	resp, err := client.Do(req)
	ses, _ := a.sesHandler.ParseSessionCookie(tx, resp.Cookies()[0])
	if err == nil || ses == nil || ses.IsUserLoggedIn() || resp.StatusCode != http.StatusSeeOther {
		log.Println(err)
		log.Println(ses)
		log.Println(ses.IsUserLoggedIn())
		t.Error("User should not be able to log in if they are unverified")
	}

	resp.Body.Close()
	tx.Commit()
	removeTestUserFromDatabase()
}

func TestUserLogInHandlerRedirecting(t *testing.T) {
	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.RedirectIfUserNotAuthenticated())(testHand))
	defer ts.Close()
	ts.URL = ts.URL + "/user/"
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)

	// Should redirect user to login page
	resp, err := client.Do(req)
	loc, _ := resp.Location()
	if err == nil || len(resp.Cookies()) != 1 || resp.StatusCode != http.StatusSeeOther || loc.Path != a.LoginURL || loc.Query().Get("redirect") != "/user/" {
		log.Println(err)
		log.Println(len(resp.Cookies()))
		log.Println(resp.Status)
		t.Error("Should be redirected to login page with redirect query string")
	}

	resp.Body.Close()
}

func TestUserLogInHandlerFailedLoginKeepsQuery(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}
	num = 0
	w := httptest.NewRecorder()

	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.LoginAdapter())(testHand))
	defer ts.Close()
	ts.URL = ts.URL + "/login/?redirect=" + url.QueryEscape("/user/")
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("username", "Dadams")
	form.Set("password", strings.Repeat("e", 64))
	form.Set("remember", "false")

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	tx, _ := db.Begin()
	req = req.WithContext(session.NewTxContext(req.Context(), tx))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	a.csrfHandler.GenerateNewToken(w, req)
	req.AddCookie(w.Result().Cookies()[0])
	tx.Commit()

	tx, _ = db.Begin()
	// POST request should not log user in with wrong password
	resp, err := client.Do(req)
	loc, _ := resp.Location()
	ses, _ := a.sesHandler.ParseSessionCookie(tx, resp.Cookies()[0])
	_, errs := ses.Flashes()
	if err == nil || len(resp.Cookies()) != 1 || loc.Path != a.LoginURL || ses.IsUserLoggedIn() || len(errs) != 1 || loc.Query().Get("redirect") != "/user/" {
		log.Println(resp.Status)
		log.Println(resp.Location())
		log.Println(errs)
		t.Error("Should be redirected to the login page with same query string after unsuccessful login attempt")
	}

	resp.Body.Close()
	tx.Commit()
	removeTestUserFromDatabase()
}

func TestUserLogInHandlerRedirectWithQuery(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}
	num = 0
	w := httptest.NewRecorder()

	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.LoginAdapter())(testHand))
	defer ts.Close()
	ts.URL = ts.URL + "/login/?redirect=" + url.QueryEscape("/redirect/after/login/")
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("username", "dAdams")
	form.Set("password", strings.Repeat("d", 64))
	form.Set("remember", "false")

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	tx, _ := db.Begin()
	req = req.WithContext(session.NewTxContext(req.Context(), tx))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	a.csrfHandler.GenerateNewToken(w, req)
	req.AddCookie(w.Result().Cookies()[0])
	tx.Commit()

	// POST request should log user in
	resp, err := client.Do(req)
	loc, _ := resp.Location()
	if err == nil || len(resp.Cookies()) != 1 || resp.StatusCode != http.StatusSeeOther || loc.Path != "/redirect/after/login/" {
		log.Println(err)
		log.Println(len(resp.Cookies()))
		log.Println(resp.Status)
		t.Error("Should be redirected to redirect query after a successful login")
	}

	tx, _ = db.Begin()
	ses, _ := a.sesHandler.ParseSessionCookie(tx, resp.Cookies()[0])
	if ses == nil || ses.IsPersistent() || ses.Username() != "dadams" || !ses.IsUserLoggedIn() {
		t.Error("The cookie on a login response is not valid")
	}

	resp.Body.Close()
	tx.Commit()
	removeTestUserFromDatabase()
}
