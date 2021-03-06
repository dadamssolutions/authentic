package authentic

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dadamssolutions/authentic/handlers/session"
)

func TestPasswordResetNoQuery(t *testing.T) {
	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.PasswordResetAdapter())(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	req, _ := http.NewRequest("GET", ts.URL, nil)
	resp, err := client.Do(req)
	redirectURL, _ := resp.Location()
	if err == nil || resp.StatusCode != http.StatusSeeOther || redirectURL.Path != a.PasswordResetRequestURL {
		log.Println(err)
		log.Println(resp.Status)
		log.Println(redirectURL.Path)
		t.Error("Get request to password reset with no query should fail")
	}
	resp.Body.Close()
}

func TestPasswordResetLoggedIn(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}

	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.PasswordResetAdapter())(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	req, _ := http.NewRequest("GET", ts.URL, nil)
	// Fake log a user in
	tx, _ := db.Begin()
	ses := a.sesHandler.CreateSession(tx, "dadams", true)
	req.AddCookie(ses.SessionCookie())
	tx.Commit()

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Error("Get request to password reset with logged in user should go through")
	}
	resp.Body.Close()

	// Fake log user out.
	tx, _ = db.Begin()
	a.sesHandler.DestroySession(tx, ses)
	tx.Commit()

	resp, err = client.Do(req)
	redirectURL, _ := resp.Location()
	if len(req.Cookies()) == 0 || err == nil || resp.StatusCode != http.StatusSeeOther || redirectURL.Path != a.PasswordResetRequestURL {
		t.Error("Get request to password reset after user logged out should redirect")
	}

	resp.Body.Close()
	removeTestUserFromDatabase()
}

func TestPasswordResetValidQuery(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}

	tx, _ := db.Begin()
	token := a.passResetHandler.GenerateNewToken(tx, "dadams")
	tx.Commit()
	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.PasswordResetAdapter())(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	req, _ := http.NewRequest("GET", ts.URL+"?"+token.Query(), nil)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		log.Println(err)
		log.Println(resp.StatusCode, resp.Status)
		t.Error("Get request to password reset with correct query should go through")
	}
	resp.Body.Close()

	// Second request should be invalid
	resp, err = client.Do(req)
	redirectURL, _ := resp.Location()
	if err == nil || resp.StatusCode != http.StatusSeeOther || redirectURL.Path != a.PasswordResetRequestURL {
		t.Error("Get request to password reset with user query token should fail")
	}

	resp.Body.Close()
	removeTestUserFromDatabase()
}

func TestPasswordResetForm(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}
	w := httptest.NewRecorder()

	tx, _ := db.Begin()
	token := a.passResetHandler.GenerateNewToken(tx, "dadams")
	tx.Commit()
	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.PasswordResetAdapter())(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("password", strings.Repeat("e", 64))
	form.Set("repeatedPassword", strings.Repeat("e", 64))

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	tx, _ = db.Begin()
	req = req.WithContext(session.NewTxContext(req.Context(), tx))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	req.AddCookie(token.SessionCookie())
	a.csrfHandler.GenerateNewToken(w, req)
	req.AddCookie(w.Result().Cookies()[0])
	tx.Commit()

	resp, err := client.Do(req)
	redirectURL, _ := resp.Location()
	if err == nil || resp.StatusCode != http.StatusSeeOther || redirectURL.Path != a.LoginURL {
		log.Println(err)
		log.Println(resp.Status)
		log.Println(resp.Location())
		t.Error("Post request with valid token should redirect to " + a.LoginURL)
	}
	resp.Body.Close()

	tx, _ = db.Begin()
	passHash := getUserPasswordHash(tx, a.usersTableName, "dadams")
	if a.CompareHashAndPassword(passHash, ([]byte(bytes.Repeat([]byte("e"), 64)))) != nil {
		t.Error("Password hash wasn't updated properly")
	}
	tx.Commit()

	removeTestUserFromDatabase()
}

func TestPasswordResetNoCSRF(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}

	tx, _ := db.Begin()
	token := a.passResetHandler.GenerateNewToken(tx, "dadams")
	tx.Commit()
	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.PasswordResetAdapter())(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("password", strings.Repeat("e", 64))
	form.Set("repeatedPassword", strings.Repeat("e", 64))

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	req.AddCookie(token.SessionCookie())

	resp, err := client.Do(req)
	redirectURL, _ := resp.Location()
	if err == nil || resp.StatusCode != http.StatusSeeOther || redirectURL.Path != a.PasswordResetRequestURL {
		log.Println(err)
		log.Println(resp.Status)
		log.Println(resp.Location())
		t.Error("Post request without csrf token should redirect to " + a.PasswordResetURL)
	}
	resp.Body.Close()

	tx, _ = db.Begin()
	passHash := getUserPasswordHash(tx, a.usersTableName, "dadams")
	if a.CompareHashAndPassword(passHash, ([]byte(bytes.Repeat([]byte("d"), 64)))) != nil {
		t.Error("Password hash was updated when it shouldn't have")
	}
	tx.Commit()

	removeTestUserFromDatabase()
}

func TestPasswordResetNoPasswordToken(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}
	w := httptest.NewRecorder()

	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.PasswordResetAdapter())(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("password", strings.Repeat("e", 64))
	form.Set("repeatedPassword", strings.Repeat("e", 64))

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	tx, _ := db.Begin()
	req = req.WithContext(session.NewTxContext(req.Context(), tx))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	a.csrfHandler.GenerateNewToken(w, req)
	req.AddCookie(w.Result().Cookies()[0])

	resp, err := client.Do(req)
	redirectURL, _ := resp.Location()
	if err == nil || resp.StatusCode != http.StatusSeeOther || redirectURL.Path != a.PasswordResetRequestURL {
		log.Println(err)
		log.Println(resp.Status)
		log.Println(resp.Location())
		t.Error("Post request without password reset token should redirect to " + a.PasswordResetURL)
	}
	resp.Body.Close()
	tx.Commit()

	tx, _ = db.Begin()
	passHash := getUserPasswordHash(tx, a.usersTableName, "dadams")
	if a.CompareHashAndPassword(passHash, ([]byte(bytes.Repeat([]byte("d"), 64)))) != nil {
		t.Error("Password hash was updated when it shouldn't have")
	}
	tx.Commit()

	removeTestUserFromDatabase()
}

func TestPasswordResetRequest(t *testing.T) {
	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.PasswordResetRequestAdapter())(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK || resp.Cookies()[0].Value == "" {
		log.Println(err)
		log.Println(resp.Status)
		t.Error("Valid password request returned unexpected response")
	}
	resp.Body.Close()
}

func TestSendPasswordResetEmail(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}
	w := httptest.NewRecorder()

	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.PasswordResetRequestAdapter())(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("email", "test@gmail.com")

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	tx, _ := db.Begin()
	req = req.WithContext(session.NewTxContext(req.Context(), tx))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	a.csrfHandler.GenerateNewToken(w, req)
	req.AddCookie(w.Result().Cookies()[0])
	tx.Commit()

	resp, err := client.Do(req)
	redirectURL, _ := resp.Location()
	if err == nil || resp.StatusCode != http.StatusSeeOther || redirectURL.Path != a.RedirectAfterResetRequest {
		t.Error("Password email not sent properly")
	}

	resp.Body.Close()
	removeTestUserFromDatabase()
}

func TestSendPasswordResetEmailWithoutCSRF(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}

	ts := httptest.NewTLSServer(a.PasswordResetRequestAdapter()(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("email", "test@gmail.com")

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	redirectURL, _ := resp.Location()
	if err == nil || resp.StatusCode != http.StatusSeeOther || redirectURL.Path != a.PasswordResetRequestURL {
		log.Println(err)
		log.Println(resp.Status)
		log.Println(redirectURL.Path)
		t.Error("Password reset email was sent without CSRF verification")
	}

	resp.Body.Close()
	removeTestUserFromDatabase()
}

func TestSendPasswordResetEmailBadEmail(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}

	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.PasswordResetRequestAdapter())(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	testCases := []url.Values{
		{"test": []string{"test@outlook.com"}},
		{"test": []string{"test@outlook.com"}},
		{"test": []string{"first last@outlook.com"}},
		{"test": []string{"test@google mail.com"}},
		{"test": []string{"test@outlook\n--.com"}},
		{"test": []string{"test@out -- look.com"}},
	}

	for _, f := range testCases {
		url := f.Encode()
		w := httptest.NewRecorder()
		tx, _ := db.Begin()
		req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(url))
		req = req.WithContext(session.NewTxContext(req.Context(), tx))
		req.Header.Set("Content-type", "application/x-www-form-urlencoded")
		a.csrfHandler.GenerateNewToken(w, req)
		req.AddCookie(w.Result().Cookies()[0])
		tx.Commit()

		resp, err := client.Do(req)
		redirectURL, _ := resp.Location()
		if err == nil || resp.StatusCode != http.StatusSeeOther || redirectURL.Path != a.PasswordResetRequestURL {
			log.Println(err)
			log.Println(resp.Status)
			log.Println(redirectURL.Path)
			t.Error("Password email sent when it shouldn't have been sent")
		}
	}

	removeTestUserFromDatabase()
}
