package authentic

import (
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dadamssolutions/authentic/handlers/csrf"
	"github.com/dadamssolutions/authentic/handlers/session"
)

func TestSignUp(t *testing.T) {
	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.SignUpAdapter())(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)

	resp, err := client.Do(req)
	cookie := resp.Cookies()[0]
	if cookie.Name != csrf.CookieName {
		cookie = resp.Cookies()[1]
	}
	if err != nil || resp.StatusCode != http.StatusOK || cookie.Value == "" {
		t.Error("Valid password request returned unexpected response")
	}

	resp.Body.Close()
}

func TestSignUpPost(t *testing.T) {
	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.SignUpAdapter())(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	w := httptest.NewRecorder()

	form := url.Values{}
	form.Set("username", "dAdams")
	form.Set("firstName", "Donnie")
	form.Set("lastName", "Adams")
	form.Set("email", "Test@gmail.com")
	form.Set("password", strings.Repeat("d", 32))
	form.Set("repeatedPassword", strings.Repeat("d", 32))

	tx, _ := db.Begin()
	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req = req.WithContext(session.NewTxContext(req.Context(), tx))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	a.csrfHandler.GenerateNewToken(w, req)
	req.AddCookie(w.Result().Cookies()[0])
	tx.Commit()

	resp, err := client.Do(req)
	redirectURL, _ := resp.Location()
	if err == nil || resp.StatusCode != http.StatusSeeOther || redirectURL.Path != a.RedirectAfterSignUp {
		log.Println(err)
		log.Println(resp.Status)
		log.Println(redirectURL.Path)
		t.Error("Sign up email not sent properly")
	}

	resp.Body.Close()
	removeTestUserFromDatabase()
}

func TestSignUpPostErrorChecking(t *testing.T) {
	err := addTestUserToDatabase(Member, true)
	if err != nil {
		t.Error(err)
	}

	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.SignUpAdapter())(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	testCases := []struct {
		firstName, lastName, username, email, password, repeatedPassword string
	}{
		{"Donnie", "Adams", "dadams", "test@gmail.com", "dddd", "dddd"},
		{"", "Adams", "dadams", "test@gmail.com", "dddd", "dddd"},
		{"Donnie", "", "dadams", "test@gmail.com", "dddd", "dddd"},
		{"Donnie", "Adams", "", "test@gmail.com", "dddd", "dddd"},
		{"Donnie", "Adams", "dadams", "", "dddd", "dddd"},
		{"Donnie", "Adams", "dadams", "test@gmail.com", "", "dddd"},
		{"Donnie", "Adams", "dadams", "test@gmail.com", "dddd", "ddd"},
	}

	for _, v := range testCases {
		w := httptest.NewRecorder()

		f := url.Values{"firstName": []string{v.firstName}, "lastName": []string{v.lastName}, "username": []string{v.username}, "email": []string{v.email}, "password": []string{v.password}, "repeatedPassword": []string{v.repeatedPassword}}

		req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(f.Encode()))
		tx, _ := db.Begin()
		req = req.WithContext(session.NewTxContext(req.Context(), tx))
		req.Header.Set("Content-type", "application/x-www-form-urlencoded")
		a.csrfHandler.GenerateNewToken(w, req)
		req.AddCookie(w.Result().Cookies()[0])
		tx.Commit()

		resp, err := client.Do(req)
		loc, _ := resp.Location()
		if err == nil || resp.StatusCode != http.StatusSeeOther || loc.Path != a.SignUpURL {
			t.Error("Password email sent when it shouldn't have been sent")
		}
		resp.Body.Close()
	}

	removeTestUserFromDatabase()
}

func TestUserValidation(t *testing.T) {
	err := addTestUserToDatabase(Member, false)
	if err != nil {
		t.Error(err)
	}
	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.SignUpVerificationAdapter())(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	tx, _ := db.Begin()
	token := a.passResetHandler.GenerateNewToken(tx, "dadams")
	tx.Commit()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?"+token.Query(), nil)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Error("User not validated correctly")
	}

	tx, _ = db.Begin()
	user := getUserFromDB(tx, a.usersTableName, "username", "dadams")
	if !user.IsValidated() {
		log.Println(user)
		t.Error("User validation request passed, but user was not validated in the database")
	}

	resp.Body.Close()
	tx.Commit()
	removeTestUserFromDatabase()
}

func TestUserValidationNoQuery(t *testing.T) {
	err := addTestUserToDatabase(Member, false)
	if err != nil {
		t.Error(err)
	}
	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.SignUpVerificationAdapter())(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	// Don't include the reset query
	//passQuery := a.passResetHandler.GenerateNewToken("dadams")
	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		log.Println(err)
		log.Println(resp.Status)
		t.Error("User validated without reset query")
	}

	tx, _ := db.Begin()
	user := getUserFromDB(tx, a.usersTableName, "username", "dadams")
	if user.IsValidated() {
		log.Println(user)
		t.Error("User validation request passed, but user was validated in the database incorrectly")
	}

	resp.Body.Close()
	tx.Commit()
	removeTestUserFromDatabase()
}

func TestUserValidationBadQuery(t *testing.T) {
	err := addTestUserToDatabase(Member, false)
	if err != nil {
		t.Error(err)
	}
	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.SignUpVerificationAdapter())(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	tx, _ := db.Begin()

	// Don't include the reset query
	token := a.passResetHandler.GenerateNewToken(tx, "dadams")
	tx.Commit()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?"+token.Query()[1:], nil)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Error("User validated without reset query")
	}

	tx, _ = db.Begin()
	user := getUserFromDB(tx, a.usersTableName, "username", "dadams")
	if user.IsValidated() {
		log.Println(user)
		t.Error("User validation request passed, but user was validated in the database incorrectly")
	}

	resp.Body.Close()
	tx.Commit()
	removeTestUserFromDatabase()
}

func TestUserCannotValidateIfLoggedIn(t *testing.T) {
	err := addTestUserToDatabase(Member, false)
	if err != nil {
		t.Error(err)
	}

	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.SignUpVerificationAdapter())(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	// Log user in by creating a session
	tx, _ := db.Begin()
	ses := a.sesHandler.CreateSession(tx, "dadams", true)
	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.AddCookie(ses.SessionCookie())
	tx.Commit()

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		log.Println(err)
		log.Println(resp.Status)
		t.Error("User was able to verify while logged in")
	}

	resp.Body.Close()
	removeTestUserFromDatabase()
}

func TestUsernameExists(t *testing.T) {
	err := addTestUserToDatabase(Member, false)
	if err != nil {
		t.Error(err)
	}

	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.SignUpAdapter())(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	w := httptest.NewRecorder()

	form := url.Values{}
	form.Set("username", "dadams")
	form.Set("firstName", "Donnie")
	form.Set("lastName", "Adams")
	form.Set("email", "other@gmail.com")
	form.Set("password", strings.Repeat("d", 32))
	form.Set("repeatedPassword", strings.Repeat("d", 32))

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	tx, _ := db.Begin()
	req = req.WithContext(session.NewTxContext(req.Context(), tx))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	a.csrfHandler.GenerateNewToken(w, req)
	req.AddCookie(w.Result().Cookies()[0])
	tx.Commit()

	resp, err := client.Do(req)
	redirectURL, _ := resp.Location()
	if err == nil || resp.StatusCode != http.StatusSeeOther || redirectURL.Path != a.SignUpURL {
		t.Error("Duplicated username was accepted in error")
	}

	resp.Body.Close()
	removeTestUserFromDatabase()
}

func TestEmailExists(t *testing.T) {
	err := addTestUserToDatabase(Member, false)
	if err != nil {
		t.Error(err)
	}

	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.SignUpAdapter())(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	w := httptest.NewRecorder()

	form := url.Values{}
	form.Set("username", "thedadams")
	form.Set("firstName", "Donnie")
	form.Set("lastName", "Adams")
	form.Set("email", "test@gmail.com")
	form.Set("password", strings.Repeat("d", 32))
	form.Set("repeatedPassword", strings.Repeat("d", 32))

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	tx, _ := db.Begin()
	req = req.WithContext(session.NewTxContext(req.Context(), tx))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	a.csrfHandler.GenerateNewToken(w, req)
	req.AddCookie(w.Result().Cookies()[0])
	tx.Commit()

	resp, err := client.Do(req)
	redirectURL, _ := resp.Location()
	if err == nil || resp.StatusCode != http.StatusSeeOther || redirectURL.Path != a.SignUpURL {
		t.Error("Duplicated email was accepted in error")
	}

	resp.Body.Close()
	removeTestUserFromDatabase()
}
