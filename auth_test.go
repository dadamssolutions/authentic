package authentic

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/smtp"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dadamssolutions/authentic/handlers/email"
	"github.com/dadamssolutions/authentic/handlers/session"
	"github.com/lib/pq"
)

var a *HTTPAuth
var num int
var testHand testHandler
var db *sql.DB

func checkRedirect(req *http.Request, via []*http.Request) error {
	return fmt.Errorf("Redirected to %v", req.URL)
}

type testHandler struct{}

func (t testHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	num++
	err := ErrorFromContext(r.Context())
	if err != nil {
		log.Println(err)
		num *= 10
	}
	w.Write([]byte("Test handler"))
}

func deleteTestTables(db *sql.DB, tableName ...string) error {
	tx, err := db.Begin()
	if err != nil {
		return nil
	}
	for i := range tableName {
		_, err = tx.Exec(fmt.Sprintf(deleteTestTableSQL, pq.QuoteLiteral(tableName[i])))
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func addTestUserToDatabase(validated bool) error {
	// Add user to the database for testing
	pass := strings.Repeat("d", 64)
	passHash, _ := a.GenerateHashFromPassword([]byte(pass))
	tx, _ := db.Begin()
	_, err := tx.Exec(fmt.Sprintf("INSERT INTO %v (username, email, pass_hash, validated) VALUES ('dadams', 'test@gmail.com', '%v', %v);", a.usersTableName, base64.RawURLEncoding.EncodeToString(passHash), validated))
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func removeTestUserFromDatabase() {
	// Remove user from database
	tx, _ := db.Begin()
	tx.Exec("DELETE FROM sessions WHERE user_id = 'dadams';")
	tx.Exec("DELETE FROM csrfs WHERE user_id = 'dadams';")
	tx.Exec(fmt.Sprintf("DELETE FROM %v WHERE username = 'dadams';", a.usersTableName))
	tx.Commit()
}

func TestUserNotLoggedInHandler(t *testing.T) {
	num = 0
	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.RedirectIfUserNotAuthenticated())(testHand))
	defer ts.Close()

	client := ts.Client()
	client.CheckRedirect = checkRedirect
	resp, err := client.Get(ts.URL)
	if err == nil || resp.StatusCode != http.StatusSeeOther || num != 0 || len(resp.Cookies()) == 0 {
		log.Println(err)
		log.Println(resp.Status)
		log.Println(len(resp.Cookies()))
		t.Error("Not redirected when user is not logged in")
	}
	resp.Body.Close()
}

func TestUserLoggedInHandler(t *testing.T) {
	num = 0
	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.RedirectIfUserNotAuthenticated())(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)

	tx, _ := db.Begin()
	defer catchTxError(tx, t, false)
	// Create the user logged in session
	ses := a.sesHandler.CreateSession(tx, "dadams", true)
	req.AddCookie(ses.SessionCookie())
	tx.Commit()

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK || num != 1 {
		log.Printf("Status code: %v with error: %v\n", resp.Status, err)
		t.Error("Redirected, but user is logged in")
	}

	if len(resp.Cookies()) == 0 || resp.Cookies()[0].Name != ses.SessionCookie().Name || resp.Cookies()[0].Value != ses.CookieValue() {
		log.Println(len(resp.Cookies()))
		t.Error("Cookie attached to response does not correspond to the session")
	}
	resp.Body.Close()
}

func TestUserHasRole(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}
	num = 0
	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.RedirectIfNoPermission(0))(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)

	tx, _ := db.Begin()
	// Create the user logged in session
	ses := a.sesHandler.CreateSession(tx, "dadams", true)
	req.AddCookie(ses.SessionCookie())
	req = req.WithContext(session.NewTxContext(req.Context(), tx))
	user := a.CurrentUser(req)
	tx.Commit()

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK || num != 1 {
		t.Error("Redirected, but user has permission")
	}
	resp.Body.Close()

	user.Role = Admin
	req, _ = http.NewRequest(http.MethodGet, ts.URL, nil)

	tx, _ = db.Begin()
	// Create the user logged in session
	ses = a.sesHandler.CreateSession(tx, "dadams", true)
	req.AddCookie(ses.SessionCookie())
	tx.Commit()

	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK || num != 2 {
		t.Error("Redirected, but user has permission")
	}
	resp.Body.Close()

	removeTestUserFromDatabase()
}

func TestUserDoesNotHaveRole(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}
	num = 0
	ts := httptest.NewTLSServer(a.MustHaveAdapters(db, a.RedirectIfNoPermission(2))(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)

	tx, _ := db.Begin()
	// Create the user logged in session
	ses := a.sesHandler.CreateSession(tx, "dadams", true)
	req.AddCookie(ses.SessionCookie())
	req = req.WithContext(session.NewTxContext(req.Context(), tx))
	user := a.CurrentUser(req)
	tx.Commit()

	resp, err := client.Do(req)
	if err == nil || resp.StatusCode != http.StatusSeeOther || num != 0 {
		t.Error("Not redirected when user does not have permission")
	}
	resp.Body.Close()

	user.Role = Manager
	req, _ = http.NewRequest(http.MethodGet, ts.URL, nil)

	tx, _ = db.Begin()
	// Create the user logged in session
	ses = a.sesHandler.CreateSession(tx, "dadams", true)
	req.AddCookie(ses.SessionCookie())
	tx.Commit()

	resp, err = client.Do(req)
	if err == nil || resp.StatusCode != http.StatusSeeOther || num != 0 {
		t.Error("Not redirected when user does not have permission")
	}
	resp.Body.Close()

	removeTestUserFromDatabase()
}

func TestCurrentUserBadCookie(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	tx, _ := db.Begin()
	req = req.WithContext(session.NewTxContext(req.Context(), tx))

	if a.CurrentUser(req) != nil {
		t.Error("No cookie in request should return empty string")
	}
	tx.Commit()

	tx, _ = db.Begin()
	// Create the user logged in session
	ses := a.sesHandler.CreateSession(tx, "dadams", true)
	req.AddCookie(ses.SessionCookie())
	a.sesHandler.DestroySession(tx, ses)

	if a.CurrentUser(req) != nil {
		t.Error("Destroyed cookie in request should return empty string")
	}
	tx.Commit()

	removeTestUserFromDatabase()
}

func TestCurrentUserGoodCookie(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}

	tx, _ := db.Begin()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(session.NewTxContext(req.Context(), tx))

	// Create the user logged in session
	ses := a.sesHandler.CreateSession(tx, "dadams", true)
	req.AddCookie(ses.SessionCookie())

	if a.CurrentUser(req).Username != "dadams" {
		t.Error("Valid cookie in request should return correct user")
	}
	tx.Commit()

	removeTestUserFromDatabase()
}

func TestCurrentUserFromContext(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}

	user := &User{FirstName: "Donnie", LastName: "Adams", Username: "dadams", Email: "test%40gmail.com"}

	tx, _ := db.Begin()
	ses := a.sesHandler.CreateSession(tx, user.Username, false)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(session.NewTxContext(req.WithContext(NewUserContext(req.Context(), user)).Context(), tx))

	userFromContext := a.CurrentUser(req)

	// If the session has not been added, then we should get no current user.
	if userFromContext != nil {
		t.Error("If no cookie is included, then no user should be found")
	}

	// Now we attach the cookie and the request should have a user.
	req.AddCookie(ses.SessionCookie())
	userFromContext = a.CurrentUser(req)

	if userFromContext == nil || userFromContext.Username != "dadams" {
		t.Error("Valid cookie in request should return correct user")
	}
	tx.Commit()

	removeTestUserFromDatabase()
}

func TestIsCurrentUser(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}
	tx, _ := db.Begin()

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(session.NewTxContext(req.Context(), tx))

	// Create the user logged in session
	ses := a.sesHandler.CreateSession(tx, "dadams", true)
	req.AddCookie(ses.SessionCookie())

	if !a.IsCurrentUser(req, "dadams") {
		t.Error("Current user should be dadams with valid cookie")
	}

	if a.IsCurrentUser(req, "nadams") {
		t.Error("Current user should not be nadams with valid cookie")
	}

	if a.IsCurrentUser(req, "") {
		t.Error("Current user should automatically be false if username is empty")
	}

	a.sesHandler.DestroySession(tx, ses)
	if a.IsCurrentUser(req, "dadams") {
		t.Error("Current user should not be dadams with destroyed cookie")
	}
	tx.Commit()

	removeTestUserFromDatabase()
}

func TestGetUserNotInDatabasePasswordHash(t *testing.T) {
	var b []byte
	tx, _ := db.Begin()
	defer catchTxError(tx, t, true)
	defer func() {
		if b != nil {
			t.Error("User not in database returned a valid password hash")
		}
	}()
	b = getUserPasswordHash(tx, a.usersTableName, "nadams")
}

func TestGetUserInDatabasePasswordHash(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}
	tx, _ := db.Begin()

	b := getUserPasswordHash(tx, a.usersTableName, "dadams")
	a.CompareHashAndPassword(b, []byte(strings.Repeat("d", 64)))
	if b == nil {
		log.Println(b)
		t.Error("User in database returned an invalid password hash")
	}
	tx.Commit()

	removeTestUserFromDatabase()
}

func TestUpdateUserLastAccess(t *testing.T) {
	err := addTestUserToDatabase(true)
	if err != nil {
		t.Error(err)
	}
	epoch, _ := time.Parse(dateLayout, "1970-01-01 00:00:00")

	tx, _ := db.Begin()
	updateTime := getUserLastAccess(tx, a.usersTableName, "dadams")
	if !updateTime.Equal(epoch) {
		t.Error("User should be created with epoch time as last access time")
	}

	now := time.Now()
	updateUserLastAccess(tx, a.usersTableName, "dadams")
	updateTime = getUserLastAccess(tx, a.usersTableName, "dadams")
	if updateTime.Equal(now) {
		t.Error("User access time not updated")
	}
	tx.Commit()
	removeTestUserFromDatabase()
}

// A Test send mail function so actual emails are not sent
func SendMail(hostname string, auth smtp.Auth, from string, to []string, msg []byte) error {
	if len(to) > 1 {
		return errors.New("Message should only be sent to one address")
	}
	message, err := mail.ReadMessage(bytes.NewReader(msg))
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(message.Body)
	if err != nil {
		return err
	}
	if message.Header.Get("Content-Type") == "" || message.Header.Get("To") != to[0] || message.Header.Get("From") != from || len(body) == 0 {
		return errors.New("Message was not constructed properly")
	}
	return nil
}

func TestMain(m *testing.M) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	var err error
	triesLeft := 5
	db, err = sql.Open("postgres", "postgres://authentic:authentic@db:5432/authentic?sslmode=disable")

	// Wait for the database to be ready.
	for triesLeft > 0 {
		if tx, err := db.Begin(); err == nil {
			tx.Rollback()
			break
		}
		log.Printf("Database not ready, %d tries left", triesLeft)
		triesLeft--
		time.Sleep(10 * time.Second)
	}
	eh := email.NewSender("House Points Test", "smtp.test.com", "587", "email@test.com", "tEsTPaSsWoRd")
	eh.SendMail = SendMail
	a, err = DefaultHTTPAuth(db, "users", "www.test.com", false, eh, 2*time.Second, 3*time.Second, 2*time.Second, 2*time.Second, 10, bytes.Repeat([]byte("d"), 16))
	if err != nil {
		log.Panic(err)
	}
	a.PasswordResetEmailTemplate = template.Must(template.ParseFiles("templates/passwordreset.tmpl.html"))
	a.SignUpEmailTemplate = template.Must(template.ParseFiles("templates/signup.tmpl.html"))
	testHand = testHandler{}
	log.Println("Running test suite now")
	exitCode := m.Run()
	// Wait a little bit for the sessions to be removed
	time.Sleep(time.Second * 2)
	os.Exit(exitCode)
}

func catchTxError(tx *sql.Tx, t *testing.T, errorExpected bool) {
	if r := recover(); r != nil {
		log.Println(r)
		tx.Rollback()
		if !errorExpected {
			t.Error(r)
		}
	} else {
		tx.Commit()
		if errorExpected {
			t.Error("Error was expected, but not was created")
		}
	}
}
