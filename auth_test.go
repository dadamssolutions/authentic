package authentic

import (
	"bytes"
	"context"
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

	"github.com/dadamssolutions/authentic/authdb"
	"github.com/dadamssolutions/authentic/handlers/email"
	"github.com/dadamssolutions/authentic/handlers/session"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
)

var a *HTTPAuth
var testHand testHandler
var db *pgxpool.Pool
var ctx context.Context

func checkRedirect(req *http.Request, via []*http.Request) error {
	return fmt.Errorf("Redirected to %v", req.URL)
}

type testHandler struct{}

func (t testHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := ErrorFromContext(r.Context())
	if err != nil {
		log.Println(err)
	}
	w.Write([]byte("Test handler"))
}

func addTestUserToDatabase(role int, validated bool) error {
	// Add user to the database for testing
	pass := strings.Repeat("d", 64)
	passHash, _ := a.GenerateHashFromPassword([]byte(pass))
	tx, _ := db.Begin(ctx)
	_, err := tx.Exec(ctx, fmt.Sprintf("INSERT INTO %v (username, email, pass_hash, role, validated) VALUES ('dadams', 'test@gmail.com', '%v', %v, %v);", "users", base64.RawURLEncoding.EncodeToString(passHash), role, validated))
	if err != nil {
		tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

func removeTestUserFromDatabase() {
	// Remove user from database
	tx, _ := db.Begin(ctx)
	tx.Exec(ctx, "DELETE FROM sessions WHERE user_id = 'dadams';")
	tx.Exec(ctx, "DELETE FROM csrfs WHERE user_id = 'dadams';")
	tx.Exec(ctx, fmt.Sprintf("DELETE FROM %v WHERE username = 'dadams';", "users"))
	tx.Commit(ctx)
}

func TestUserNotLoggedInHandler(t *testing.T) {
	ts := httptest.NewTLSServer(a.MustHaveAdapters(ctx, db, a.RedirectIfUserNotAuthenticated())(testHand))
	defer ts.Close()

	client := ts.Client()
	client.CheckRedirect = checkRedirect
	resp, err := client.Get(ts.URL)
	if err == nil || resp.StatusCode != http.StatusSeeOther || len(resp.Cookies()) == 0 {
		log.Println(err)
		log.Println(resp.Status)
		log.Println(len(resp.Cookies()))
		t.Error("Not redirected when user is not logged in")
	}
	resp.Body.Close()
}

func TestUserLoggedInHandler(t *testing.T) {
	ts := httptest.NewTLSServer(a.MustHaveAdapters(ctx, db, a.RedirectIfUserNotAuthenticated())(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)

	tx, _ := db.Begin(ctx)
	c := session.NewTxContext(ctx, tx)
	defer catchTxError(ctx, tx, t, false)
	// Create the user logged in session
	ses := a.sesHandler.CreateSession(c, "dadams", true)
	req.AddCookie(ses.SessionCookie())
	tx.Commit(ctx)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
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
	err := addTestUserToDatabase(authdb.Member, true)
	if err != nil {
		t.Error(err)
	}
	ts := httptest.NewTLSServer(a.MustHaveAdapters(ctx, db, a.RedirectIfNoPermission(0))(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)

	tx, _ := db.Begin(ctx)
	c := session.NewTxContext(ctx, tx)
	// Create the user logged in session
	ses := a.sesHandler.CreateSession(c, "dadams", true)
	req.AddCookie(ses.SessionCookie())
	req = req.WithContext(c)
	user := a.CurrentUser(req)
	tx.Commit(ctx)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Error("Redirected, but user has permission")
	}
	resp.Body.Close()

	user.Role = authdb.Admin
	req, _ = http.NewRequest(http.MethodGet, ts.URL, nil)

	tx, _ = db.Begin(ctx)
	c = session.NewTxContext(ctx, tx)
	// Create the user logged in session
	ses = a.sesHandler.CreateSession(c, "dadams", true)
	req.AddCookie(ses.SessionCookie())
	tx.Commit(ctx)

	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Error("Redirected, but user has permission")
	}
	resp.Body.Close()

	removeTestUserFromDatabase()
}

func TestUserDoesNotHaveRole(t *testing.T) {
	err := addTestUserToDatabase(authdb.Member, true)
	if err != nil {
		t.Error(err)
	}
	ts := httptest.NewTLSServer(a.MustHaveAdapters(ctx, db, a.RedirectIfNoPermission(2))(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)

	tx, _ := db.Begin(ctx)
	c := session.NewTxContext(ctx, tx)
	// Create the user logged in session
	ses := a.sesHandler.CreateSession(c, "dadams", true)
	req.AddCookie(ses.SessionCookie())
	req = req.WithContext(c)
	user := a.CurrentUser(req)
	tx.Commit(ctx)

	resp, err := client.Do(req)
	if err == nil || resp.StatusCode != http.StatusSeeOther {
		t.Error("Not redirected when user does not have permission")
	}
	resp.Body.Close()

	user.Role = authdb.Manager
	req, _ = http.NewRequest(http.MethodGet, ts.URL, nil)

	tx, _ = db.Begin(ctx)
	c = session.NewTxContext(ctx, tx)
	// Create the user logged in session
	ses = a.sesHandler.CreateSession(c, "dadams", true)
	req.AddCookie(ses.SessionCookie())
	tx.Commit(ctx)

	resp, err = client.Do(req)
	if err == nil || resp.StatusCode != http.StatusSeeOther {
		t.Error("Not redirected when user does not have permission")
	}
	resp.Body.Close()

	removeTestUserFromDatabase()
}

func TestCurrentUserBadCookie(t *testing.T) {
	err := addTestUserToDatabase(authdb.Member, true)
	if err != nil {
		t.Error(err)
	}

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	tx, _ := db.Begin(ctx)
	c := session.NewTxContext(req.Context(), tx)
	req = req.WithContext(c)

	if a.CurrentUser(req) != nil {
		t.Error("No cookie in request should return empty string")
	}
	tx.Commit(ctx)

	tx, _ = db.Begin(ctx)
	c = session.NewTxContext(req.Context(), tx)
	// Create the user logged in session
	ses := a.sesHandler.CreateSession(c, "dadams", true)
	req.AddCookie(ses.SessionCookie())
	a.sesHandler.DestroySession(c, ses)

	if a.CurrentUser(req) != nil {
		t.Error("Destroyed cookie in request should return empty string")
	}
	tx.Commit(ctx)

	removeTestUserFromDatabase()
}

func TestCurrentUserGoodCookie(t *testing.T) {
	err := addTestUserToDatabase(authdb.Member, true)
	if err != nil {
		t.Error(err)
	}

	tx, _ := db.Begin(ctx)
	c := session.NewTxContext(ctx, tx)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(c)

	// Create the user logged in session
	ses := a.sesHandler.CreateSession(c, "dadams", true)
	req.AddCookie(ses.SessionCookie())

	if a.CurrentUser(req).Username != "dadams" {
		t.Error("Valid cookie in request should return correct user")
	}
	tx.Commit(ctx)

	removeTestUserFromDatabase()
}

func TestCurrentUserFromContext(t *testing.T) {
	err := addTestUserToDatabase(authdb.Member, true)
	if err != nil {
		t.Error(err)
	}

	user := &authdb.User{FirstName: "Donnie", LastName: "Adams", Username: "dadams", Email: "test%40gmail.com"}

	tx, _ := db.Begin(ctx)
	c := session.NewTxContext(ctx, tx)
	ses := a.sesHandler.CreateSession(c, user.Username, false)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(NewUserContext(c, user))

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
	tx.Commit(ctx)

	removeTestUserFromDatabase()
}

func TestIsCurrentUser(t *testing.T) {
	err := addTestUserToDatabase(authdb.Member, true)
	if err != nil {
		t.Error(err)
	}
	tx, _ := db.Begin(ctx)
	c := session.NewTxContext(ctx, tx)

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(c)

	// Create the user logged in session
	ses := a.sesHandler.CreateSession(c, "dadams", true)
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

	a.sesHandler.DestroySession(c, ses)
	if a.IsCurrentUser(req, "dadams") {
		t.Error("Current user should not be dadams with destroyed cookie")
	}
	tx.Commit(ctx)

	removeTestUserFromDatabase()
}

func TestGetUserNotInDatabase(t *testing.T) {
	var u *authdb.User
	tx, _ := db.Begin(ctx)
	u = a.conn.GetUserFromDB(session.NewTxContext(context.Background(), tx), "username", "nadams")
	if u != nil {
		t.Error("User not in database returned as valid")
	}
}

func TestGetUserInDatabasePasswordHash(t *testing.T) {
	err := addTestUserToDatabase(authdb.Member, true)
	if err != nil {
		t.Error(err)
	}
	tx, _ := db.Begin(ctx)

	u := a.conn.GetUserFromDB(session.NewTxContext(context.Background(), tx), "username", "dadams")
	u.VerifyPassword([]byte(strings.Repeat("d", 64)), a.CompareHashAndPassword)
	if u == nil {
		log.Println(u)
		t.Error("User in database returned as invalid")
	}
	tx.Commit(ctx)

	removeTestUserFromDatabase()
}

func TestUpdateUserLastAccess(t *testing.T) {
	err := addTestUserToDatabase(authdb.Member, true)
	if err != nil {
		t.Error(err)
	}
	epoch, _ := time.Parse("2006-01-02 15:04:05", "1970-01-01 00:00:00")

	tx, _ := db.Begin(ctx)
	c := session.NewTxContext(ctx, tx)
	updateTime := a.conn.GetUserLastAccess(c, "dadams")
	if !updateTime.Equal(epoch) {
		t.Error("User should be created with epoch time as last access time")
	}

	now := time.Now()
	a.conn.UpdateUserLastAccess(c, "dadams")
	updateTime = a.conn.GetUserLastAccess(c, "dadams")
	if updateTime.Equal(now) {
		t.Error("User access time not updated")
	}
	tx.Commit(ctx)
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
	ctx = context.Background()
	triesLeft := 10
	db, err = pgxpool.Connect(context.Background(), "postgres://authentic:authentic@db:5432/authentic?sslmode=disable")

	// Wait for the database to be ready.
	for triesLeft > 0 {
		if tx, err := db.Begin(ctx); err == nil {
			tx.Rollback(ctx)
			break
		}
		log.Printf("Database not ready, %d tries left", triesLeft)
		triesLeft--
		time.Sleep(5 * time.Second)
	}
	eh := email.NewSender("House Points Test", "smtp.test.com", "587", "email@test.com", "tEsTPaSsWoRd")
	eh.SendMail = SendMail
	conn, _ := authdb.NewConn(ctx, db, "users")
	a, err = DefaultHTTPAuth(ctx, db, conn, "www.test.com", false, eh, 2*time.Second, 3*time.Second, 2*time.Second, 2*time.Second, 10, bytes.Repeat([]byte("d"), 16))
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

func catchTxError(ctx context.Context, tx pgx.Tx, t *testing.T, errorExpected bool) {
	if r := recover(); r != nil {
		log.Println(r)
		tx.Rollback(ctx)
		if !errorExpected {
			t.Error(r)
		}
	} else {
		tx.Commit(ctx)
		if errorExpected {
			t.Error("Error was expected, but not was created")
		}
	}
}
