package session

import (
	"database/sql"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dadamssolutions/authentic8/handlers/session/sessions"
	_ "github.com/lib/pq"
)

var timeout = time.Minute
var db, err = sql.Open("postgres", "postgres://authentic8:authentic8@db:5432/authentic8_session?sslmode=disable")
var da sesDataAccess
var sh *Handler

func TestBadDatabaseConnectionError(t *testing.T) {
	// Open a bad database to test errors
	dbt, err := sql.Open("postgres", "user=test dbname=")

	_, err = newDataAccess(dbt, "sessions", sh.dataAccess.cookieName, nil, timeout, timeout)
	if err == nil {
		t.Error(err)
	}

	_, err = NewHandlerWithDB(dbt, "sessions", "sessionID", timeout, timeout, nil)
	if err == nil {
		t.Error(err)
	}
}

func TestIDGenerators(t *testing.T) {
	id := sh.dataAccess.generateSelectorID()
	if len(id) != selectorIDLength {
		t.Errorf("Selector ID is not of the expected length. %v != %v", len(id), selectorIDLength)
	}

	id = sh.dataAccess.generateSessionID()
	if len(id) != sessionIDLength {
		t.Errorf("Session ID is not of the expected length. %v != %v", len(id), sessionIDLength)
	}
}

func TestBadDatabaseConnection(t *testing.T) {
	sh := newHandler(sesDataAccess{}, timeout)
	if sh == nil {
		t.Error("Session handler should always be returned by unexported newSesHandler")
	}
}

func TestNegativeTimeoutSesCreation(t *testing.T) {
	sh1, err := NewHandlerWithDB(db, "sessions", "sessionID", timeout, -timeout, nil)
	if err != nil {
		log.Println(err)
		t.Error("We should not have an error with negative timeout")
	}
	if sh1.maxLifetime != 0 {
		t.Error("A negative timeout should produce a 0 maxLifetime")
	}
}

func TestUpdateExpiredTime(t *testing.T) {
	tx, _ := db.Begin()
	// We should get an update to expiration time.
	ses := sh.CreateSession(tx, "dadams", true)
	now := time.Now().Add(sh.maxLifetime)
	time.Sleep(time.Microsecond * 2)
	err := sh.UpdateSessionIfValid(tx, ses)
	if err != nil || ses.ExpireTime().Before(now) {
		log.Println(err)
		t.Error("Session expiration not updated.")
	}
	tx.Commit()

	tx, _ = db.Begin()
	// Now we should not get an update to expiration time.
	sesNotInDatabase := sessions.NewSession("", "", "", "", "", time.Microsecond)
	nowt := time.Now().Add(sh.maxLifetime)

	time.Sleep(time.Millisecond)

	err = sh.UpdateSessionIfValid(tx, sesNotInDatabase)
	if err == nil || nowt.Before(sesNotInDatabase.ExpireTime()) {
		t.Error("Session expiration update unexpected")
	}
	tx.Commit()
}

func TestUpdateToNonPersisantShouldCreateNewSession(t *testing.T) {
	tx, _ := db.Begin()
	ses := sh.CreateSession(tx, "username", false)
	selector, session := ses.SelectorID(), ses.SessionID()
	err := sh.UpdateSessionIfValid(tx, ses)
	if err != nil || ses.SelectorID() == selector || ses.SessionID() == session || ses.IsDestroyed() {
		t.Error("Non-persistent session should be destroyed and re-created on update")
	}
	tx.Commit()
}

func TestCreateSession(t *testing.T) {
	tx, _ := db.Begin()
	ses := sh.CreateSession(tx, "thedadams", true)
	if ses == nil || !ses.IsValid() || !ses.IsPersistent() {
		t.Error("Session not created properly")
	}

	ses = sh.CreateSession(tx, "thedadams", false)
	if ses == nil || !ses.IsValid() || ses.IsPersistent() {
		t.Error("Session not created properly")
	}
	tx.Commit()
}

func TestSessionNotValidForEncryptionReasons(t *testing.T) {
	tx, _ := db.Begin()
	ses := sh.CreateSession(tx, "thedadams", true)
	if ses == nil || !ses.IsValid() || !ses.IsPersistent() {
		t.Error("Session not created properly")
	}

	if !sh.isValidSession(tx, ses) {
		t.Error("Session where username and encrypted username match should be valid")
	}

	newSession := sessions.NewSession(ses.SelectorID(), ses.SessionID(), ses.Username(), ses.Username(), sh.dataAccess.cookieName, sh.maxLifetime)

	if sh.isValidSession(tx, newSession) {
		t.Error("Session where username and encrypted username don't match should be invalid")
	}

	sh.DestroySession(tx, ses)
	tx.Commit()
}

func TestSessionValidityWithLongUsername(t *testing.T) {
	tx, _ := db.Begin()
	ses := sh.CreateSession(tx, "thedadamsthedadams", true)
	if ses == nil || !ses.IsValid() || !ses.IsPersistent() {
		t.Error("Session not created properly")
	}

	if !sh.isValidSession(tx, ses) {
		t.Error("Session where username and encrypted username match should be valid")
	}

	sh.DestroySession(tx, ses)
	tx.Commit()
}

func TestDestroySession(t *testing.T) {
	tx, _ := db.Begin()
	// We put the session in the database so it is destroyed
	ses := sh.CreateSession(tx, "anyone", true)
	sh.DestroySession(tx, ses)
	if ses.IsValid() {
		t.Error("Session not destroyed.")
	}

	// Session is not in the database and should be destroyed
	sessionNotInDatabase := sessions.NewSession(strings.Repeat("a", selectorIDLength), strings.Repeat("a", sessionIDLength), "", "nadams", sh.dataAccess.cookieName, sh.maxLifetime)
	sh.DestroySession(tx, sessionNotInDatabase)
	if sessionNotInDatabase.IsValid() {
		t.Error("Session not destroyed.")
	}
	tx.Commit()
}

func TestParseSessionFromRequest(t *testing.T) {
	tx, _ := db.Begin()
	ses := sh.CreateSession(tx, "dadams", true)
	r, _ := http.NewRequest("GET", "/", nil)
	r = r.WithContext(NewTxContext(r.Context(), tx))
	sesTest, err := sh.ParseSessionFromRequest(r)
	if err == nil || sesTest != nil {
		t.Error("Cookie was parsed where none exists")
	}

	r.AddCookie(ses.SessionCookie())
	sesTest, err = sh.ParseSessionFromRequest(r)
	if err != nil || !sesTest.Equals(ses, sh.dataAccess.hashString) {
		log.Println(err)
		t.Error("Cookie not parsed properly from request")
	}
	tx.Commit()
}

func TestParsedSessionOfInvalidCookie(t *testing.T) {
	tx, _ := db.Begin()
	ses := sh.CreateSession(tx, "dadams", true)
	r, _ := http.NewRequest("GET", "/", nil)
	r.AddCookie(ses.SessionCookie())
	sh.DestroySession(tx, ses)
	r = r.WithContext(NewTxContext(r.Context(), tx))

	sesTest, err := sh.ParseSessionFromRequest(r)
	if err == nil || sesTest != nil {
		t.Error("Cookie was parsed for destroyed session")
	}
	tx.Commit()
}

func TestSessionParsingFromCookie(t *testing.T) {
	tx, _ := db.Begin()
	ses := sh.CreateSession(tx, "dadams", true)
	sesTest, err := sh.ParseSessionCookie(tx, ses.SessionCookie())

	// Should be a valid cookie
	if err != nil || !ses.Equals(sesTest, sh.dataAccess.hashString) {
		log.Println(err)
		t.Error("Session cookie not parsed properly")
	}
	tx.Commit()
}

func TestSessionParsingNotInDB(t *testing.T) {
	tx, _ := db.Begin()
	sessionNotInDatabase := sessions.NewSession(strings.Repeat("a", selectorIDLength), strings.Repeat("a", sessionIDLength), "", "nadams", sh.dataAccess.cookieName, sh.maxLifetime)
	cookie := sessionNotInDatabase.SessionCookie()

	// The session is not in the database so should be invalid
	sessionNotInDatabase.UpdateExpireTime(time.Second)
	cookie = sessionNotInDatabase.SessionCookie()
	sesTest, err := sh.ParseSessionCookie(tx, cookie)
	if err == nil || sesTest != nil {
		t.Error("Session cookie should be invalid")
	}
	tx.Commit()
}

func TestSessionParsingBadName(t *testing.T) {
	tx, _ := db.Begin()
	// The cookie name is not correct
	sessionNotInDatabase := sessions.NewSession(strings.Repeat("d", selectorIDLength), strings.Repeat("d", sessionIDLength), "", "thedadams", "something else", timeout)
	sesTest, err := sh.ParseSessionCookie(tx, sessionNotInDatabase.SessionCookie())
	if err == nil || sesTest != nil {
		t.Error("Session cookie should be invalid")
	}
	tx.Commit()
}

func TestParsingCookieDetectsPersistance(t *testing.T) {
	tx, _ := db.Begin()
	sesP := sh.CreateSession(tx, "dadams", true)
	ses := sh.CreateSession(tx, "nadams", false)

	sesPTest, _ := sh.ParseSessionCookie(tx, sesP.SessionCookie())
	if sesPTest == nil || !sesPTest.IsPersistent() {
		t.Error("Persistent cookie parsed as non-persistent")
	}

	sesTest, _ := sh.ParseSessionCookie(tx, ses.SessionCookie())
	if sesTest == nil || sesTest.IsPersistent() {
		t.Error("Non-persistent cookie parsed as persistent")
	}
	tx.Commit()
}

func TestAttachPersistentCookieToResponseWriter(t *testing.T) {
	tx, _ := db.Begin()
	session := sh.CreateSession(tx, "dadams", true)
	w := httptest.NewRecorder()
	err := sh.AttachCookie(tx, w, session)
	resp := w.Result()
	attachedSession, err := sh.ParseSessionCookie(tx, resp.Cookies()[0])
	if err != nil || !session.Equals(attachedSession, sh.dataAccess.hashString) {
		t.Error("Cookie not attached to response writer")
	}

	sh.DestroySession(tx, session)
	w = httptest.NewRecorder()
	err = sh.AttachCookie(tx, w, session)
	if err == nil || session.Equals(attachedSession, sh.dataAccess.hashString) {
		t.Error("Invalid cookie attached to response writer")
	}
	tx.Commit()
}

func TestAttachSessionOnlyCookieToResponseWriter(t *testing.T) {
	tx, _ := db.Begin()
	session := sh.CreateSession(tx, "dadams", false)
	w := httptest.NewRecorder()
	err := sh.AttachCookie(tx, w, session)
	resp := w.Result()
	attachedSession, err := sh.ParseSessionCookie(tx, resp.Cookies()[0])
	if err != nil || !session.Equals(attachedSession, sh.dataAccess.hashString) {
		t.Error("Cookie not attached to response writer")
	}

	sh.DestroySession(tx, session)
	w = httptest.NewRecorder()
	err = sh.AttachCookie(tx, w, session)
	if err == nil || session.Equals(attachedSession, sh.dataAccess.hashString) {
		t.Error("Invalid cookie attached to response writer")
	}
	tx.Commit()
}

func TestValidateUserInputs(t *testing.T) {
	for i := 0; i < 100; i++ {
		ses := sessions.NewSession(sh.dataAccess.generateSelectorID(), sh.dataAccess.generateSessionID(), sh.dataAccess.generateRandomString(12), "", sh.dataAccess.cookieName, 0)
		if !sh.validateUserInputs(ses) {
			t.Error("Session should have IDs and username")
		}
	}

	for i := 0; i < 100; i++ {
		ses := sessions.NewSession(sh.dataAccess.generateSelectorID(), sh.dataAccess.generateSessionID(), sh.dataAccess.generateRandomString(12)+" "+sh.dataAccess.generateRandomString(9), "", sh.dataAccess.cookieName, 0)
		if sh.validateUserInputs(ses) {
			log.Println(ses)
			t.Error("Session should NOT have IDs and username")
		}
	}
}

func TestTimeoutOfNonPersistentCookies(t *testing.T) {
	tx, _ := db.Begin()
	sh, _ := NewHandlerWithDB(db, "sessions", "sessionID", 500*time.Millisecond, time.Second, nil)
	ses := sh.CreateSession(tx, "nadams", false)
	tx.Commit()
	time.Sleep(time.Millisecond * 25) // Wait for a short time

	tx, _ = db.Begin()
	err := sh.UpdateSessionIfValid(tx, ses)
	if err != nil || ses.IsDestroyed() {
		t.Error("Non-persistent session should not be destroyed yet")
	}
	tx.Commit()

	time.Sleep(time.Millisecond * 500) // Wait for clean-up to fire

	tx, _ = db.Begin()
	// ses should not be destroyed
	if !sh.isValidSession(tx, ses) {
		t.Error("Non-persistent session should not be destroyed yet")
	}
	tx.Commit()

	time.Sleep(time.Millisecond * 500) // Wait for clean-up to fire

	tx, _ = db.Begin()

	// ses should now be destroyed
	if sh.isValidSession(tx, ses) || !ses.IsDestroyed() {
		t.Errorf("Non-persistent session %v should now be destroyed", ses.SelectorID())
	}
	tx.Commit()
}

func TestTimeoutOfPersistentCookies(t *testing.T) {
	tx, _ := db.Begin()
	sh, _ := NewHandlerWithDB(db, "sessions", "sessionID", 500*time.Millisecond, time.Second, nil)
	ses := sh.CreateSession(tx, "dadams", true)
	tx.Commit()
	time.Sleep(time.Millisecond * 500) // Wait for clean-up to fire

	tx, _ = db.Begin()
	// Now ses should be in the database.
	if !sh.isValidSession(tx, ses) {
		t.Error("A persistent session should be valid")
	}
	tx.Commit()

	time.Sleep(time.Second)

	tx, _ = db.Begin()
	// Now ses1 should be destroyed
	if sh.isValidSession(tx, ses) {
		t.Error("A persistent session should now be invalid")
	}
	tx.Commit()
}

func TestReadFlashes(t *testing.T) {
	tx, _ := db.Begin()
	ses := sh.CreateSession(tx, "dadams", false)
	ses.AddError("Error1")
	ses.AddMessage("Message1")
	ses.AddMessage("Message2")

	msgs, errs := sh.ReadFlashes(tx, ses)
	if len(msgs) != 2 || len(errs) != 1 {
		t.Error("Messages or errors not returned properly")
	}

	ses1, _ := sh.ParseSessionCookie(tx, ses.SessionCookie())

	msgs, errs = ses1.Flashes()
	if len(msgs) != 0 || len(errs) != 0 {
		t.Error("Flashes should be empty after reading.")
	}
	tx.Commit()
}

func TestLogUserIn(t *testing.T) {
	tx, _ := db.Begin()
	session := sh.CreateSession(tx, "", false)
	sh.LogUserIn(tx, session, "dadams")

	if !session.IsUserLoggedIn() || session.Username() != "dadams" {
		t.Error("User not logged into session")
	}

	sh.LogUserOut(tx, session)

	if session.IsUserLoggedIn() || session.Username() != "" {
		t.Error("User not logged out of session")
	}
	tx.Commit()
}
func TestMain(m *testing.M) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	triesLeft := 5

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
	if err != nil {
		log.Fatal(err)
	}
	sh, err = NewHandlerWithDB(db, "sessions", "sessionID", timeout, timeout, nil)
	if err != nil {
		log.Fatal(err)
	}
	num := m.Run()
	err = sh.dataAccess.dropTable(db)
	if err != nil {
		log.Fatal(err)
	}
	// The second time we drop the table, it should fail.
	err = sh.dataAccess.dropTable(db)
	if err == nil {
		log.Fatal("We shouldn't be able to drop the table twice.")
	}
	os.Exit(num)
}
