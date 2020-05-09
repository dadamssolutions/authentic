/*
Package session uses a database backend to manage session cookies for a server. A seshandler can manage persistent and session only cookies simultaneously.

Once a database connection is established, one can create a seshandler with something like:
	sh, err := seshandler.NewSesHandlerWithDB(db, time.Minute * 20, time.Day)

One can create a new (persistent) session with:
	session, err := sh.CreateSession("username", true)

The session structs themselves should not be acted upon independently. Instead the sessions should be passed to the handler:
	err = sh.DestroySession(session)
This will "destroy" the session struct itself and in the database. Once the struct is destroyed, it can be passed to the handler which will detected its destroyed-ness. For security reasons, a destroyed session cannot be un-destoyed.

A selectorID and a sessionID is generated for each session. The selectorID and a hash of the sessionID is stored in the database. The selectorID and sessionID are sent with the response. This is an idea taken from https://paragonie.com/blog/2015/04/secure-authentication-php-with-long-term-persistence#title.2

This package is best used with an authentication handler.
*/
package session

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dadamssolutions/authentic8/handlers/session/sessions"
)

// These are made constants because the database should be cleared and updated if they change.
const (
	selectorIDLength = 16
	sessionIDLength  = 64
)

// Handler creates and maintains session in a database.
type Handler struct {
	dataAccess  sesDataAccess
	maxLifetime time.Duration
}

// NewHandlerWithDB creates a new session handler.
// The database connection should be a pointer to the database connection
// used in the rest of the app for concurrency purposes.
// If either timeout <= 0, then it is set to 0 (session only cookies).
func NewHandlerWithDB(db *sql.DB, tableName, cookieName string, sessionTimeout time.Duration, persistentSessionTimeout time.Duration, secret []byte) (*Handler, error) {
	da, err := newDataAccess(db, tableName, cookieName, secret, sessionTimeout, persistentSessionTimeout)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return newHandler(da, persistentSessionTimeout), nil
}

func newHandler(da sesDataAccess, timeout time.Duration) *Handler {
	if timeout < 0 {
		timeout = 0
	}
	ses := &Handler{dataAccess: da, maxLifetime: timeout}
	return ses
}

// GetTableName returns the table name for this handler.
func (sh *Handler) GetTableName() string {
	return sh.dataAccess.tableName
}

// CreateSession generates a new session for the given user ID.
func (sh *Handler) CreateSession(tx *sql.Tx, username string, persistent bool) *sessions.Session {
	ses := sh.dataAccess.createSession(tx, username, sh.maxLifetime, persistent)
	return ses
}

// DestroySession gets rid of a session, if it exists in the database.
// If destroy is successful, the session pointer is set to nil.
func (sh *Handler) DestroySession(tx *sql.Tx, ses *sessions.Session) {
	sh.dataAccess.destroySession(tx, ses)
}

// isValidSession determines if the given session is valid.
func (sh *Handler) isValidSession(tx *sql.Tx, ses *sessions.Session) bool {
	// First we check that the inputs have not been tampered with
	if ses != nil && sh.validateUserInputs(ses) {
		// The we check the session against the session in the database
		if err := sh.dataAccess.validateSession(tx, ses, sh.maxLifetime); err != nil {
			log.Println(err)
		} else {
			return true
		}
	}
	return false
}

// UpdateSessionIfValid resets the expiration of the session from time.Now.
// Should also be used to verify that a session is valid.
// If the session is invalid, then a non-nil error will be returned.
func (sh *Handler) UpdateSessionIfValid(tx *sql.Tx, ses *sessions.Session) error {
	if !sh.isValidSession(tx, ses) {
		log.Println("We were provided an invalid session so we can't update it")
		return invalidSessionError(sh.dataAccess.tableName)
	}
	return sh.updateSession(tx, ses)
}

// ParseSessionFromRequest takes a request, determines if there is a valid session cookie,
// and returns the session, if it exists.
func (sh *Handler) ParseSessionFromRequest(r *http.Request) (*sessions.Session, error) {
	cookie, err := r.Cookie(sh.dataAccess.cookieName)
	// No session cookie available
	if err != nil {
		return nil, noSessionCookieFoundInRequest(sh.dataAccess.tableName)
	}
	tx := TxFromContext(r.Context())
	session, err := sh.ParseSessionCookie(tx, cookie)
	if err != nil {
		log.Println(err)
	}
	return session, err
}

// ParseSessionCookie takes a cookie, determines if it is a valid session cookie,
// and returns the session, if it exists.
func (sh *Handler) ParseSessionCookie(tx *sql.Tx, cookie *http.Cookie) (*sessions.Session, error) {
	// Break the cookie into its parts.
	unescapedCookie, err := url.QueryUnescape(cookie.Value)
	cookieStrings := strings.Split(unescapedCookie, "|")
	if err != nil || cookie.Name != sh.dataAccess.cookieName || len(cookieStrings) != 3 {
		return nil, invalidSessionCookie(sh.dataAccess.tableName)
	}

	selectorID, encryptedUsername, sessionID := cookieStrings[0], cookieStrings[1], cookieStrings[2]
	// Get the info on the session from the database
	dbSession, err := sh.dataAccess.getSessionInfo(tx, selectorID, sessionID, encryptedUsername, sh.maxLifetime)
	if err != nil {
		log.Printf("Database returned an error for selector ID %v\n", selectorID)
		return nil, invalidSessionCookie(sh.dataAccess.tableName)
	}
	// Make sure the session is valid before returning it
	if !sh.isValidSession(tx, dbSession) {
		sh.DestroySession(tx, dbSession)
		return nil, invalidSessionCookie(sh.dataAccess.tableName)
	}
	return dbSession, nil
}

// AttachCookie sets a cookie on a ResponseWriter
// A session is returned because the session may have changed when it is updated
func (sh *Handler) AttachCookie(tx *sql.Tx, w http.ResponseWriter, ses *sessions.Session) error {
	// Need to save the selector incase the call to UpdateSessionIfValid returns an error
	var err error
	var selectorID string
	if ses != nil {
		selectorID = ses.SelectorID()
	}
	err = sh.UpdateSessionIfValid(tx, ses)
	if err != nil {
		log.Printf("Invalid %v with ID %v: no cookie returned", sh.dataAccess.tableName, selectorID)
		return invalidSessionError(sh.dataAccess.tableName)
	}
	// Attach the cookie to the response writer
	http.SetCookie(w, ses.SessionCookie())
	return nil
}

// LogUserIn logs the user into the session and saves the information to the database
func (sh *Handler) LogUserIn(tx *sql.Tx, ses *sessions.Session, username string) {
	sh.dataAccess.logUserIntoSession(tx, ses, username, sh.maxLifetime)
}

// LogUserOut logs the user out of the session and saves the information in the database
func (sh *Handler) LogUserOut(tx *sql.Tx, ses *sessions.Session) {
	sh.dataAccess.logUserOut(tx, ses, sh.maxLifetime)
}

// ReadFlashes allows reading of the flashes from the session and then updates the database.
// This is a shorthand for reading flashes from the session and then calling UpdateSession.
func (sh *Handler) ReadFlashes(tx *sql.Tx, ses *sessions.Session) ([]interface{}, []interface{}) {
	msgs, errs := ses.Flashes()
	sh.dataAccess.updateSession(tx, ses, sh.maxLifetime)
	return msgs, errs
}

// CopySession returns a new session with the values of the parameter session (accept selector and session IDs)
func (sh *Handler) CopySession(tx *sql.Tx, ses *sessions.Session, persistent bool) *sessions.Session {
	newSes := sh.CreateSession(tx, ses.Username(), persistent)
	if newSes == nil {
		return nil
	}
	msgs, errs := ses.Flashes()
	newSes.AddMessage(msgs...)
	newSes.AddError(errs...)
	sh.DestroySession(tx, ses)
	return newSes
}

func (sh *Handler) updateSession(tx *sql.Tx, ses *sessions.Session) error {
	// If the session is persistent, then we reset the expiration from time.Now
	if !ses.IsPersistent() {
		// If the session is not persistent, then it should be destroyed
		// and another one created in its place.
		newerSession := sh.CopySession(tx, ses, ses.IsPersistent())
		if newerSession == nil {
			return errors.New("Could not copy session to new session")
		}
		*ses = *newerSession
	}
	sh.dataAccess.updateSession(tx, ses, sh.maxLifetime)
	return nil
}

func (sh *Handler) validateUserInputs(ses *sessions.Session) bool {
	// Escaping these should not change them.
	// If it does, then we know the session has been altered.
	s1 := url.QueryEscape(ses.SelectorID())
	s2 := url.QueryEscape(ses.Username())
	s3 := url.QueryEscape(ses.SessionID())
	if s1 != ses.SelectorID() || s2 != ses.Username() || s3 != ses.SessionID() {
		log.Printf("The %v has invalid pieces. The user must have altered them: ", sh.dataAccess.tableName)
		log.Println(ses.SelectorID())
		return false
	}
	return true
}
