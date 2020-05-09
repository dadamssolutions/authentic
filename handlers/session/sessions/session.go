/*
Package sessions contains a Session type used to track session cookies in HTTP responses.

Each session will have a unique selector and session ID, be attached to a single user account,
and can be persistent or session only.

This package should be not be uses without seshandler which manages sessions for a server.
*/
package sessions

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	errorKey = "errors"
	msgKey   = "messages"
)

// Session type represents an HTTP session.
type Session struct {
	cookie            *http.Cookie
	selectorID        string
	sessionID         string
	encryptedUsername string
	persistent        bool
	destroyed         bool
	values            map[string][]interface{}

	lock *sync.RWMutex
}

// NewSession creates a new session with the given information
func NewSession(selectorID, sessionID, username, encryptedUsername, sessionCookieName string, maxLifetime time.Duration) *Session {
	s := &Session{selectorID: selectorID, sessionID: sessionID, encryptedUsername: encryptedUsername, values: make(map[string][]interface{}), lock: &sync.RWMutex{}}
	c := &http.Cookie{Name: sessionCookieName, Value: s.CookieValue(), Path: "/", HttpOnly: true, Secure: true, MaxAge: int(maxLifetime.Seconds())}
	s.cookie = c
	s.values["username"] = []interface{}{username}
	s.values["errors"] = make([]interface{}, 0)
	s.values["messages"] = make([]interface{}, 0)
	if maxLifetime != 0 {
		c.Expires = time.Now().Add(maxLifetime)
		s.persistent = true
	}
	return s
}

// SessionCookie builds a cookie from the Session struct
func (s *Session) SessionCookie() *http.Cookie {
	s.lock.RLock()
	defer s.lock.RUnlock()
	if !s.IsValid() {
		return nil
	}
	s.cookie.Value = s.CookieValue()
	return s.cookie
}

// CookieValue returns the value of the cookie to send with the response
func (s *Session) CookieValue() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return url.QueryEscape(s.selectorID + "|" + s.encryptedUsername + "|" + s.sessionID)
}

// HashPayload returns the string related to the session to be hashed.
func (s *Session) HashPayload() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.values["username"][0].(string) + s.sessionID
}

// SelectorID returns the session's selector ID
func (s *Session) SelectorID() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.selectorID
}

// SessionID returns the session's session ID
func (s *Session) SessionID() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.sessionID
}

// Username returns the username of the account to which the session is associated.
func (s *Session) Username() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.values["username"][0].(string)
}

// EncryptedUsername returns the username of the account to which the session is associated.
func (s *Session) EncryptedUsername() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.encryptedUsername
}

// ExpireTime returns the time that the session will expire.
func (s *Session) ExpireTime() time.Time {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.cookie.Expires
}

// IsExpired returns whether the session is expired.
func (s *Session) IsExpired() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.IsPersistent() && s.cookie.Expires.Before(time.Now())
}

// IsPersistent returns whether the session is a persistent one.
func (s *Session) IsPersistent() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.persistent
}

// MarkSessionExpired marks the session expired.
func (s *Session) MarkSessionExpired() {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.cookie.Expires = time.Now().Add(-1 * time.Second)
}

// UpdateExpireTime updates the time that the session expires
func (s *Session) UpdateExpireTime(maxLifetime time.Duration) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.cookie.Expires = time.Now().Add(maxLifetime)
}

// Destroy destroys a session.
func (s *Session) Destroy() {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.destroyed = true
}

// IsDestroyed returns whether the session has been destroyed
func (s *Session) IsDestroyed() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.destroyed
}

// IsValid returns whether the session is valid
// A session is valid if it is neither destroyed nor expired.
func (s *Session) IsValid() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return !s.IsDestroyed() && !s.IsExpired()
}

// IsUserLoggedIn returns true if the user is logged in
func (s *Session) IsUserLoggedIn() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.values["username"][0] != "" && s.encryptedUsername != ""
}

// LogUserIn logs a user into a session.
// It returns a non-nil error if there is already a user logged into that session.
func (s *Session) LogUserIn(username, encryptedUsername string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.values["username"][0] != "" && s.values["username"][0] != username {
		return errors.New("Trying to log a user into a session that already has a user")
	}
	s.values["username"][0] = username
	s.encryptedUsername = encryptedUsername
	return nil
}

// LogUserOut logs a user out of a session.
func (s *Session) LogUserOut() {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.values["username"][0] = ""
	s.encryptedUsername = ""
	s.persistent = false
}

// Equals returns whether other session is equal to this session
func (s *Session) Equals(other *Session, hash func(string) string) bool {
	s.lock.RLock()
	other.lock.RLock()
	defer s.lock.RUnlock()
	defer other.lock.RUnlock()
	return s.SelectorID() == other.SelectorID() && s.Username() == other.Username() && s.SessionID() == other.SessionID() && s.IsDestroyed() == other.IsDestroyed() && s.IsPersistent() == other.IsPersistent() && hash(s.HashPayload()) == hash(other.HashPayload())
}

// AddError adds an error to the session flashes
func (s *Session) AddError(err ...interface{}) {
	s.addToFlashes(errorKey, err...)
}

// AddMessage adds an error to the session flashes
func (s *Session) AddMessage(msg ...interface{}) {
	s.addToFlashes(msgKey, msg...)
}

// Flashes gets and deletes the flash messages.
func (s *Session) Flashes() ([]interface{}, []interface{}) {
	s.lock.Lock()
	defer s.lock.Unlock()
	defer func() {
		s.values[errorKey] = s.values[errorKey][:0]
		s.values[msgKey] = s.values[msgKey][:0]
	}()
	return s.values[msgKey], s.values[errorKey]
}

// ValuesAsText converts the values into text for storage in a database.
func (s *Session) ValuesAsText() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	b, err := json.Marshal(s.values)
	if err != nil {
		log.Println(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// TextToValues converts the string to a values map for the session.
// It returns an error if the string cannot be converted.
func (s *Session) TextToValues(text string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	textBytes, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		return errors.New("Cannot convert text to values for session")
	}
	err = json.Unmarshal(textBytes, &s.values)
	if err != nil {
		return errors.New("Cannot convert text to values for session")
	}
	return nil
}

func (s *Session) addToFlashes(key string, val ...interface{}) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.values[key] = append(s.values[key], val...)
}
