package sessions

import (
	"crypto/sha256"
	"encoding/base64"
	"log"
	"net/url"
	"strings"
	"testing"
	"time"
)

var timeout = time.Minute
var sessionCookieName = "sessionID"
var selectorIDLength = 16
var sessionIDLength = 64

func hash(s string) string {
	hashBytes := sha256.Sum256([]byte(s))
	return url.QueryEscape(base64.RawURLEncoding.EncodeToString(hashBytes[:]))
}

func TestHashPayload(t *testing.T) {
	ses := NewSession(strings.Repeat("A", 16), strings.Repeat("B", 64), strings.Repeat("C", 12), strings.Repeat("D", 12), "sessionID", time.Second)
	if len(ses.HashPayload()) != 76 {
		t.Error("Hash payload is not the correct length")
	}

	if ses.HashPayload()[:12] != strings.Repeat("C", 12) {
		t.Error("Hash payload does not start with the username")
	}

	if ses.HashPayload()[12:] != strings.Repeat("B", 64) {
		t.Error("Hash payload does not end with the sessionID")
	}
}

func TestGetters(t *testing.T) {
	ses := NewSession(strings.Repeat("A", 16), strings.Repeat("B", 64), strings.Repeat("C", 12), strings.Repeat("D", 12), "sessionID", time.Second)

	if ses.SelectorID() != strings.Repeat("A", 16) {
		t.Error("Selector ID not returned correctly")
	}

	if ses.SessionID() != strings.Repeat("B", 64) {
		t.Error("Session ID not returned correctly")
	}

	if ses.Username() != strings.Repeat("C", 12) {
		t.Error("Username not returned correctly")
	}

	if ses.EncryptedUsername() != strings.Repeat("D", 12) {
		t.Error("Encrypted username not returned correctly")
	}
}

func TestSessionEquality(t *testing.T) {
	ses1 := NewSession(strings.Repeat("A", 16), strings.Repeat("B", 64), strings.Repeat("C", 12), strings.Repeat("D", 12), "sessionID", time.Second)

	ses2 := NewSession(strings.Repeat("A", 16), strings.Repeat("B", 64), strings.Repeat("C", 12), strings.Repeat("D", 12), "sessionID", time.Second)

	if !ses1.Equals(ses2, hash) {
		t.Error("Equal sessions not identified as so")
	}

	ses1.persistent = false
	if ses1.Equals(ses2, hash) {
		t.Error("Non-persisant and persistent sessions identified as equal")
	}
	ses1.persistent = true

	ses1.Destroy()
	if ses1.Equals(ses2, hash) {
		t.Error("Destroyed and active sessions identified as equal")
	}
	ses2.Destroy()

	// All other attributes are obvious as well.
}

func TestSessionOnlyCookieCreate(t *testing.T) {
	ses := NewSession("", "", "", "", sessionCookieName, 0)
	cookie := ses.SessionCookie()

	if cookie == nil || cookie.MaxAge != 0 || !cookie.Expires.IsZero() {
		t.Error("Cookie will not expire after session terminated")
	}
}

func TestExpiredSession(t *testing.T) {
	ses := NewSession("", "", "", "", sessionCookieName, timeout)
	if ses.IsExpired() {
		t.Error("Session should not be expired")
	}
	ses.MarkSessionExpired()
	if !ses.IsExpired() {
		t.Error("Session should be expired")
	}
}

func TestUpdateSessionExpiredTime(t *testing.T) {
	ses := NewSession("", "", "", "", sessionCookieName, timeout)
	firstTime := time.Now().Add(timeout)
	time.Sleep(time.Microsecond)
	ses.UpdateExpireTime(timeout)

	if ses.ExpireTime().Before(firstTime) {
		t.Error("Expired time not updated properly")
	}
}

func TestAddFlashes(t *testing.T) {
	ses := NewSession("", "", "", "", sessionCookieName, timeout)
	ses.AddError("Error")
	ses.AddMessage("Message")

	if ses.values[errorKey][0] != "Error" || ses.values[msgKey][0] != "Message" {
		t.Error("Flash messages are not correct")
	}

	ses.AddError("Error2")
	if len(ses.values[errorKey]) != 2 || ses.values[errorKey][1] != "Error2" {
		t.Error("Second error not added properly")
	}
}

func TestReadFlashes(t *testing.T) {
	ses := NewSession("", "", "", "", sessionCookieName, timeout)
	ses.AddError("Error")
	ses.AddMessage("Message")
	ses.AddError("Error2")

	msgs, errs := ses.Flashes()
	if len(ses.values[msgKey]) != 0 || len(ses.values[errorKey]) != 0 || len(errs) != 2 || len(msgs) != 1 || errs[1] != "Error2" || msgs[0] != "Message" {
		t.Error("Flashes not returned and removed")
	}
}

func TestLogUserIn(t *testing.T) {
	ses := NewSession("", "", "", "", sessionCookieName, timeout)
	if ses.IsUserLoggedIn() {
		t.Error("A user should not be logged in for a session created with no username")
	}

	err := ses.LogUserIn("dadams", "dadams")
	if err != nil || !ses.IsUserLoggedIn() {
		log.Println(err)
		log.Println(ses.Username())
		t.Error("A user should be logged in after call")
	}

	ses.LogUserOut()
	if ses.IsUserLoggedIn() {
		t.Error("A user should not be logged in after log out call")
	}
}

func TestSessionCookie(t *testing.T) {
	ses := NewSession(strings.Repeat("d", selectorIDLength), strings.Repeat("d", sessionIDLength), strings.Repeat("d", 12), "thedadams", sessionCookieName, timeout)
	cookie := ses.SessionCookie()
	// Should have a valid cookie
	if cookie == nil || cookie.Name != sessionCookieName || cookie.Value != ses.CookieValue() || !ses.ExpireTime().Equal(cookie.Expires) || cookie.MaxAge != int(timeout.Seconds()) {
		t.Error("Session cookie not created properly")
	}

	ses.Destroy()
	cookie = ses.SessionCookie()
	if cookie != nil {
		t.Error("Cookie created for a destroyed session.")
	}

	ses.destroyed = false
	ses.cookie.Expires = time.Now()
	time.Sleep(time.Microsecond) // Wait for the session to be expired
	cookie = ses.SessionCookie()
	if cookie != nil {
		t.Error("Cookie created for an expired session")
	}
}
