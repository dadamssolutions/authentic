/*Package passreset provies a handler for password reset token generation, validation, and deletion.
Tokens are one-time use and can be expired without use.
*/
package passreset

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dadamssolutions/authentic8/handlers/session"
)

const (
	// CookieName is the header name for post requests
	CookieName = "X-Post-PassReset"
	queryName  = "resetToken"
)

// Handler handles the creation and validation of password reset tokens
type Handler struct {
	*session.Handler
}

// NewHandler creates a new handler using the database pointer.
func NewHandler(db *sql.DB, tableName string, timeout time.Duration, secret []byte) *Handler {
	sh, err := session.NewHandlerWithDB(db, tableName, CookieName, timeout, timeout, secret)
	if err != nil {
		log.Println("There was a problem creating the password reset handler")
		log.Println(err)
		return nil
	}
	return &Handler{sh}
}

// GenerateNewToken generates a new token for protecting against CSRF
func (c *Handler) GenerateNewToken(tx *sql.Tx, username string) *Token {
	ses := c.CreateSession(tx, username, false)
	if ses == nil {
		log.Println("Error creating a new password reset token")
		return nil
	}
	return &Token{ses}
}

// ValidToken verifies that a password reset token is valid and then destroys it.
// Returns the username of the user for a valid token and "" when there is an error.
func (c *Handler) ValidToken(r *http.Request) (string, error) {
	tx := session.TxFromContext(r.Context())
	return c.verifyToken(tx, r.URL.Query().Get(queryName))
}

// ValidHeaderToken verifies that a password reset token is valid and then destroys it.
// This method is used in post requests.
func (c *Handler) ValidHeaderToken(r *http.Request) (string, error) {
	cookie, _ := r.Cookie(CookieName)
	if cookie == nil {
		return "", errors.New("No password reset cookie")
	}
	tx := session.TxFromContext(r.Context())
	return c.verifyToken(tx, strings.Replace(cookie.Value, queryName+"=", "", 1))
}

func (c *Handler) verifyToken(tx *sql.Tx, token string) (string, error) {
	ses, err := c.ParseSessionCookie(tx, &http.Cookie{Name: CookieName, Value: token})
	if err != nil {
		err = fmt.Errorf("Password reset token %v was not valid", token)
		log.Println(err)
		return "", err
	}
	c.DestroySession(tx, ses)
	return ses.Username(), nil
}
