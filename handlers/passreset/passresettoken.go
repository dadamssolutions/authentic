package passreset

import (
	"github.com/dadamssolutions/authentic/handlers/session/sessions"
)

// A Token represents a token used to reset passswords
type Token struct {
	*sessions.Session
}

// Query returns the request query needed for the token
func (p *Token) Query() string {
	return queryName + "=" + p.CookieValue()
}
