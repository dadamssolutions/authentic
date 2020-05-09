/*Package smtpauth provides implementations of the smtp.Auth interface for sending messages
with the LOGIN authentication mechanism, only allowed of SSL/TLS connections.
*/
package smtpauth

import (
	"fmt"
	"net/smtp"
	"strings"
)

// LoginAuth is an Auth that implements the LOGIN authentication
// mechanism as defined in RFC 4616.
type LoginAuth struct {
	username, password string
}

// NewLoginAuth returns an Auth that implements the LOGIN authentication
// mechanism as defined in RFC 4616.
func NewLoginAuth(username, password string) smtp.Auth {
	return &LoginAuth{username, password}
}

// Start begins an authentication with a server.
// It returns the name of the authentication protocol
// and optionally data to include in the initial AUTH message
// sent to the server. It can return proto == "" to indicate
// that the authentication should be skipped.
// If it returns a non-nil error, the SMTP client aborts
// the authentication attempt and closes the connection.
func (a *LoginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", nil, nil
}

// Next continues the authentication. The server has just sent
// the fromServer data. If more is true, the server expects a
// response, which Next should return as toServer; otherwise
// Next should return toServer == nil.
// If Next returns a non-nil error, the SMTP client aborts
// the authentication attempt and closes the connection.
func (a *LoginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	command := string(fromServer)
	command = strings.TrimSpace(command)
	command = strings.TrimSuffix(command, ":")
	command = strings.ToLower(command)

	if more {
		if command == "username" {
			return []byte(fmt.Sprintf("%s", a.username)), nil
		} else if command == "password" {
			return []byte(fmt.Sprintf("%s", a.password)), nil
		} else {
			// We've already sent everything.
			return nil, fmt.Errorf("unexpected server challenge: %s", command)
		}
	}
	return nil, nil
}
