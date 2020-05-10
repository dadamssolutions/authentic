package authentic

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"

	"github.com/dadamssolutions/adaptd"
	"github.com/dadamssolutions/authentic/handlers/passreset"
	"github.com/dadamssolutions/authentic/handlers/session"
)

// PasswordResetRequestAdapter handles the GET and POST requests for requesting password reset.
// If the request is GET, the getHandler passed to the Adapter.
//
// The form shown to the user in a GET request should have an input with name 'email'
// The POST request should be pointed to the same handler, and the user is sent a link to reset their password.
//
// When a POST request is received, the database is checked for the existing user. If the user exists,
// and email is send to the user. You can include {{.link}} in the template to include the password reset link.
//
// If a user with the supplied email does not exists, then the handler passed to the Adapter is called
// with the appropriate error on the Request's context.
//
// After successful password reset, the user is redirected to redirectOnSuccess.
// If their is an error, the user is redirected to redirectOnError.
func (a *HTTPAuth) PasswordResetRequestAdapter() adaptd.Adapter {

	return a.StandardPostAndGetAdapter(
		http.HandlerFunc(a.passwordResetRequest),
		a.RedirectAfterResetRequest,
		a.PasswordResetRequestURL,
		"CSRF token not valid for password reset request",
	)
}

// PasswordResetAdapter handles the GET and POST requests for reseting the password.
// If the request is GET with the correct query string, the getHandler passed to the Adapter.
//
// If the request is GET with invalid query string, the user is redirected to redirectOnError
// unless the user is logged in. An authenticated user is allow to reset their password.
//
// The form shown to the user in a GET request should have inputs with names 'password' and 'repeatedPassword'
// The POST request should be pointed to the same handler, and the user's password is updated.
//
// After successful password reset, the user is redirected to redirectOnSuccess.
// If their is an error, the user is redirected to redirectOnError.
func (a *HTTPAuth) PasswordResetAdapter() adaptd.Adapter {
	// A check function that returns err == nil if the user is logged in or the password reset token is valid.
	f := func(w http.ResponseWriter, r *http.Request) error {
		username, err := a.passResetHandler.ValidToken(r)
		tx := session.TxFromContext(r.Context())
		u := getUserFromDB(tx, a.usersTableName, "username", username)
		*r = *r.WithContext(NewUserContext(r.Context(), u))
		if !a.userIsAuthenticated(w, r) && err != nil {
			log.Printf("Cannot generate a token for %v\n", username)
			return fmt.Errorf("Cannot generate a password reset token")
		}
		return nil
	}

	// A check function that attaches a password reset token as a cookie.
	g := func(w http.ResponseWriter, r *http.Request) error {
		var ses *passreset.Token
		u := UserFromContext(r.Context())
		tx := session.TxFromContext(r.Context())
		if u != nil {
			ses = a.passResetHandler.GenerateNewToken(tx, u.Username)
		}
		if ses == nil {
			log.Printf("Cannot attach token for %v\n", u.Username)
			return errors.New("Cannot attach token")
		}

		return a.passResetHandler.AttachCookie(tx, w, ses.Session)
	}

	logOnError := "CSRF token not valid for password reset request"

	adapters := []adaptd.Adapter{
		RedirectOnError(f, http.RedirectHandler(a.PasswordResetRequestURL, http.StatusSeeOther), "Invalid password reset query"),
		RedirectOnError(g, http.RedirectHandler(a.PasswordResetRequestURL, http.StatusInternalServerError), "Error attaching password reset token"),
	}

	return a.StandardPostAndGetAdapter(http.HandlerFunc(a.passwordReset), a.LoginURL, a.PasswordResetRequestURL, logOnError, adapters...)
}

func (a *HTTPAuth) passwordReset(w http.ResponseWriter, r *http.Request) {
	password, repeatedPassword := url.QueryEscape(r.PostFormValue("password")), url.QueryEscape(r.PostFormValue("repeatedPassword"))

	username, err := a.passResetHandler.ValidHeaderToken(r)
	if password != repeatedPassword {
		err = fmt.Errorf("Passwords do not match")
	}
	if err != nil {
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
		return
	}
	passHash, err := a.GenerateHashFromPassword([]byte(password))
	if err != nil {
		err = fmt.Errorf("Invalid password")
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
		return
	}
	tx := session.TxFromContext(r.Context())
	updateUserPassword(tx, a.usersTableName, username, base64.RawURLEncoding.EncodeToString(passHash))
	if err != nil {
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
	} else {
		ses := SessionFromContext(r.Context())
		if ses != nil {
			ses.AddMessage(fmt.Sprintf("Password for %v was reset successfully!", username))
		}
	}
}

func (a *HTTPAuth) passwordResetRequest(w http.ResponseWriter, r *http.Request) {
	tx := session.TxFromContext(r.Context())
	addr, err := mail.ParseAddress(r.PostFormValue("email"))
	if err != nil {
		*r = *r.WithContext(NewErrorContext(r.Context(), fmt.Errorf("Email %v is not valid", r.PostFormValue("email"))))
		return
	}
	sendEmail, err := strconv.ParseBool(r.PostFormValue("sendEmail"))
	redirectPath := r.PostFormValue("redirect")
	a.userIsAuthenticated(w, r)
	admin := UserFromContext(r.Context())
	if err != nil || admin == nil || !admin.HasPermission(Admin) {
		// If there was nothing to parse, then we assume that the email should be sent
		sendEmail = true
	} else if redirectPath == "" {
		redirectPath = "/"
	}
	user := getUserFromDB(tx, a.usersTableName, "email", strings.ToLower(addr.Address))
	if user == nil {
		*r = *r.WithContext(NewErrorContext(r.Context(), fmt.Errorf("Email %v does not exist", addr.Address)))
		return
	}
	token := a.passResetHandler.GenerateNewToken(tx, user.Username)

	data := make(map[string]interface{})
	data["Link"] = a.domainName + a.PasswordResetURL + "?" + token.Query()
	if sendEmail {
		err = a.emailHandler.SendMessage(a.PasswordResetEmailTemplate, "Password Reset Request", data, user)
		if err != nil {
			*r = *r.WithContext(NewErrorContext(r.Context(), err))
		}
		log.Println(fmt.Sprintf("Password reset email sent to %v", user.Username))
	} else {
		session := SessionFromContext(r.Context())
		session.AddMessage("Please send the following link:")
		session.AddMessage(data["Link"])
		a.RedirectHandler(redirectPath, http.StatusSeeOther).ServeHTTP(w, r)
	}
}
