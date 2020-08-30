package authentic

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/dadamssolutions/adaptd"
)

// LoginAdapter handles the login GET and POST requests
// If it is determined that the login page should be shown, then the handler passed to the Adapter is called.
// If the user login POST request fails, the handler passed to the adapter is called again,
// this time with an error on the Request's context.
//
// The form for the POST request should point back to this handler.
// The form should have three inputs: username, password, and remember.
func (a *HTTPAuth) LoginAdapter() adaptd.Adapter {
	f := func(w http.ResponseWriter, r *http.Request) bool {
		return !a.userIsAuthenticated(w, r)
	}

	logOnError := "Bad login request. Try again."

	adapters := []adaptd.Adapter{adaptd.CheckAndRedirect(f, a.RedirectHandlerWithMode(a.RedirectAfterLogin, http.StatusSeeOther, RedirectToQueryMode), "User requesting login page is logged in")}

	return a.StandardPostAndGetAdapter(http.HandlerFunc(a.logUserIn), a.RedirectAfterLogin, a.LoginURL, logOnError, adapters...)
}

func (a *HTTPAuth) logUserIn(w http.ResponseWriter, r *http.Request) {
	ses := SessionFromContext(r.Context())
	// If the user is authenticated already, then we just redirect
	if ses.IsUserLoggedIn() {
		log.Printf("User requesting login page, but is already logged in. Redirecting to %v\n", a.RedirectAfterLogin)
		return
	}
	// If the user is not logged in, we check the credentials
	username, password := url.QueryEscape(r.PostFormValue("username")), url.QueryEscape(r.PostFormValue("password"))
	username = strings.ToLower(username)
	remember := url.QueryEscape(r.PostFormValue("remember"))
	rememberMe, _ := strconv.ParseBool(remember)
	user := a.conn.GetUserFromDB(r.Context(), "username", username)
	// If the user cannot be found by username, then we look for the email address.
	if user == nil {
		user = a.conn.GetUserFromDB(r.Context(), "email", strings.ToLower(r.PostFormValue("username")))
	}
	// If the user has provided correct credentials, then we log them in by creating a session.
	if user != nil && user.IsValidated() && user.VerifyPassword([]byte(password), a.CompareHashAndPassword) {
		ses = a.sesHandler.CopySession(r.Context(), ses, rememberMe)
		a.sesHandler.LogUserIn(r.Context(), ses, user.Username)
		*r = *r.WithContext(NewUserContext(r.Context(), user))
	}

	if ses.IsUserLoggedIn() {
		log.Printf("User %v logged in successfully. Redirecting to %v\n", user.Username, a.RedirectAfterLogin)
	} else {
		log.Printf("User %v login failed, redirecting back to login page\n", username)
		err := fmt.Errorf("Login failed, please try again")
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
	}
	*r = *r.WithContext(NewSessionContext(r.Context(), ses))
}
