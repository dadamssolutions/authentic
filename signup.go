package authentic

import (
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"strings"

	"github.com/dadamssolutions/adaptd"
	"github.com/dadamssolutions/authentic/authdb"
)

// SignUpAdapter handles the sign up GET and POST requests.
// If it is determined that the sign up page should be shown, then the handler passed to the Adapter is called.
// If the user sign up POST request fails, the handler passed to the adapter is called again,
// this time with an error on the Request's context.
//
// The form for the POST request should point back to this handler.
// The form should have six inputs: firstname, lastname, username, email, password, repeatedPassword
func (a *HTTPAuth) SignUpAdapter() adaptd.Adapter {
	f := func(w http.ResponseWriter, r *http.Request) bool {
		return !a.userIsAuthenticated(w, r)
	}

	logOnError := "CSRF token not valid for password reset request"

	adapters := []adaptd.Adapter{
		adaptd.CheckAndRedirect(f, a.RedirectHandler(a.RedirectAfterLogin, http.StatusSeeOther), "User requesting login page is logged in"),
	}

	return a.StandardPostAndGetAdapter(http.HandlerFunc(a.signUp), a.RedirectAfterSignUp, a.SignUpURL, logOnError, adapters...)
}

// SignUpVerificationAdapter handles verification of sign ups.
// The user is sent an email with a verification link. When the user clicks that link they are sent to
// this handler that verifies the token they were given and marks them as verified.
func (a *HTTPAuth) SignUpVerificationAdapter() adaptd.Adapter {
	// A check function that returns err == nil if the user is logged in or the password reset token is valid.
	f := func(w http.ResponseWriter, r *http.Request) error {
		username, err := a.passResetHandler.ValidToken(r)
		if err != nil {
			return fmt.Errorf("Invalid sign-up verification token")
		}

		u := a.conn.GetUserFromDB(r.Context(), "username", username)
		*r = *r.WithContext(NewUserContext(r.Context(), u))
		return nil
	}

	return func(h http.Handler) http.Handler {
		adapters := []adaptd.Adapter{
			RedirectOnError(f, a.RedirectHandler(a.SignUpURL, http.StatusUnauthorized), "Invalid sign up validation query"),
			RedirectOnError(a.verifySignUp, a.RedirectHandler(a.SignUpURL, http.StatusUnauthorized), "Invalid sign up validation query"),
		}
		return adaptd.Adapt(h, adapters...)
	}
}

func (a *HTTPAuth) signUp(w http.ResponseWriter, r *http.Request) {
	// If the user is authenticated already, then we just redirect
	if a.userIsAuthenticated(w, r) {
		log.Printf("User requesting sign up page, but is already logged in. Redirecting to %v\n", a.RedirectAfterLogin)
		return
	}
	// If the user is not logged in, we get the information and validate it
	password, repeatedPassword := r.PostFormValue("password"), r.PostFormValue("repeatedPassword")
	if password == "" || password != repeatedPassword {
		log.Println("Sign up passwords did not match, redirecting back to sign up page")
		*r = *r.WithContext(NewErrorContext(
			r.Context(),
			fmt.Errorf("Passwords did not match"),
		))
		return
	}
	username := r.PostFormValue("username")
	addr, err := mail.ParseAddress(r.PostFormValue("email"))
	if err != nil {
		log.Printf("Sign up included a bad email address: %v\n", r.PostFormValue("email"))
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
		return
	}
	firstName, lastName := r.PostFormValue("firstName"), r.PostFormValue("lastName")
	hashedPassword, err := a.GenerateHashFromPassword([]byte(password))
	if err != nil {
		log.Println("Unable to hash password")
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
		return
	}
	user := authdb.NewUser(firstName, lastName, strings.ToLower(username), strings.ToLower(addr.Address), hashedPassword, false)

	if usernameExists, emailExists := a.conn.UsernameOrEmailExists(r.Context(), user); usernameExists {
		log.Printf("Username %v exists\n", user.Username)
		*r = *r.WithContext(NewErrorContext(
			r.Context(),
			fmt.Errorf("Username %v already exists", user.Username),
		))
		return
	} else if emailExists {
		log.Printf("Email %v exists\n", user.GetEmail())
		*r = *r.WithContext(NewErrorContext(
			r.Context(),
			fmt.Errorf("Email %v already exists", user.Email),
		))
		return
	}

	// Get the reset token and send the message.
	token := a.passResetHandler.GenerateNewToken(r.Context(), user.Username)
	data := make(map[string]interface{})
	data["Link"] = "https://" + a.domainName + a.SignUpVerificationURL + "?" + token.Query()
	err = a.emailHandler.SendMessage(a.SignUpEmailTemplate, "Welcome!", data, user)
	if err != nil || !user.IsValid() {
		log.Println("User sign up failed, redirecting back to sign up page")
		*r = *r.WithContext(NewErrorContext(
			r.Context(),
			fmt.Errorf("User %v, %v was invalid, could not sign up", user.Username, user.Email),
		))
		return
	}
	a.conn.AddUserToDatabase(r.Context(), user)
}

func (a *HTTPAuth) verifySignUp(w http.ResponseWriter, r *http.Request) error {
	err := fmt.Errorf("No valid user was available")
	user := UserFromContext(r.Context())
	if user == nil {
		return err
	}

	a.conn.ValidateUser(r.Context(), user)

	return nil
}
