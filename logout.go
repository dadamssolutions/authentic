package authentic

import (
	"net/http"

	"github.com/dadamssolutions/adaptd"
)

// LogoutAdapter handles the logout requests
// The handler passed to the Adapter is only called is when the logout fails.
// In this case, the error and the session are put on the Request's context.
func (a *HTTPAuth) LogoutAdapter(redirectOnSuccess string) adaptd.Adapter {
	return func(h http.Handler) http.Handler {
		g := func(w http.ResponseWriter, r *http.Request) bool {
			return !a.logUserOut(w, r)
		}

		adapters := []adaptd.Adapter{
			adaptd.CheckAndRedirect(a.userIsAuthenticated, a.RedirectHandler(redirectOnSuccess, http.StatusSeeOther), "Requesting logout page, but no user is logged in"),
			adaptd.CheckAndRedirect(g, a.RedirectHandler(redirectOnSuccess, http.StatusSeeOther), "User was logged out"),
		}
		return adaptd.Adapt(h, adapters...)
	}
}
