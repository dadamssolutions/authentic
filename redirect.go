package authentic8

import (
	"net/http"
	"net/url"
	"strings"
)

// Redirect modes
const (
	StandardMode = iota
	AddRedirectQueryMode
	RetainQueriesMode
	RedirectToQueryMode
)

// RedirectHandler allows redefining the http.RedirectHandler to use redirect URL queries.
type RedirectHandler struct {
	url        string
	code, mode int
}

// RedirectHandler returns a standard redirect handler that is compatible with the authentication cookie.
// This is the same as calling `RedirectHandlerWithMode(url, code, StandardMode)`.
func (a *HTTPAuth) RedirectHandler(url string, code int) http.Handler {
	return a.RedirectHandlerWithMode(url, code, StandardMode)
}

// RedirectHandlerWithMode returns a redirect handler that is compatible with the authentication cookie.
// The mode determines how it handles redirect URL queries.
//
// StandardMode - ignores queries
// AddRedirectQueryMode - adds the request URL as a redirect query string to the URL.
// RedirectToQueryMode - redirects to the redirect query string as a URL
// All queries are URL Un/Escaped automatically.
func (a *HTTPAuth) RedirectHandlerWithMode(url string, code, mode int) http.Handler {
	return a.AttachSessionCookie()(RedirectHandler{url, code, mode})
}

// ServeHTTP serves a redirect based on the given mode of the RedirectHandler.
func (rh RedirectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch rh.mode {
	case AddRedirectQueryMode:
		http.Redirect(w, r, rh.url+"?redirect="+url.QueryEscape(r.URL.Path), rh.code)
	case RedirectToQueryMode:
		redirect, err := url.QueryUnescape(r.URL.Query().Get("redirect"))
		if redirect == "" || err != nil {
			redirect = rh.url
		}
		http.Redirect(w, r, strings.ReplaceAll(redirect, "://", ""), rh.code)
	case RetainQueriesMode:
		q := r.URL.Query()
		url := rh.url
		if len(q) != 0 {
			url += "?" + q.Encode()
		}
		http.Redirect(w, r, url, rh.code)
	default:
		http.Redirect(w, r, rh.url, rh.code)
	}
}
