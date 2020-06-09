package authentic

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/dadamssolutions/adaptd"
	"github.com/dadamssolutions/authentic/handlers/session"
)

// RedirectIfErrorOnContext checks for an error on the Request's context.
// If the error is not nil, the redirect handler is called.
func RedirectIfErrorOnContext(redirectHandler http.Handler) adaptd.Adapter {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ErrorFromContext(r.Context()) != nil {
				redirectHandler.ServeHTTP(w, r)
				return
			}
			h.ServeHTTP(w, r)
		})
	}
}

// RedirectOnError redirects based on whether it kind find an error in the Request's context.
func RedirectOnError(f func(http.ResponseWriter, *http.Request) error, fh http.Handler, logOnError string) adaptd.Adapter {
	g := func(w http.ResponseWriter, r *http.Request) bool {
		err := f(w, r)
		if err != nil {
			*r = *r.WithContext(NewErrorContext(r.Context(), errors.New(logOnError)))
			return false
		}
		return true
	}

	return adaptd.OnCheck(g, fh, logOnError)
}

// PostAndOtherOnError calls postHandler and then checks the error on the Request's context.
// If there is an error, the handler passed to the adapter is called.
//
// This is useful for a POST request that tries to log a user in and calls a GET handler on error.
// The GET handler can then look at the error on the Request's context.
func PostAndOtherOnError(postHandler http.Handler, redirectOnSuccess, redirectOnError http.Handler) adaptd.Adapter {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				postHandler.ServeHTTP(w, r)
				if loc := w.Header().Get("Location"); loc != "" {
					return
				}
				err := ErrorFromContext(r.Context())
				if err == nil {
					redirectOnSuccess.ServeHTTP(w, r)
					return
				}
				redirectOnError.ServeHTTP(w, r)
				return
			}
			h.ServeHTTP(w, r)
		})
	}
}

// PutTxOnContext puts a new database transaction on the context before calling the passed handler.
// If the transaction that is put on the context should be rolledback, then panic should be called.
// PutTxOnContext will recover from the panic and report a 500 error.
// If starting the transaction fails, then panic is called.
func PutTxOnContext(db *sql.DB) adaptd.Adapter {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tx, err := db.Begin()
			if err != nil || tx == nil {
				panic(err)
			}

			defer func() {
				if r := recover(); r != nil {
					var err error
					switch r := r.(type) {
					case error:
						err = r
					default:
						err = fmt.Errorf("Panic Error: %v", r)
					}
					w.WriteHeader(http.StatusInternalServerError)
					log.Printf("Transaction is being rolled back: %s", err.Error())
					if err := tx.Rollback(); err != nil {
						panic(err)
					}
				}
			}()

			h.ServeHTTP(w, r.WithContext(session.NewTxContext(r.Context(), tx)))

			if err = tx.Commit(); err != nil {
				panic(err)
			}
		})
	}
}

func adaptAndAbsorbError(h http.Handler, adapters ...adaptd.Adapter) http.Handler {
	// Attach adapters in reverse order because that is what should be implied by the ordering of the caller.
	// The way the middleware will work is the first adapter applied will be the last one to get called.
	// However, if there is an error on the context, then h is called immediately.
	for i := len(adapters) - 1; i >= 0; i-- {
		h = adapters[i](func(f http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if ErrorFromContext(r.Context()) != nil {
					return
				}
				f.ServeHTTP(w, r)
			})
		}(h))
	}
	return h
}
