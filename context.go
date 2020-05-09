package authentic8

import (
	"context"

	"github.com/dadamssolutions/authentic8/handlers/session/sessions"
)

type key int

const (
	errorKey   key = 0
	userKey    key = 1
	sessionKey key = 2
)

// NewErrorContext adds an error to the context.
func NewErrorContext(ctx context.Context, err error) context.Context {
	return context.WithValue(ctx, errorKey, err)
}

// ErrorFromContext looks for an error in the context.
// If there is no error found, then the return value will be nil.
func ErrorFromContext(ctx context.Context) error {
	err, _ := ctx.Value(errorKey).(error)
	return err
}

// NewUserContext adds a User to the context.
func NewUserContext(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, userKey, user)
}

// UserFromContext looks for a User in the context.
// If there is no User found, then the return value will be nil.
func UserFromContext(ctx context.Context) *User {
	user, _ := ctx.Value(userKey).(*User)
	return user
}

// NewSessionContext adds a *session.Session to the context.
func NewSessionContext(ctx context.Context, ses *sessions.Session) context.Context {
	return context.WithValue(ctx, sessionKey, ses)
}

// SessionFromContext looks for a session in the context.
// If there is no session found, then the return value will be nil.
func SessionFromContext(ctx context.Context) *sessions.Session {
	ses, _ := ctx.Value(sessionKey).(*sessions.Session)
	return ses
}
