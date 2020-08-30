package authdb

import (
	"log"
	"strings"
)

// Represent roles used for users.
const (
	Member = iota
	Manager
	Supervisor
	Admin
)

// Role is represents the role of a user.
// Roles elevate and have a linear hierarchy.
type Role int

// HasRole returns whether the role has the given permssion level.
func (r Role) HasRole(permission Role) bool {
	return r >= permission
}

// User represents a user to be logged in or signed up represented in the created database.
// For ease, you would want the representation of the user in your app to embed User.
type User struct {
	FirstName, LastName, Email, Greet, Username string
	Role                                        Role
	validated                                   bool
	passHash                                    []byte
}

// NewUser returns a User with the given information. The user is not added to the database.
func NewUser(firstName, lastName, username, email string, passHash []byte, validated bool) *User {
	return &User{FirstName: firstName, LastName: lastName, Username: strings.ToLower(username), Email: email, passHash: passHash, validated: false}
}

// GetEmail implements the email.Recipient interface.
func (u User) GetEmail() string {
	return u.Email
}

// Greeting implements the email.Recipient interface.
func (u User) Greeting() string {
	return u.FirstName
}

// HasPermission determines whether the user has the given permission level
func (u User) HasPermission(role Role) bool {
	return u.Role.HasRole(role)
}

// IsValidated returns whether the user has validated their login
func (u User) IsValidated() bool {
	return u.validated
}

// IsValid returns `true` if the User has a FirstName, LastName, Email, or Username
func (u User) IsValid() bool {
	return !(u.FirstName == "" || u.LastName == "" || u.Email == "" || u.Username == "")
}

// VerifyPassword returns `true` if testPass matches the User's password
func (u User) VerifyPassword(testPass []byte, verifyFunc func([]byte, []byte) error) bool {
	err := verifyFunc(u.passHash, testPass)
	if err != nil {
		log.Printf("Unable to verify password: %v", err)
	}
	return err == nil
}
