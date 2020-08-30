package authentic

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"github.com/dadamssolutions/authentic/handlers/session"
	"github.com/jackc/pgx/v4"
)

// Represent roles used for users.
const (
	Member = iota
	Manager
	Supervisor
	Admin

	createUsersTableSQL     = "CREATE TABLE IF NOT EXISTS %v (username varchar, fname varchar DEFAULT '', lname varchar DEFAULT '', email varchar NOT NULL UNIQUE, role int NOT NULL DEFAULT 0, validated boolean DEFAULT false, pass_hash char(80) DEFAULT '', last_access timestamp DEFAULT 'epoch', PRIMARY KEY (username));"
	addUserToDatabaseSQL    = "INSERT INTO %s (username, fname, lname, email, validated, pass_hash) VALUES ('%s','%s','%s','%s',false,'%s');"
	getUserInfoSQL          = "SELECT username, fname, lname, email, role, validated FROM %s WHERE %s = '%s';"
	getUserPasswordHashSQL  = "SELECT pass_hash FROM %v WHERE username = '%s';"
	validateUserSQL         = "UPDATE %v SET validated = true WHERE username = '%s';"
	updateUserPasswordSQL   = "UPDATE %v SET (pass_hash, validated) = ('%s', true) WHERE username = '%s';" // #nosec
	updateUserLastAccessSQL = "UPDATE %v SET last_access = '%s' WHERE username = '%s';"
	getUserLastAccessSQL    = "SELECT last_access FROM %s WHERE username = '%s';"
	deleteTestTableSQL      = "DROP TABLE %s;"
	dateLayout              = "2006-01-02 15:04:05"
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

func (u User) isValid() bool {
	return !(u.FirstName == "" || u.LastName == "" || u.Email == "" || u.Username == "")
}

func getUserFromDB(ctx context.Context, tableName, col, search string) *User {
	tx := session.TxFromContext(ctx)
	user := User{}
	err := tx.QueryRow(ctx, fmt.Sprintf(getUserInfoSQL, pgx.Identifier{tableName}.Sanitize(), pgx.Identifier{col}.Sanitize(), search)).Scan(&user.Username, &user.FirstName, &user.LastName, &user.Email, &user.Role, &user.validated)
	if err != nil {
		log.Println(err)
		log.Println("Cannot get user from database")
		return nil
	}

	user.passHash = getUserPasswordHash(ctx, tx, tableName, user.Username)

	return &user
}

func usernameOrEmailExists(ctx context.Context, tableName string, user *User) (bool, bool) {
	usernameSearch := getUserFromDB(ctx, tableName, "username", user.Username)
	emailSearch := getUserFromDB(ctx, tableName, "email", user.GetEmail())
	return usernameSearch != nil, emailSearch != nil
}

func addUserToDatabase(ctx context.Context, tableName string, user *User) {
	tx := session.TxFromContext(ctx)
	_, err := tx.Exec(ctx, fmt.Sprintf(addUserToDatabaseSQL, pgx.Identifier{tableName}.Sanitize(), user.Username, user.FirstName, user.LastName, user.Email, string(user.passHash)))
	if err != nil {
		panic(fmt.Sprintf("Cannot add user %v to database: %v", user.Username, err))
	}
}

func validateUser(ctx context.Context, tableName string, user *User) {
	tx := session.TxFromContext(ctx)
	_, err := tx.Exec(ctx, fmt.Sprintf(validateUserSQL, pgx.Identifier{tableName}.Sanitize(), user.Username))
	if err != nil {
		panic(fmt.Sprintf("Could not validate user %v: %v", user.Username, err))
	}
}

func getUserPasswordHash(ctx context.Context, tx pgx.Tx, tableName, username string) []byte {
	var pwHash string
	err := tx.QueryRow(ctx, fmt.Sprintf(getUserPasswordHashSQL, pgx.Identifier{tableName}.Sanitize(), username)).Scan(&pwHash)
	if err != nil {
		panic(fmt.Sprintf("Cannot get password for user %v: %v", username, err))
	}
	pwDecoded, err := base64.RawURLEncoding.DecodeString(pwHash)
	if err != nil {
		return nil
	}
	return pwDecoded
}

func updateUserPassword(ctx context.Context, tableName, username, passHash string) {
	tx := session.TxFromContext(ctx)
	_, err := tx.Exec(ctx, fmt.Sprintf(updateUserPasswordSQL, pgx.Identifier{tableName}.Sanitize(), passHash, username))
	if err != nil {
		panic(fmt.Sprintf("Could not update user %v password: %v", username, err))
	}
}

func getUserLastAccess(ctx context.Context, tableName, username string) time.Time {
	var t time.Time
	tx := session.TxFromContext(ctx)
	err := tx.QueryRow(ctx, fmt.Sprintf(getUserLastAccessSQL, pgx.Identifier{tableName}.Sanitize(), username)).Scan(&t)
	if err != nil {
		panic(fmt.Sprintf("Could not get last access time for user %v: %v", username, err))
	}
	return t
}

func updateUserLastAccess(ctx context.Context, tableName, username string) {
	tx := session.TxFromContext(ctx)
	_, err := tx.Exec(ctx, fmt.Sprintf(updateUserLastAccessSQL, pgx.Identifier{tableName}.Sanitize(), time.Now().Format(dateLayout), username))
	if err != nil {
		panic(fmt.Sprintf("Could not update last access time for user %v: %v", username, err))
	}
}
