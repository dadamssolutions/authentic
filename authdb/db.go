package authdb

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"github.com/dadamssolutions/authentic/handlers/session"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
)

const (
	createUsersTableSQL     = "CREATE TABLE IF NOT EXISTS %v (username varchar, fname varchar DEFAULT '', lname varchar DEFAULT '', email varchar NOT NULL UNIQUE, role int NOT NULL DEFAULT 0, validated boolean DEFAULT false, pass_hash char(80) DEFAULT '', last_access timestamp DEFAULT 'epoch', PRIMARY KEY (username));"
	addUserToDatabaseSQL    = "INSERT INTO %s (username, fname, lname, email, validated, pass_hash) VALUES ($1,$2,$3,$4,false,$5);"
	getUserInfoSQL          = "SELECT username, fname, lname, email, role, validated FROM %s WHERE %s = $1;"
	getUserPasswordHashSQL  = "SELECT pass_hash FROM %v WHERE username = $1;"
	validateUserSQL         = "UPDATE %v SET validated = true WHERE username = $1;"
	updateUserPasswordSQL   = "UPDATE %v SET (pass_hash, validated) = ($1, true) WHERE username = $2;" // #nosec
	updateUserLastAccessSQL = "UPDATE %v SET last_access = $1 WHERE username = $2;"
	getUserLastAccessSQL    = "SELECT last_access FROM %s WHERE username = $1;"
	dateLayout              = "2006-01-02 15:04:05"
)

// Conn represents the methods used to pull information from the database
type Conn interface {
	GetUserFromDB(context.Context, string, string) *User
	UsernameOrEmailExists(context.Context, *User) (bool, bool)
	AddUserToDatabase(context.Context, *User)
	ValidateUser(context.Context, *User)
	UpdateUserPassword(context.Context, string, string)
	GetUserLastAccess(context.Context, string) time.Time
	UpdateUserLastAccess(context.Context, string)
}

// NewConn returns a Conn that uses the database from db and the tableNmae given
func NewConn(ctx context.Context, db *pgxpool.Pool, tableName string) (Conn, error) {
	err := createUsersTable(ctx, db, tableName)
	if err != nil {
		log.Printf("Could not create users table: %v", err)
		return nil, err
	}
	return conn{tableName}, nil
}

type conn struct {
	tableName string
}

// GetUserFromDB returns a User struct as pulled from the database.
func (c conn) GetUserFromDB(ctx context.Context, col, search string) *User {
	tx := session.TxFromContext(ctx)
	user := User{}
	err := tx.QueryRow(ctx, fmt.Sprintf(getUserInfoSQL, pgx.Identifier{c.tableName}.Sanitize(), pgx.Identifier{col}.Sanitize()), search).Scan(&user.Username, &user.FirstName, &user.LastName, &user.Email, &user.Role, &user.validated)
	if err != nil {
		log.Println(err)
		log.Println("Cannot get user from database")
		return nil
	}

	user.passHash = c.getUserPasswordHash(ctx, tx, user.Username)

	return &user
}

// UsernameOrEmailExists returns two bools:
// the first is `true` if the username for the User is in the database
// the second is `true` if the email for the User is in the database
func (c conn) UsernameOrEmailExists(ctx context.Context, user *User) (bool, bool) {
	usernameSearch := c.GetUserFromDB(ctx, "username", user.Username)
	emailSearch := c.GetUserFromDB(ctx, "email", user.GetEmail())
	return usernameSearch != nil, emailSearch != nil
}

// AddUserToDatabase add the User to the database
func (c conn) AddUserToDatabase(ctx context.Context, user *User) {
	tx := session.TxFromContext(ctx)
	_, err := tx.Exec(ctx, fmt.Sprintf(addUserToDatabaseSQL, pgx.Identifier{c.tableName}.Sanitize()), user.Username, user.FirstName, user.LastName, user.Email, string(user.passHash))
	if err != nil {
		panic(fmt.Sprintf("Cannot add user %v to database: %v", user.Username, err))
	}
}

// ValidateUser changes the User's status in the database to `true`
func (c conn) ValidateUser(ctx context.Context, user *User) {
	tx := session.TxFromContext(ctx)
	_, err := tx.Exec(ctx, fmt.Sprintf(validateUserSQL, pgx.Identifier{c.tableName}.Sanitize()), user.Username)
	if err != nil {
		panic(fmt.Sprintf("Could not validate user %v: %v", user.Username, err))
	}
}

// UpdateUserPassword updates the User's password in the database
func (c conn) UpdateUserPassword(ctx context.Context, username, passHash string) {
	tx := session.TxFromContext(ctx)
	_, err := tx.Exec(ctx, fmt.Sprintf(updateUserPasswordSQL, pgx.Identifier{c.tableName}.Sanitize()), passHash, username)
	if err != nil {
		panic(fmt.Sprintf("Could not update user %v password: %v", username, err))
	}
}

// GetUserLastAccess returns the last time the User is known to access the site.
func (c conn) GetUserLastAccess(ctx context.Context, username string) time.Time {
	var t time.Time
	tx := session.TxFromContext(ctx)
	err := tx.QueryRow(ctx, fmt.Sprintf(getUserLastAccessSQL, pgx.Identifier{c.tableName}.Sanitize()), username).Scan(&t)
	if err != nil {
		panic(fmt.Sprintf("Could not get last access time for user %v: %v", username, err))
	}
	return t
}

// UpdateUserLastAccess updates the last time the User is known to access the site.
func (c conn) UpdateUserLastAccess(ctx context.Context, username string) {
	tx := session.TxFromContext(ctx)
	_, err := tx.Exec(ctx, fmt.Sprintf(updateUserLastAccessSQL, pgx.Identifier{c.tableName}.Sanitize()), time.Now().Format(dateLayout), username)
	if err != nil {
		panic(fmt.Sprintf("Could not update last access time for user %v: %v", username, err))
	}
}

// getUserPasswordHash gets the User's hashed password from the database
func (c conn) getUserPasswordHash(ctx context.Context, tx pgx.Tx, username string) []byte {
	var pwHash string
	err := tx.QueryRow(ctx, fmt.Sprintf(getUserPasswordHashSQL, pgx.Identifier{c.tableName}.Sanitize()), username).Scan(&pwHash)
	if err != nil {
		panic(fmt.Sprintf("Cannot get password for user %v: %v", username, err))
	}
	pwDecoded, err := base64.RawURLEncoding.DecodeString(pwHash)
	if err != nil {
		return nil
	}
	return pwDecoded
}

// createUsersTable creates the table in the database for user information, if it doesn't exist already.
func createUsersTable(ctx context.Context, db *pgxpool.Pool, tableName string) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil
	}
	_, err = tx.Exec(ctx, fmt.Sprintf(createUsersTableSQL, pgx.Identifier{tableName}.Sanitize()))
	if err != nil {
		if err := tx.Rollback(ctx); err != nil {
			panic(err)
		}
		return err
	}
	return tx.Commit(ctx)
}
