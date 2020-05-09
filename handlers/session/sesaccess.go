package session

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/dadamssolutions/authentic8/handlers/session/sessions"
	"github.com/lib/pq"
)

const (
	timestampFormat    = "2006-01-02 15:04:05.000 -0700"
	tableCreation      = "CREATE TABLE IF NOT EXISTS %s (selector char(16), session_hash varchar NOT NULL, user_id varchar(50) NOT NULL DEFAULT '', values text, created timestamp WITH TIME ZONE NOT NULL, expiration timestamp WITH TIME ZONE NOT NULL, persistent boolean NOT NULL, PRIMARY KEY (selector));"
	dropTable          = "DROP TABLE %s;"
	insertSession      = "INSERT INTO %s (selector, session_hash, user_id, values, created, expiration, persistent) VALUES(%s, %s, %s, %s, %s, %s, %s);"
	deleteSession      = "DELETE FROM %s WHERE selector = %s;"
	getSessionInfo     = "SELECT selector, session_hash, user_id, values, expiration, persistent FROM %s WHERE selector = %s;"
	updateSession      = "UPDATE %s SET (user_id, expiration, values) = (%s, %s, %s) WHERE selector = %s;"
	cleanUpOldSessions = "DELETE FROM %v WHERE (NOT persistent AND created < NOW() - INTERVAL '%v SECONDS') OR (persistent AND expiration < NOW() - INTERVAL '%v SECONDS') RETURNING selector;"
)

type sesDataAccess struct {
	tableName  string
	cookieName string
	secret     []byte
	cipher     cipher.Block
	lock       *sync.RWMutex
}

func newDataAccess(db *sql.DB, tableName, cookieName string, secret []byte, sessionTimeout, persistentSessionTimeout time.Duration) (sesDataAccess, error) {
	var err error
	sesAccess := sesDataAccess{tableName, cookieName, nil, nil, &sync.RWMutex{}}

	// Set up encryption/decryption capabilities.
	if secret == nil {
		secret = []byte(sesAccess.generateRandomString(32))
	}
	sesAccess.secret = secret
	sesAccess.cipher, err = aes.NewCipher(secret)
	if err != nil {
		log.Println("Error creating the cipher for encryption/decryption")
	}
	err = sesAccess.createTable(db)
	if err != nil {
		log.Printf("Could not create the table in the database: %v\n", err)
		return sesAccess, err
	}

	// Each time this ticks, we will clean the database of old sessions.
	c := time.Tick(sessionTimeout)
	go sesAccess.cleanUpOldSessions(db, c, sessionTimeout.Seconds(), persistentSessionTimeout.Seconds())
	return sesAccess, nil
}

// hashString is a helper function to has the session ID before putting it into the database
func (s sesDataAccess) hashString(data string) string {
	hashBytes := sha256.Sum256([]byte(data))
	return url.QueryEscape(base64.RawURLEncoding.EncodeToString(hashBytes[:]))
}

// generateRandomString is a helper function to find selector and session IDs
func (s sesDataAccess) generateRandomString(length int) string {
	if length <= 0 {
		log.Panicln("Cannot generate a random string of negative length")
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	b := make([]byte, length)
	st := ""
	for true {
		_, err := rand.Read(b)
		if err != nil {
			log.Panicf("ERROR: %v\n", err)
		}
		st = base64.RawURLEncoding.EncodeToString(b)[:length]
		if url.QueryEscape(st) == st {
			break
		}
	}
	return st
}

func (s sesDataAccess) generateSelectorID() string {
	return s.generateRandomString(selectorIDLength)
}

func (s sesDataAccess) generateSessionID() string {
	return s.generateRandomString(sessionIDLength)
}

func (s sesDataAccess) createTable(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return databaseTableCreationError(s.tableName)
	}
	// Create the table we need in the database
	_, err = tx.Exec(fmt.Sprintf(tableCreation, pq.QuoteIdentifier(s.tableName)))
	if err != nil {
		tx.Rollback()
		return databaseTableCreationError(s.tableName)
	}
	log.Println(s.tableName + " table created")
	return tx.Commit()
}

func (s sesDataAccess) cleanUpOldSessions(db *sql.DB, c <-chan time.Time, sessionTimeout, persistentSessionTimeout float64) {
	log.Printf("Waiting to clean old %v...\n", s.tableName)
	for range c {
		//log.Printf("Cleaning old %v....\n", s.tableName)
		tx, err := db.Begin()
		if err != nil {
			log.Printf("We have stopped cleaning up old %v\n", s.tableName)
			log.Println(err)
			return
		}
		// Clean up old sessions that are not persistent and are older than maxLifetimeSessionOnly
		// Also clean up old expired persistent sessions.
		rows, err := tx.Query(fmt.Sprintf(cleanUpOldSessions, s.tableName, sessionTimeout, persistentSessionTimeout))
		if err != nil {
			tx.Rollback()
			log.Printf("We have stopped cleaning up old %v\n", s.tableName)
			log.Println(err)
			return
		}
		defer rows.Close()
		for rows.Next() {
			selectorDeleted := ""
			rows.Scan(&selectorDeleted)
			log.Printf("Deleted %v with selector %v\n", s.tableName, selectorDeleted)
		}
		tx.Commit()
	}
}

// dropTable is used in testing to clear the database each time.
func (s sesDataAccess) dropTable(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return databaseTableCreationError(s.tableName)
	}
	// Drop the sessions table
	_, err = tx.Exec(fmt.Sprintf(dropTable, pq.QuoteIdentifier(s.tableName)))
	if err != nil {
		tx.Rollback()
		return databaseTableCreationError(s.tableName)
	}
	return tx.Commit()
}

func (s sesDataAccess) createSession(tx *sql.Tx, username string, maxLifetime time.Duration, persistent bool) *sessions.Session {
	if !persistent {
		maxLifetime = 0
	}
	var selectorID, sessionID string
	var err error
	var ses *sessions.Session

	// We need to loop until we generate unique selector and session IDs
	for true {
		selectorID, sessionID = s.generateSelectorID(), s.generateSessionID()
		ses = sessions.NewSession(selectorID, sessionID, username, s.encrypt(username, selectorID), s.cookieName, maxLifetime)
		queryString := fmt.Sprintf(insertSession,
			pq.QuoteIdentifier(s.tableName),
			pq.QuoteLiteral(ses.SelectorID()),
			pq.QuoteLiteral(s.hashString(ses.HashPayload())),
			pq.QuoteLiteral(ses.Username()),
			pq.QuoteLiteral(ses.ValuesAsText()),
			pq.QuoteLiteral(time.Now().Format(timestampFormat)),
			pq.QuoteLiteral(ses.ExpireTime().Format(timestampFormat)),
			pq.QuoteLiteral(strconv.FormatBool(persistent)))
		_, err = tx.Exec(queryString)
		if err != nil {
			if e, ok := err.(pq.Error); ok {
				// This error code means that the uniqueness of ids has been violated
				// We try again in this case.
				if string(e.Code) == "23505" {
					continue
				}
			}
			log.Println(err)
			panic(err)
		}
		// We have the ids so we break and return
		break
	}
	return ses
}

// getSessionInfo pulls the session out of the database.
// No validation is done here. That must be done elsewhere.
func (s sesDataAccess) getSessionInfo(tx *sql.Tx, selectorID, sessionID, encryptedUsername string, maxLifetime time.Duration) (*sessions.Session, error) {
	var dbHash, values, username string
	var expires time.Time
	var persistent bool
	var ses *sessions.Session

	queryString := fmt.Sprintf(getSessionInfo,
		pq.QuoteIdentifier(s.tableName),
		pq.QuoteLiteral(selectorID))
	err := tx.QueryRow(queryString).Scan(&selectorID, &dbHash, &username, &values, &expires, &persistent)
	if err != nil {
		return nil, err
	}
	// If the session is persistent, then we set the expiration to maxLifetime
	if persistent {
		ses = sessions.NewSession(selectorID, sessionID, username, encryptedUsername, s.cookieName, maxLifetime)
	} else {
		ses = sessions.NewSession(selectorID, sessionID, username, encryptedUsername, s.cookieName, 0)
	}
	err = ses.TextToValues(values)
	if err != nil {
		return nil, err
	}
	// Check that the encryptedUsername decrypts to the right thing. Otherwise, sessions is not valid
	if username != ses.Username() || !s.decryptAndCompare(encryptedUsername, ses.Username(), selectorID) {
		return nil, errors.New("Session username is not valid")
	}
	return ses, err
}

func (s sesDataAccess) destroySession(tx *sql.Tx, ses *sessions.Session) {
	queryString := fmt.Sprintf(deleteSession,
		pq.QuoteIdentifier(s.tableName),
		pq.QuoteLiteral(ses.SelectorID()))
	tx.Exec(queryString)
	ses.Destroy()
}

// updateSession indicates that the session is active and the expiration needs to be updated.
func (s sesDataAccess) updateSession(tx *sql.Tx, ses *sessions.Session, maxLifetime time.Duration) {
	queryString := fmt.Sprintf(updateSession,
		pq.QuoteIdentifier(s.tableName),
		pq.QuoteLiteral(ses.Username()),
		pq.QuoteLiteral(ses.ExpireTime().Add(maxLifetime).Format(timestampFormat)),
		pq.QuoteLiteral(ses.ValuesAsText()),
		pq.QuoteLiteral(ses.SelectorID()))
	_, err := tx.Exec(queryString)
	if err != nil {
		panic(err)
	}
	ses.UpdateExpireTime(maxLifetime)
}

// validateSession pulls the info for a session out of the database and checks that the session is valid
// i.e. neither destroyed nor expired, username and encryptedUsername match
func (s sesDataAccess) validateSession(tx *sql.Tx, ses *sessions.Session, maxLifetime time.Duration) error {
	dbSession, err := s.getSessionInfo(tx, ses.SelectorID(), ses.SessionID(), ses.EncryptedUsername(), maxLifetime)
	if err != nil || !ses.Equals(dbSession, s.hashString) {
		s.destroySession(tx, ses)
		return sessionNotInDatabaseError(ses.SelectorID(), s.tableName)
	}

	if !ses.IsValid() {
		s.destroySession(tx, ses)
		log.Printf("%v %v is not valid so we destroyed it", s.tableName, ses.SelectorID())
		return sessionExpiredError(ses.SelectorID(), s.tableName)
	}
	return nil
}

// logUserIntoSession takes care of logging a user into a session.
// This includes things like changing the encrypted username data.
func (s sesDataAccess) logUserIntoSession(tx *sql.Tx, ses *sessions.Session, username string, maxLifetime time.Duration) {
	ses.LogUserIn(username, s.encrypt(username, ses.SelectorID()))
	s.updateSession(tx, ses, maxLifetime)
}

// logUserOut takes care of logging a user into a session.
// This includes things like changing the encrypted username data.
func (s sesDataAccess) logUserOut(tx *sql.Tx, ses *sessions.Session, maxLifetime time.Duration) {
	ses.LogUserOut()
	s.destroySession(tx, ses)
	newSes := s.createSession(tx, "", maxLifetime, false)
	*ses = *newSes
}

// Encryption functions for hiding the username.
func (s sesDataAccess) padToBlockSize(b []byte) []byte {
	// If the padding is already valid, then we shouldn't pad.
	if _, err := s.isValidPadding(b); err == nil {
		return b
	}
	bytesToAdd := s.cipher.BlockSize() - (len(b) % s.cipher.BlockSize())
	return append(b, bytes.Repeat([]byte{byte(bytesToAdd)}, bytesToAdd)...)
}

func (s sesDataAccess) isValidPadding(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return b, errors.New("Invalid padding")
	}
	paddedByte := b[len(b)-1]
	// If the last byte is 0 or greater than the block length, then we know the padding is invalid.
	if paddedByte > byte(s.cipher.BlockSize()) || paddedByte <= 0 {
		return b, errors.New("Invalid padding")
	}
	for i := len(b) - 1; i > len(b)-1-int(paddedByte); i-- {
		if b[i] != paddedByte {
			return b, errors.New("Invalid padding")
		}
	}
	return b[:len(b)-int(paddedByte)], nil
}

func (s sesDataAccess) encrypt(d, selectorID string) string {
	mode := cipher.NewCBCEncrypter(s.cipher, []byte(selectorID))
	b := s.padToBlockSize([]byte(d))
	mode.CryptBlocks(b, b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s sesDataAccess) decrypt(e, selectorID string) string {
	b, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil {
		log.Println(err)
		return ""
	}
	mode := cipher.NewCBCDecrypter(s.cipher, []byte(selectorID))
	mode.CryptBlocks(b, b)
	b, err = s.isValidPadding(b)
	if err != nil {
		log.Println(err)
		return ""
	}
	return string(b)
}

func (s sesDataAccess) decryptAndCompare(e, d, selectorID string) bool {
	return d == s.decrypt(e, selectorID)
}
