package session

import (
	"errors"
	"fmt"
)

func badDatabaseConnectionError() error {
	return errors.New("The database connection is not valid")
}
func databaseTableCreationError(table string) error {
	return fmt.Errorf("Cannot create %v table in the database", table)
}

func invalidSessionCookie(table string) error {
	return fmt.Errorf("Cookie does not represent a valid %v cookie", table)
}

func invalidSessionError(table string) error {
	return fmt.Errorf("%v is not valid", table)
}

func sessionExpiredError(selectorID, table string) error {
	return fmt.Errorf("The %v ID %v is expired", table, selectorID)
}

func sessionNotInDatabaseError(selectorID, table string) error {
	return fmt.Errorf("%v with selector ID %v was not found in the database", table, selectorID)
}

func noSessionCookieFoundInRequest(table string) error {
	return fmt.Errorf("No %v cookie was found in request", table)
}
