package handlers

import (
	"net/http"

	"gomail/security"
	"gomail/store"
)

// getSessionAccount returns the authenticated account for the current request.
// Returns nil if not logged in or account not found.
func getSessionAccount(db *store.DB, sm *security.SessionManager, r *http.Request) *store.Account {
	email := sm.GetSession(r)
	if email == "" {
		return nil
	}
	account, _ := db.GetAccountByEmail(email)
	return account
}
