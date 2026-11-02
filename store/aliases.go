package store

import (
	"database/sql"
	"fmt"
	"net/mail"
	"strings"
)

type Alias struct {
	Address         string
	TargetAccountID int64
	TargetEmail     string
	OwnerAccountID  int64
}

// GetDeliveryAccount resolves a real mailbox or one local virtual address.
// Authentication must continue to use GetAccountByEmail, never this method.
func (db *DB) GetDeliveryAccount(address string) (*Account, error) {
	account, err := db.GetAccountByEmail(address)
	if err != nil || account != nil {
		return account, err
	}
	var targetID int64
	err = db.QueryRow(`SELECT v.target_account_id FROM aliases v LEFT JOIN accounts o ON o.id=v.owner_account_id WHERE v.address = ? AND (v.owner_account_id IS NULL OR (o.allow_aliases=1 AND o.is_active=1))`, strings.ToLower(address)).Scan(&targetID)
	if err == sql.ErrNoRows {
		parts := strings.SplitN(address, "@", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "postmaster") {
			return nil, nil
		}
		domain, domainErr := db.GetDomainByName(strings.ToLower(parts[1]))
		if domainErr != nil || domain == nil || !domain.IsActive {
			return nil, domainErr
		}
		// Explicit postmaster accounts and aliases take precedence. Otherwise
		// route the required role address to an active administrator.
		var adminID int64
		lookupErr := db.QueryRow(`SELECT a.id FROM accounts a JOIN domains d ON d.id=a.domain_id WHERE a.is_admin=1 AND a.is_active=1 AND d.is_active=1 ORDER BY CASE WHEN d.id=? THEN 0 ELSE 1 END,a.id LIMIT 1`, domain.ID).Scan(&adminID)
		if lookupErr == sql.ErrNoRows {
			return nil, nil
		}
		if lookupErr != nil {
			return nil, lookupErr
		}
		return db.GetAccount(adminID)
	}
	if err != nil {
		return nil, err
	}
	target, err := db.GetAccount(targetID)
	if err != nil || target == nil {
		return nil, err
	}
	return db.GetAccountByEmail(target.Email)
}

func (db *DB) ListAliases() ([]Alias, error) {
	rows, err := db.Query(`SELECT v.address, v.target_account_id, a.email, COALESCE(v.owner_account_id,0) FROM aliases v JOIN accounts a ON a.id=v.target_account_id ORDER BY v.address`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var aliases []Alias
	for rows.Next() {
		var alias Alias
		if err := rows.Scan(&alias.Address, &alias.TargetAccountID, &alias.TargetEmail, &alias.OwnerAccountID); err != nil {
			return nil, err
		}
		aliases = append(aliases, alias)
	}
	return aliases, rows.Err()
}

func (db *DB) CreateAlias(address string, targetID int64) error {
	return db.createAlias(address, targetID, 0)
}

func (db *DB) CreateUserAlias(address string, accountID int64) error {
	address = strings.ToLower(strings.TrimSpace(address))
	parsed, err := mail.ParseAddress(address)
	if err != nil || parsed.Address != address || parsed.Name != "" || len(address) > 254 || strings.Count(address, "@") != 1 {
		return fmt.Errorf("enter a valid email address")
	}
	parts := strings.SplitN(address, "@", 2)
	switch parts[0] {
	case "postmaster", "abuse", "hostmaster", "webmaster", "security", "admin", "administrator", "noreply", "mailer-daemon":
		return fmt.Errorf("this operational address is reserved for administrators")
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	lock := ""
	if db.driver == "mysql" {
		lock = " FOR UPDATE"
	}
	var domainName string
	var active, allowed, domainActive int
	err = tx.QueryRow(`SELECT d.domain,a.is_active,a.allow_aliases,d.is_active FROM accounts a JOIN domains d ON d.id=a.domain_id WHERE a.id=?`+lock, accountID).Scan(&domainName, &active, &allowed, &domainActive)
	if err == sql.ErrNoRows || active != 1 || allowed != 1 || domainActive != 1 {
		return fmt.Errorf("alias permission is disabled")
	}
	if err != nil {
		return err
	}
	if parts[1] != strings.ToLower(domainName) {
		return fmt.Errorf("alias must use your own domain")
	}
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM aliases WHERE owner_account_id=?`, accountID).Scan(&count); err != nil {
		return err
	}
	if count >= 20 {
		return fmt.Errorf("maximum of 20 aliases per account")
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM accounts WHERE LOWER(email)=?`, address).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return fmt.Errorf("an account already uses this address")
	}
	if _, err := tx.Exec(`INSERT INTO aliases(address,target_account_id,owner_account_id) VALUES(?,?,?)`, address, accountID, accountID); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) createAlias(address string, targetID, ownerID int64) error {
	address = strings.ToLower(strings.TrimSpace(address))
	parsed, err := mail.ParseAddress(address)
	if err != nil || parsed.Address != address || parsed.Name != "" || len(address) > 254 || strings.Count(address, "@") != 1 {
		return fmt.Errorf("enter a valid email address")
	}
	parts := strings.SplitN(address, "@", 2)
	domain, err := db.GetDomainByName(parts[1])
	if err != nil {
		return err
	}
	if domain == nil || !domain.IsActive {
		return fmt.Errorf("alias domain must be active and hosted here")
	}
	target, err := db.GetAccount(targetID)
	if err != nil {
		return err
	}
	if target == nil || !target.IsActive {
		return fmt.Errorf("destination must be an active local account")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM accounts WHERE LOWER(email)=?`, address).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return fmt.Errorf("an account already uses this address")
	}
	var owner interface{}
	if ownerID != 0 {
		owner = ownerID
	}
	_, err = db.Exec(`INSERT INTO aliases(address,target_account_id,owner_account_id) VALUES(?,?,?)`, address, targetID, owner)
	return err
}

func (db *DB) ListUserAliases(accountID int64) ([]Alias, error) {
	rows, err := db.Query(`SELECT address FROM aliases WHERE owner_account_id=? ORDER BY address`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var aliases []Alias
	for rows.Next() {
		var alias Alias
		if err := rows.Scan(&alias.Address); err != nil {
			return nil, err
		}
		aliases = append(aliases, alias)
	}
	return aliases, rows.Err()
}

func (db *DB) DeleteUserAlias(address string, accountID int64) error {
	_, err := db.Exec(`DELETE FROM aliases WHERE address=? AND owner_account_id=?`, strings.ToLower(strings.TrimSpace(address)), accountID)
	return err
}

func (db *DB) DeleteAlias(address string) error {
	_, err := db.Exec(`DELETE FROM aliases WHERE address=?`, strings.ToLower(strings.TrimSpace(address)))
	return err
}
