package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SMTPAuthMode is a bit set: password=1, app credential=2, both=3.
type SMTPAuthMode string

const (
	SMTPAuthDisabled SMTPAuthMode = "disabled"
	SMTPAuthPassword SMTPAuthMode = "password"
	SMTPAuthApp      SMTPAuthMode = "app"
	SMTPAuthBoth     SMTPAuthMode = "both"
)

func (m SMTPAuthMode) mask() int {
	switch m {
	case SMTPAuthPassword:
		return 1
	case SMTPAuthApp:
		return 2
	case SMTPAuthBoth:
		return 3
	default:
		return 0
	}
}

func ValidSMTPAuthMode(mode SMTPAuthMode, admin bool) bool {
	return mode == SMTPAuthPassword || mode == SMTPAuthApp || mode == SMTPAuthBoth || (!admin && mode == SMTPAuthDisabled)
}

func (db *DB) SMTPAdminAuthMode() (SMTPAuthMode, error) {
	var mode SMTPAuthMode
	err := db.QueryRow(`SELECT mode FROM smtp_auth_policy WHERE id=1`).Scan(&mode)
	if errors.Is(err, sql.ErrNoRows) {
		return SMTPAuthBoth, nil // Preserve existing SMTP password logins.
	}
	if err == nil && !ValidSMTPAuthMode(mode, true) {
		return "", fmt.Errorf("invalid SMTP administrator authentication policy")
	}
	return mode, err
}

func (db *DB) SetSMTPAdminAuthMode(mode SMTPAuthMode) error {
	if !ValidSMTPAuthMode(mode, true) {
		return fmt.Errorf("invalid SMTP administrator authentication policy")
	}
	_, err := db.ExecuteUpsert(
		`INSERT INTO smtp_auth_policy(id,mode) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET mode=excluded.mode`,
		`INSERT INTO smtp_auth_policy(id,mode) VALUES(1,?) ON DUPLICATE KEY UPDATE mode=VALUES(mode)`, mode)
	return err
}

func (db *DB) SMTPUserAuthMode(accountID int64) (SMTPAuthMode, error) {
	var mode SMTPAuthMode
	err := db.QueryRow(`SELECT mode FROM smtp_user_auth_policy WHERE account_id=?`, accountID).Scan(&mode)
	if errors.Is(err, sql.ErrNoRows) {
		return SMTPAuthBoth, nil
	}
	if err == nil && !ValidSMTPAuthMode(mode, false) {
		return "", fmt.Errorf("invalid SMTP user authentication policy")
	}
	return mode, err
}

func (db *DB) SetSMTPUserAuthMode(accountID int64, mode SMTPAuthMode) error {
	if !ValidSMTPAuthMode(mode, false) {
		return fmt.Errorf("invalid SMTP user authentication policy")
	}
	admin, err := db.SMTPAdminAuthMode()
	if err != nil {
		return err
	}
	if mode.mask() & ^admin.mask() != 0 {
		return fmt.Errorf("selected SMTP login method is not allowed by the administrator")
	}
	_, err = db.ExecuteUpsert(
		`INSERT INTO smtp_user_auth_policy(account_id,mode) VALUES(?,?) ON CONFLICT(account_id) DO UPDATE SET mode=excluded.mode`,
		`INSERT INTO smtp_user_auth_policy(account_id,mode) VALUES(?,?) ON DUPLICATE KEY UPDATE mode=VALUES(mode)`, accountID, mode)
	return err
}

func (db *DB) SMTPAllowedCredentials(accountID int64) (password, app bool, err error) {
	admin, err := db.SMTPAdminAuthMode()
	if err != nil {
		return false, false, err
	}
	user, err := db.SMTPUserAuthMode(accountID)
	if err != nil {
		return false, false, err
	}
	allowed := admin.mask() & user.mask()
	return allowed&1 != 0, allowed&2 != 0, nil
}

type SMTPAppPassword struct {
	ID         int64
	Name       string
	CreatedAt  time.Time
	LastUsedAt sql.NullTime
}

func (db *DB) ListSMTPAppPasswords(accountID int64) ([]SMTPAppPassword, error) {
	rows, err := db.Query(`SELECT id,name,created_at,last_used_at FROM smtp_app_passwords WHERE account_id=? ORDER BY id DESC`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []SMTPAppPassword
	for rows.Next() {
		var credential SMTPAppPassword
		if err := rows.Scan(&credential.ID, &credential.Name, &credential.CreatedAt, &credential.LastUsedAt); err != nil {
			return nil, err
		}
		result = append(result, credential)
	}
	return result, rows.Err()
}

func (db *DB) CreateSMTPAppPassword(accountID int64, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return "", fmt.Errorf("name must contain 1 to 100 characters")
	}
	_, allowed, err := db.SMTPAllowedCredentials(accountID)
	if err != nil {
		return "", err
	}
	if !allowed {
		return "", fmt.Errorf("SMTP app credentials are disabled")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM smtp_app_passwords WHERE account_id=?`, accountID).Scan(&count); err != nil {
		return "", err
	}
	if count >= 20 {
		return "", fmt.Errorf("maximum of 20 app credentials reached")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	token := "gm_" + hex.EncodeToString(secret)
	hash := sha256.Sum256([]byte(token))
	_, err = db.Exec(`INSERT INTO smtp_app_passwords(account_id,name,secret_hash) VALUES(?,?,?)`, accountID, name, hex.EncodeToString(hash[:]))
	if err != nil {
		return "", err
	}
	return token, nil // Shown once; only a hash is stored.
}

func (db *DB) VerifySMTPAppPassword(accountID int64, token string) (int64, error) {
	if len(token) != 67 || !strings.HasPrefix(token, "gm_") {
		return 0, nil
	}
	hash := sha256.Sum256([]byte(token))
	var id int64
	err := db.QueryRow(`SELECT id FROM smtp_app_passwords WHERE account_id=? AND secret_hash=?`, accountID, hex.EncodeToString(hash[:])).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if _, err := db.Exec(`UPDATE smtp_app_passwords SET last_used_at=? WHERE id=? AND account_id=?`, time.Now().UTC(), id, accountID); err != nil {
		return 0, err
	}
	return id, nil
}

func (db *DB) SMTPAppPasswordExists(accountID, id int64) (bool, error) {
	var found int
	err := db.QueryRow(`SELECT 1 FROM smtp_app_passwords WHERE account_id=? AND id=?`, accountID, id).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (db *DB) RevokeSMTPAppPassword(accountID, id int64) error {
	result, err := db.Exec(`DELETE FROM smtp_app_passwords WHERE id=? AND account_id=?`, id, accountID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows
	}
	return nil
}
