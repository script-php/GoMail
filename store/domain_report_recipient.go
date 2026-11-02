package store

import (
	"database/sql"
	"fmt"
)

// DomainReportRecipient returns the configured local mailbox. A zero ID means
// the domain uses the default postmaster destination.
func (db *DB) DomainReportRecipient(domainID int64) (int64, string, error) {
	var accountID int64
	var email string
	err := db.QueryRow(`SELECT r.account_id,a.email FROM domain_report_recipients r JOIN accounts a ON a.id=r.account_id WHERE r.domain_id=?`, domainID).Scan(&accountID, &email)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, "", nil
		}
		return 0, "", err
	}
	return accountID, email, nil
}

func (db *DB) SetDomainReportRecipient(domainID, accountID int64) error {
	if accountID == 0 {
		_, err := db.Exec(`DELETE FROM domain_report_recipients WHERE domain_id=?`, domainID)
		return err
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM accounts a JOIN domains d ON d.id=a.domain_id WHERE d.id=? AND d.is_active=1 AND a.id=? AND a.is_active=1`, domainID, accountID).Scan(&count); err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("select an active mailbox on this domain")
	}
	_, err := db.ExecuteUpsert(
		`INSERT INTO domain_report_recipients(domain_id,account_id) VALUES(?,?) ON CONFLICT(domain_id) DO UPDATE SET account_id=excluded.account_id`,
		`INSERT INTO domain_report_recipients(domain_id,account_id) VALUES(?,?) ON DUPLICATE KEY UPDATE account_id=VALUES(account_id)`, domainID, accountID)
	return err
}
