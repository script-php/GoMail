package store

import (
	"database/sql"
	"time"
)

// LoadMTASTSPolicy returns the last fetched policy, including its absolute
// expiry, so process restarts cannot extend or forget a live policy.
func (db *DB) LoadMTASTSPolicy(domain string) (id, document string, expiry time.Time, err error) {
	err = db.QueryRow(`SELECT policy_id, policy_json, expires_at FROM mta_sts_policy_cache WHERE domain=?`, domain).Scan(&id, &document, &expiry)
	if err == sql.ErrNoRows {
		err = nil
	}
	return
}

func (db *DB) SaveMTASTSPolicy(domain, id, document string, expiry time.Time) error {
	if db.driver == "mysql" {
		_, err := db.Exec(`INSERT INTO mta_sts_policy_cache(domain,policy_id,policy_json,expires_at) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE policy_id=VALUES(policy_id),policy_json=VALUES(policy_json),expires_at=VALUES(expires_at)`, domain, id, document, expiry)
		return err
	}
	_, err := db.Exec(`INSERT INTO mta_sts_policy_cache(domain,policy_id,policy_json,expires_at) VALUES(?,?,?,?) ON CONFLICT(domain) DO UPDATE SET policy_id=excluded.policy_id,policy_json=excluded.policy_json,expires_at=excluded.expires_at`, domain, id, document, expiry)
	return err
}
