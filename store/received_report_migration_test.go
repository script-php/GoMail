package store

import (
	"database/sql"
	"testing"
)

func TestReceivedReportDomainUniquenessUpgradePreservesHistory(t *testing.T) {
	root := t.TempDir()
	path := root + "/mail.db"
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`CREATE TABLE received_reports (id INTEGER PRIMARY KEY AUTOINCREMENT,account_id INTEGER NOT NULL,source_message_id INTEGER NOT NULL,dedupe_key TEXT NOT NULL UNIQUE,kind TEXT NOT NULL,report_domain TEXT NOT NULL,submitter TEXT NOT NULL,report_id TEXT NOT NULL,period_start TEXT NOT NULL,period_end TEXT NOT NULL,successes INTEGER NOT NULL DEFAULT 0,failures INTEGER NOT NULL DEFAULT 0,payload_json TEXT NOT NULL,received_at DATETIME NOT NULL DEFAULT (datetime('now')),UNIQUE(account_id,source_message_id,kind))`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`INSERT INTO received_reports(account_id,source_message_id,dedupe_key,kind,report_domain,submitter,report_id,period_start,period_end,payload_json) VALUES(1,7,'old-key','tls-rpt','first.test','sender','id-1','start','end','{}')`)
	if err != nil {
		t.Fatal(err)
	}
	legacy.Close()
	db, err := Open(path, root+"/attachments")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	inserted, err := db.SaveReceivedReport(ReceivedReport{AccountID: 1, SourceMessageID: 7, Kind: "tls-rpt", ReportDomain: "second.test", Submitter: "sender", ReportID: "id-1", PeriodStart: "start", PeriodEnd: "end", PayloadJSON: "{}"})
	if err != nil || !inserted {
		t.Fatalf("second domain inserted=%v err=%v", inserted, err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM received_reports`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("history count=%d err=%v", count, err)
	}
}
