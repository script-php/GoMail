package store

import "testing"

func TestDraftLifecycleAndOwnership(t *testing.T) {
	db := mailboxDB(t)
	id, err := db.SaveDraft(1, 0, "one@drafts.example", "to@example.net", "", "subject", "body")
	if err != nil {
		t.Fatal(err)
	}
	msg, err := db.GetMessage(id, 1)
	if err != nil || msg == nil || msg.Direction != "draft" || msg.Subject != "subject" {
		t.Fatalf("bad draft: %+v %v", msg, err)
	}
	if _, err = db.SaveDraft(2, id, "two@drafts.example", "attacker@example.net", "", "changed", "changed"); err == nil {
		t.Fatal("cross-account draft update succeeded")
	}
	if _, err = db.SaveDraft(1, id, "one@drafts.example", "new@example.net", "cc@example.net", "updated", "new body"); err != nil {
		t.Fatal(err)
	}
	msg, _ = db.GetMessage(id, 1)
	if msg.ToAddr != "new@example.net" || msg.Subject != "updated" {
		t.Fatalf("draft not updated: %+v", msg)
	}
	if err = db.DeleteDraft(1, id); err != nil {
		t.Fatal(err)
	}
	msg, _ = db.GetMessage(id, 1)
	if msg != nil {
		t.Fatal("draft was not deleted")
	}
}
