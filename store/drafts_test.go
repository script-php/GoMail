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
	drafts, err := db.GetFolderByType(1, "drafts")
	if err != nil || drafts.TotalCount != 1 {
		t.Fatalf("draft count after save: %+v, %v", drafts, err)
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
	drafts, _ = db.GetFolderByType(1, "drafts")
	if drafts.TotalCount != 0 {
		t.Fatalf("draft count after delete: %+v", drafts)
	}
	expunges, err := db.GetIMAPExpunges(1, drafts.ID, 0)
	if err != nil || len(expunges) != 1 || expunges[0].UID == 0 {
		t.Fatalf("draft expunge history=%#v err=%v", expunges, err)
	}
	msg, _ = db.GetMessage(id, 1)
	if msg != nil {
		t.Fatal("draft was not deleted")
	}
}

func TestDeleteDraftRollsBackWhenFolderCountFails(t *testing.T) {
	db := mailboxDB(t)
	id, err := db.SaveDraft(1, 0, "user1@drafts.example", "to@example.net", "", "draft", "body")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_draft_count BEFORE UPDATE OF total_count ON folders
		WHEN OLD.total_count > 0 BEGIN SELECT RAISE(FAIL, 'draft count unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteDraft(1, id); err == nil {
		t.Fatal("draft deletion committed without folder count")
	}
	message, err := db.GetMessage(id, 1)
	if err != nil || message == nil {
		t.Fatalf("failed deletion removed draft: %+v, %v", message, err)
	}
}

func TestDraftSaveRequiresDraftsFolderAndRestoreReturnsThere(t *testing.T) {
	db := mailboxDB(t)
	id, err := db.SaveDraft(1, 0, "one@drafts.example", "to@example.net", "", "original", "original body")
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := db.GetFolderByType(1, "inbox")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ApplyMessageAction(1, []int64{id}, "move", inbox.ID); err == nil {
		t.Fatal("moved a draft out of Drafts")
	}
	if err := db.ApplyMessageAction(1, []int64{id}, "trash", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveDraft(1, id, "one@drafts.example", "to@example.net", "", "wrong", "wrong body"); err == nil {
		t.Fatal("updated a trashed draft")
	}
	msg, err := db.GetMessage(id, 1)
	if err != nil || msg == nil || msg.Subject != "original" || msg.TextBody != "original body" {
		t.Fatalf("failed saves changed the draft: %+v %v", msg, err)
	}
	if err := db.ApplyMessageAction(1, []int64{id}, "restore", 0); err != nil {
		t.Fatal(err)
	}
	drafts, err := db.GetFolderByType(1, "drafts")
	if err != nil {
		t.Fatal(err)
	}
	msg, err = db.GetMessage(id, 1)
	if err != nil || msg == nil || msg.IsDeleted || msg.FolderID == nil || *msg.FolderID != drafts.ID {
		t.Fatalf("restored draft not in Drafts: %+v %v", msg, err)
	}
	if _, err := db.SaveDraft(1, id, "one@drafts.example", "to@example.net", "", "updated", "updated body"); err != nil {
		t.Fatalf("cannot save restored draft: %v", err)
	}
}
