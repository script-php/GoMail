package delivery

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"path/filepath"
	"strings"
	"testing"

	"gomail/auth"
	"gomail/config"
	"gomail/store"
)

func TestSevenBitMIMESinglePart(t *testing.T) {
	raw := []byte("From: alice@example.test\r\nTo: bob@example.test\r\nSubject: hello\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nHi, café!\r\n")
	converted := sevenBitMIME(raw)
	if containsEightBit(converted) || bytes.Equal(converted, raw) {
		t.Fatalf("message was not converted to seven-bit MIME: %q", converted)
	}
	message, err := mail.ReadMessage(bytes.NewReader(converted))
	if err != nil || message.Header.Get("Content-Transfer-Encoding") != "quoted-printable" {
		t.Fatalf("converted MIME headers: %v, %v", message.Header, err)
	}
	decoded, err := io.ReadAll(quotedprintable.NewReader(message.Body))
	if err != nil || string(decoded) != "Hi, café!\r\n" {
		t.Fatalf("decoded body=%q err=%v", decoded, err)
	}
	if !bytes.Equal(sevenBitMIME(converted), converted) {
		t.Fatal("conversion is not idempotent")
	}
}

func TestSevenBitMIMEMultipartPreservesAttachment(t *testing.T) {
	raw := []byte("From: alice@example.test\r\nTo: bob@example.test\r\nSubject: files\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=outer\r\n\r\n" +
		"--outer\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nCafé\r\n" +
		"--outer\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=a.bin\r\n\r\nAAEC/w==\r\n" +
		"--outer--\r\n")
	converted := sevenBitMIME(raw)
	if containsEightBit(converted) || bytes.Equal(converted, raw) {
		t.Fatalf("multipart message was not converted: %q", converted)
	}
	message, err := mail.ReadMessage(bytes.NewReader(converted))
	if err != nil {
		t.Fatal(err)
	}
	_, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	reader := multipart.NewReader(message.Body, params["boundary"])
	textPart, err := reader.NextRawPart()
	if err != nil || textPart.Header.Get("Content-Transfer-Encoding") != "quoted-printable" {
		t.Fatalf("text part: %v, %v", textPart, err)
	}
	decoded, err := io.ReadAll(quotedprintable.NewReader(textPart))
	if err != nil || string(decoded) != "Café" {
		t.Fatalf("decoded text=%q err=%v", decoded, err)
	}
	attachment, err := reader.NextRawPart()
	if err != nil {
		t.Fatal(err)
	}
	encodedAttachment, err := io.ReadAll(attachment)
	if err != nil || string(encodedAttachment) != "AAEC/w==" || attachment.Header.Get("Content-Transfer-Encoding") != "base64" {
		t.Fatalf("attachment=%q headers=%v err=%v", encodedAttachment, attachment.Header, err)
	}
}

func TestSevenBitMIMEConvertsMultipartWithPreamble(t *testing.T) {
	raw := []byte("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=outer\r\n\r\n" +
		"This is a MIME preamble.\r\n--outer\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nCafé\r\n--outer--\r\n")
	converted := sevenBitMIME(raw)
	if bytes.Equal(converted, raw) || containsEightBit(converted) || !bytes.Contains(converted, []byte("This is a MIME preamble.\r\n--outer\r\n")) {
		t.Fatalf("multipart preamble conversion failed: %q", converted)
	}
	message, err := mail.ReadMessage(bytes.NewReader(converted))
	if err != nil {
		t.Fatal(err)
	}
	reader := multipart.NewReader(message.Body, "outer")
	part, err := reader.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(quotedprintable.NewReader(part))
	if err != nil || string(decoded) != "Café" {
		t.Fatalf("decoded body=%q err=%v", decoded, err)
	}
}

func TestSevenBitMIMEDoesNotAlterExistingSignaturesOrOpaqueParts(t *testing.T) {
	for _, raw := range []string{
		"MIME-Version: 1.0\r\nDKIM-Signature: v=1; b=abc\r\nContent-Transfer-Encoding: 8bit\r\n\r\ncafé",
		"MIME-Version: 1.0\r\nARC-Message-Signature: i=1; b=abc\r\nContent-Transfer-Encoding: 8bit\r\n\r\ncafé",
		"MIME-Version: 1.0\r\nContent-Type: multipart/signed; boundary=outer\r\n\r\n--outer\r\nContent-Type: text/plain\r\n\r\ncafé\r\n--outer--\r\n",
		"MIME-Version: 1.0\r\nSubject: café\r\nContent-Transfer-Encoding: 8bit\r\n\r\ncafé",
		"MIME-Version: 1.0\r\nContent-Transfer-Encoding: base64\r\n\r\ncafé",
		"MIME-Version: 1.0\r\nContent-Transfer-Encoding: binary\r\n\r\ncafé",
		"MIME-Version: 1.0\r\nContent-Transfer-Encoding: 8bit\r\n\r\ncafé\n",
	} {
		if got := sevenBitMIME([]byte(raw)); string(got) != raw {
			t.Fatalf("protected or unsupported message was modified: %q", got)
		}
	}
	if got := sevenBitMIME([]byte("Subject: plain\r\n\r\n" + strings.Repeat("a", 100))); containsEightBit(got) {
		t.Fatal("seven-bit input gained eight-bit bytes")
	}
}

func TestQueueConvertsBeforeDKIMSigning(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	private, public, _, err := auth.GenerateDKIMKeyPair("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateDomain(&store.Domain{Domain: "sender.example", IsActive: true, DKIMSelector: "mail", DKIMAlgorithm: "ed25519", DKIMPrivateKey: private, DKIMPublicKey: public}); err != nil {
		t.Fatal(err)
	}
	q := NewQueue(db, &config.Config{Server: config.ServerConfig{Hostname: "mail.sender.example", Domain: "sender.example"}})
	raw := []byte("From: alice@sender.example\r\nTo: bob@receiver.example\r\nSubject: hello\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nCafé\r\n")
	if err := q.Enqueue("alice@sender.example", []string{"bob@receiver.example"}, raw, 0); err != nil {
		t.Fatal(err)
	}
	var queued []byte
	if err := db.QueryRow(`SELECT raw_message FROM outbound_queue WHERE rcpt_to = ?`, "bob@receiver.example").Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if containsEightBit(queued) || !bytes.Contains(queued, []byte("Content-Transfer-Encoding: quoted-printable")) || !bytes.Contains(queued, []byte("DKIM-Signature:")) {
		t.Fatalf("queued message was not seven-bit and DKIM-signed: %q", queued)
	}
}

func TestSentCopyRetainsWireMessageID(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	private, public, _, err := auth.GenerateDKIMKeyPair("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	domainID, err := db.CreateDomain(&store.Domain{Domain: "sender.example", IsActive: true, DKIMSelector: "mail", DKIMAlgorithm: "ed25519", DKIMPrivateKey: private, DKIMPublicKey: public})
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "alice@sender.example", PasswordHash: "unused", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	q := NewQueue(db, &config.Config{Server: config.ServerConfig{Hostname: "mail.sender.example", Domain: "sender.example"}})
	raw := []byte("Message-ID: <client-123@sender.example>\r\nFrom: alice@sender.example\r\nTo: bob@receiver.example\r\nSubject: hello\r\n\r\nbody\r\n")
	if err := q.Enqueue("alice@sender.example", []string{"bob@receiver.example"}, raw, accountID); err != nil {
		t.Fatal(err)
	}
	var storedID, envID string
	var queued []byte
	if err := db.QueryRow(`SELECT m.message_id, q.dsn_envid, q.raw_message FROM messages m JOIN outbound_queue q ON q.message_id=m.id WHERE m.account_id=?`, accountID).Scan(&storedID, &envID, &queued); err != nil {
		t.Fatal(err)
	}
	if storedID != "client-123@sender.example" || envID != storedID || !bytes.Contains(queued, []byte("Message-ID: <client-123@sender.example>")) {
		t.Fatalf("stored Message-ID=%q ENVID=%q queued header=%q", storedID, envID, queued)
	}
}

func TestSubmissionDSNOptionsPersistPerRecipient(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	private, public, _, err := auth.GenerateDKIMKeyPair("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateDomain(&store.Domain{Domain: "sender.example", IsActive: true, DKIMSelector: "mail", DKIMAlgorithm: "ed25519", DKIMPrivateKey: private, DKIMPublicKey: public}); err != nil {
		t.Fatal(err)
	}
	q := NewQueue(db, &config.Config{Server: config.ServerConfig{Hostname: "mail.sender.example", Domain: "sender.example"}})
	raw := []byte("From: alice@sender.example\r\nTo: bob@receiver.example\r\nSubject: report\r\n\r\nbody\r\n")
	dsn := SubmissionDSN{Notify: []string{"SUCCESS,FAILURE", "NEVER", ""}, OriginalRecipient: []string{"old@receiver.example", "", ""}, Return: "HDRS", EnvelopeID: "order 123"}
	if err := q.EnqueueSubmission("alice@sender.example", []string{"bob@receiver.example", "carol@receiver.example", "dave@receiver.example"}, dsn, raw, 0); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ recipient, notify, original string }{
		{"bob@receiver.example", "SUCCESS,FAILURE", "old@receiver.example"},
		{"carol@receiver.example", "NEVER", "carol@receiver.example"},
		{"dave@receiver.example", "", "dave@receiver.example"},
	} {
		var notify, ret, envID, original string
		if err := db.QueryRow(`SELECT dsn_notify,dsn_ret,dsn_envid,original_recipient FROM outbound_queue WHERE rcpt_to=?`, tc.recipient).Scan(&notify, &ret, &envID, &original); err != nil {
			t.Fatal(err)
		}
		if notify != tc.notify || ret != "HDRS" || envID != "order 123" || original != tc.original {
			t.Errorf("%s: notify=%q ret=%q envid=%q original=%q", tc.recipient, notify, ret, envID, original)
		}
	}
}
