package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveAttachmentsUsesBoundedSafeExtension(t *testing.T) {
	directory := t.TempDir()
	records, err := SaveAttachments([]ParsedAttachment{{Filename: "payload." + strings.Repeat("x", 300), ContentType: "application/octet-stream", Data: []byte("data")}}, 42, directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || filepath.Ext(records[0].StoragePath) != ".bin" {
		t.Fatalf("unsafe extension was retained: %+v", records)
	}
	if data, err := os.ReadFile(filepath.Join(directory, records[0].StoragePath)); err != nil || string(data) != "data" {
		t.Fatalf("attachment was not written safely: %q %v", data, err)
	}
}

func TestRemoveSavedAttachmentsCleansBatch(t *testing.T) {
	directory := t.TempDir()
	records, err := SaveAttachments([]ParsedAttachment{{Filename: "one.txt", Data: []byte("one")}, {Filename: "two.txt", Data: []byte("two")}}, 7, directory)
	if err != nil {
		t.Fatal(err)
	}
	RemoveSavedAttachments(records, directory)
	for _, record := range records {
		if _, err := os.Stat(filepath.Join(directory, record.StoragePath)); !os.IsNotExist(err) {
			t.Fatalf("attachment %s was not removed: %v", record.StoragePath, err)
		}
	}
}

func TestParseConvertsDeclaredCharsets(t *testing.T) {
	raw := strings.Join([]string{
		"From: sender@example.com",
		"To: user@example.com",
		"Subject: =?ISO-8859-1?Q?Ol=E1?=",
		"Content-Type: text/plain; charset=iso-8859-1",
		"Content-Transfer-Encoding: quoted-printable",
		"",
		"caf=E9",
	}, "\r\n")
	message, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if message.Subject != "Olá" || strings.TrimSpace(message.TextBody) != "café" {
		t.Fatalf("charset conversion failed: subject=%q body=%q", message.Subject, message.TextBody)
	}
}

func TestParseRFC2231FilenameAndNestedRelatedAlternative(t *testing.T) {
	raw := strings.Join([]string{
		"From: sender@example.com",
		"To: user@example.com",
		"Subject: MIME fixture",
		"MIME-Version: 1.0",
		"Content-Type: multipart/related; boundary=outer",
		"",
		"--outer",
		"Content-Type: multipart/alternative; boundary=inner",
		"",
		"--inner",
		"Content-Type: text/plain; charset=windows-1252",
		"Content-Transfer-Encoding: quoted-printable",
		"",
		"price =8010",
		"--inner",
		"Content-Type: text/html; charset=utf-8",
		"",
		"<p>price €10<img src=\"cid:logo@example\"></p>",
		"--inner--",
		"--outer",
		"Content-Type: image/png",
		"Content-ID: <logo@example>",
		"Content-Disposition: inline; filename*0*=UTF-8''logo-%E2%82%AC; filename*1=.png",
		"Content-Transfer-Encoding: base64",
		"",
		"iVBORw0KGgo=",
		"--outer--",
		"",
	}, "\r\n")
	message, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(message.TextBody) != "price €10" || !strings.Contains(message.HTMLBody, "cid:logo@example") {
		t.Fatalf("multipart alternatives not decoded: text=%q html=%q", message.TextBody, message.HTMLBody)
	}
	if len(message.Attachments) != 1 || message.Attachments[0].Filename != "logo-€.png" || message.Attachments[0].ContentType != "image/png" {
		t.Fatalf("related RFC2231 attachment not preserved: %+v", message.Attachments)
	}
}

func TestParseMIMETypeCaseInsensitivityAndEncodedAttachment(t *testing.T) {
	raw := strings.Join([]string{
		"From: sender@example.com",
		"To: user@example.com",
		"Subject: MIME case fixture",
		"MIME-Version: 1.0",
		"Content-Type: Multipart/Mixed; boundary=CaseBoundary",
		"",
		"--CaseBoundary",
		"Content-Type: Text/HTML; charset=UTF-8",
		"Content-Transfer-Encoding: quoted-printable",
		"",
		"<p>Hello =E2=82=AC</p>",
		"--CaseBoundary",
		"Content-Type: Application/Octet-Stream; name=\"=?UTF-8?Q?report-=E2=82=AC.txt?=\"",
		"Content-Disposition: Attachment",
		"Content-Transfer-Encoding: base64",
		"",
		"aGVsbG8gYXR0YWNobWVudA==",
		"--CaseBoundary--",
		"",
	}, "\r\n")
	message, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(message.HTMLBody, "Hello €") || message.TextBody != "Hello €" {
		t.Fatalf("case-insensitive HTML part not parsed: text=%q html=%q", message.TextBody, message.HTMLBody)
	}
	if len(message.Attachments) != 1 || message.Attachments[0].Filename != "report-€.txt" || string(message.Attachments[0].Data) != "hello attachment" {
		t.Fatalf("encoded attachment not parsed: %+v", message.Attachments)
	}
}

func TestParseRejectsExcessiveMIMENesting(t *testing.T) {
	var body strings.Builder
	for i := 0; i < 32; i++ {
		boundary := fmt.Sprintf("b%d", i)
		body.WriteString("Content-Type: multipart/mixed; boundary=" + boundary + "\r\n\r\n")
		body.WriteString("--" + boundary + "\r\n")
	}
	body.WriteString("Content-Type: text/plain\r\n\r\ncontent\r\n")
	for i := 31; i >= 0; i-- {
		body.WriteString(fmt.Sprintf("--b%d--\r\n", i))
	}
	raw := "From: sender@example.com\r\nContent-Type: multipart/mixed; boundary=b0\r\n\r\n" + strings.TrimPrefix(body.String(), "Content-Type: multipart/mixed; boundary=b0\r\n\r\n")
	message, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if message.TextBody == "content" {
		t.Fatal("parser traversed MIME nesting beyond its safety limit")
	}
}
