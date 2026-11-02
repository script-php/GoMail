package mailclient

import (
	"bytes"
	"net/textproto"
	"strings"
	"testing"
)

func TestIMAPMIMEBodyStructureAndSections(t *testing.T) {
	raw := []byte("From: sender@example.net\r\nSubject: multipart fixture\r\nX-Hidden: secret\r\nContent-Type: multipart/mixed; boundary=outer\r\n\r\n" +
		"--outer\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\nhello text\r\n" +
		"--outer\r\nContent-Type: application/octet-stream; name=file.bin\r\nContent-Disposition: attachment; filename=file.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nYWJj\r\n--outer--\r\n")
	entity, err := parseIMAPMIME(raw)
	if err != nil {
		t.Fatal(err)
	}
	structure := entity.bodyStructure(true)
	for _, expected := range []string{`"MIXED"`, `"TEXT" "PLAIN"`, `"APPLICATION" "OCTET-STREAM"`, `"ATTACHMENT"`} {
		if !strings.Contains(structure, expected) {
			t.Fatalf("BODYSTRUCTURE missing %s: %s", expected, structure)
		}
	}
	part, ok := parseIMAPBodyRequest("BODY.PEEK[1]")
	if !ok {
		t.Fatal("part request rejected")
	}
	data, err := entity.section(part, raw)
	if err != nil || !bytes.Equal(data, []byte("hello text")) && !bytes.Equal(data, []byte("hello text\r\n")) {
		t.Fatalf("part 1=%q err=%v", data, err)
	}
	headers, ok := parseIMAPBodyRequest("BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)]")
	if !ok {
		t.Fatal("HEADER.FIELDS request rejected")
	}
	data, err = entity.section(headers, raw)
	if err != nil || !bytes.Contains(data, []byte("From: sender@example.net")) || !bytes.Contains(data, []byte("Subject: multipart fixture")) || bytes.Contains(data, []byte("X-Hidden")) {
		t.Fatalf("filtered headers=%q err=%v", data, err)
	}
	partial, ok := parseIMAPBodyRequest("BODY.PEEK[1]<2.4>")
	if !ok || string(applyIMAPPartial([]byte("hello text"), partial)) != "llo " || partial.label != "BODY[1]<2>" {
		t.Fatalf("partial=%#v", partial)
	}
}

func TestIMAPMIMEPartHeadersPreserveOriginalOctets(t *testing.T) {
	partHeader := "cOnTeNt-TyPe:\ttext/plain;\r\n\tcharset=utf-8\r\nX-Custom:  first  value\r\n\r\n"
	raw := []byte("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=outer\r\n\r\n" +
		"--outer\r\n" + partHeader + "hello\r\n--outer--\r\n")
	entity, err := parseIMAPMIME(raw)
	if err != nil {
		t.Fatal(err)
	}
	request, ok := parseIMAPBodyRequest("BODY.PEEK[1.MIME]")
	if !ok {
		t.Fatal("MIME section request rejected")
	}
	got, err := entity.section(request, raw)
	if err != nil || string(got) != partHeader {
		t.Fatalf("part MIME headers changed: got %q, want %q, err=%v", got, partHeader, err)
	}
}

func TestIMAPMessageRFC822StructureAndEnvelope(t *testing.T) {
	raw := []byte("Content-Type: message/rfc822\r\nContent-Transfer-Encoding: 7bit\r\n\r\n" +
		"Date: Thu, 16 Oct 2026 12:00:00 +0000\r\nFrom: Alice <alice@example.net>, Bob <bob@example.org>\r\nTo: User <user@example.com>\r\nSubject: nested\r\nMessage-ID: <nested@example.net>\r\nContent-Type: text/plain\r\n\r\nnested body\r\n")
	entity, err := parseIMAPMIME(raw)
	if err != nil {
		t.Fatal(err)
	}
	structure := entity.bodyStructure(true)
	for _, expected := range []string{`"MESSAGE" "RFC822"`, `"alice" "example.net"`, `"bob" "example.org"`, `"TEXT" "PLAIN"`} {
		if !strings.Contains(structure, expected) {
			t.Fatalf("nested BODYSTRUCTURE missing %s: %s", expected, structure)
		}
	}
	request, _ := parseIMAPBodyRequest("BODY.PEEK[1.TEXT]")
	data, err := entity.section(request, raw)
	if err != nil || string(data) != "nested body\r\n" {
		t.Fatalf("nested text=%q err=%v", data, err)
	}
	header := textproto.MIMEHeader{"From": {"Alice <alice@example.net>, Bob <bob@example.org>"}, "To": {"user@example.com"}}
	envelope := imapEnvelopeHeader(header)
	if !strings.Contains(envelope, `"alice" "example.net"`) || !strings.Contains(envelope, `"bob" "example.org"`) {
		t.Fatalf("multi-address envelope=%s", envelope)
	}
}

func TestIMAPEnvelopeQuotedLocalPart(t *testing.T) {
	for _, tc := range []struct{ address, mailbox string }{
		{`"a@b"@example.test`, `a@b`},
		{`"a\"@b"@example.test`, `a"@b`},
	} {
		mailbox, host, ok := splitIMAPMailbox(tc.address)
		if !ok || mailbox != tc.mailbox || host != "example.test" {
			t.Fatalf("split %q => %q, %q, %v", tc.address, mailbox, host, ok)
		}
	}
	envelope := imapEnvelopeHeader(textproto.MIMEHeader{"From": {`"a@b"@example.test`}})
	if !strings.Contains(envelope, `(NIL NIL "a@b" "example.test")`) {
		t.Fatalf("quoted local-part envelope=%s", envelope)
	}
}

func TestParseFetchItemsKeepsBodySectionsTogether(t *testing.T) {
	items := parseFetchItems(`(UID BODYSTRUCTURE BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT)] BODY.PEEK[1]<0.12>)`)
	want := []string{"UID", "BODYSTRUCTURE", "BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT)]", "BODY.PEEK[1]<0.12>"}
	if strings.Join(items, "|") != strings.Join(want, "|") {
		t.Fatalf("items=%q want=%q", items, want)
	}
	for _, malformed := range []string{`(BODY.PEEK[1]`, `BODY.PEEK[1]]`, `BODY.PEEK[HEADER.FIELDS (FROM)] extra)`} {
		if got := parseFetchItems(malformed); got != nil {
			t.Fatalf("accepted malformed items %q: %q", malformed, got)
		}
	}
}
