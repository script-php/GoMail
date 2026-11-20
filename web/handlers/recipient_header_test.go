package handlers

import (
	"net/mail"
	"strings"
	"testing"
	"time"
)

func TestFormatRecipientHeaderPreservesAddresses(t *testing.T) {
	input := "José <jose@example.test>; zoe@example.net"
	header, err := formatRecipientHeader(input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(header, "=?UTF-8?B?Sm9zw6kgPGpvc2VA") {
		t.Fatalf("encoded the whole mailbox: %q", header)
	}
	addresses, err := mail.ParseAddressList(header)
	if err != nil || len(addresses) != 2 || addresses[0].Address != "jose@example.test" || addresses[0].Name != "José" || addresses[1].Address != "zoe@example.net" {
		t.Fatalf("header=%q addresses=%v err=%v", header, addresses, err)
	}
	utf8Header, err := formatRecipientHeader("zoë@example.net")
	if err != nil || !strings.Contains(utf8Header, "zoë@example.net") || strings.Contains(utf8Header, "=?") {
		t.Fatalf("internationalized address was changed: %q, %v", utf8Header, err)
	}
	if _, err := formatRecipientHeader("a@example.test\r\nBcc: other@example.test"); err == nil {
		t.Fatal("accepted header injection")
	}
}

func TestRecipientHeaderUsesIDNAForASCIILocalPart(t *testing.T) {
	header, err := formatRecipientHeader("Müller <user@bücher.example>")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(header, "<user@xn--bcher-kva.example>") || strings.Contains(header, "user@bücher.example") {
		t.Fatalf("IDNA recipient header = %q", header)
	}
	trace := originatingHeaders(true, "", "mail.example.test", "id@example.test", []string{"user@bücher.example"}, time.Now())
	if !strings.Contains(trace, "for <user@xn--bcher-kva.example>") || strings.Contains(trace, "user@bücher.example") {
		t.Fatalf("IDNA trace field = %q", trace)
	}
	utf8Header, err := formatRecipientHeader("josé@bücher.example")
	if err != nil || !strings.Contains(utf8Header, "josé@bücher.example") {
		t.Fatalf("UTF-8 local part changed: %q, %v", utf8Header, err)
	}
}
