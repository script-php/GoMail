package handlers

import (
	"net/mail"
	"strings"
	"testing"
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
