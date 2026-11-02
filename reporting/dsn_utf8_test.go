package reporting

import (
	"strings"
	"testing"
)

func TestDSNPreservesUTF8ORCPTTypeInSevenBitReport(t *testing.T) {
	message, err := BuildDSNMessage("mail.example.test", "alice@example.test", "utf-8;josé+tag@example.test", "sender@example.test", "delivered", "delivered", 250, "", "HDRS", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(message, `Original-Recipient: utf-8; jos\x{E9}\x{2B}tag@example.test`) {
		t.Fatal("UTF-8 original recipient lost its address type or safe encoding")
	}
}
