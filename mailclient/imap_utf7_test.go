package mailclient

import "testing"

func TestIMAPModifiedUTF7(t *testing.T) {
	for _, value := range []string{"Inbox", "A&B", "Proiecte/Română", "日本語", "Résumé 📬"} {
		encoded := encodeIMAPMailbox(value)
		decoded, err := decodeIMAPMailbox(encoded)
		if err != nil || decoded != value {
			t.Fatalf("%q -> %q -> %q, %v", value, encoded, decoded, err)
		}
	}
	for _, invalid := range []string{"&", "&abc", "&A-", "raw-é"} {
		if _, err := decodeIMAPMailbox(invalid); err == nil {
			t.Fatalf("accepted invalid modified UTF-7 %q", invalid)
		}
	}
}
