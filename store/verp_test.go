package store

import "testing"

func TestVERPEncodingRoundTrip(t *testing.T) {
	db := &DB{}
	for _, recipient := range []string{
		"user+tag=notice@north-west.example.net",
		"user@two-part.example.org",
		"a=b+c@sub-domain.example.com",
	} {
		address, err := db.EncodeVERP("sender@example.com", recipient)
		if err != nil {
			t.Fatalf("encode %q: %v", recipient, err)
		}
		decoded, err := db.DecodeVERP(address)
		if err != nil || decoded != recipient {
			t.Fatalf("decode %q = %q, %v", address, decoded, err)
		}
	}
}
