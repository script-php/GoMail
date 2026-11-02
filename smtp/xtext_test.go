package smtp

import "testing"

func TestXTextRoundTrip(t *testing.T) {
	for _, value := range []string{"simple-id", "id+tag=value", "address with space@example.com", "caf\xc3\xa9@example.com"} {
		encoded := encodeXText(value)
		decoded, err := decodeXText(encoded)
		if err != nil || decoded != value {
			t.Fatalf("round trip %q -> %q -> %q, err=%v", value, encoded, decoded, err)
		}
	}
	if got := encodeXText("a+b=c"); got != "a+2Bb+3Dc" {
		t.Fatalf("encoding = %q", got)
	}
	for _, invalid := range []string{"bad+", "bad+0", "bad+GG", "bad=value"} {
		if _, err := decodeXText(invalid); err == nil {
			t.Errorf("accepted invalid xtext %q", invalid)
		}
	}
}

func TestRFC6533Unitext(t *testing.T) {
	for _, tc := range []struct {
		input  string
		native bool
		want   string
	}{
		{`jos\x{E9}\x{2B}tag@example.test`, false, "josé+tag@example.test"},
		{`josé\x{2B}tag@example.test`, true, "josé+tag@example.test"},
	} {
		got, err := decodeUnitext(tc.input, tc.native)
		if err != nil || got != tc.want {
			t.Errorf("decode %q = %q, %v", tc.input, got, err)
		}
	}
	for _, value := range []string{`bad\x{}`, `bad\x{110000}`, `bad\x{D800}`, `bad\x{GG}`, `bad+tag@example.test`, "josé@example.test"} {
		if _, err := decodeUnitext(value, false); err == nil {
			t.Errorf("accepted malformed/non-ASCII legacy ORCPT %q", value)
		}
	}
}

func TestParseESMTPParametersPreservesValues(t *testing.T) {
	params, err := parseESMTPParameters("FROM:<sender@example.com> RET=full ENVID=CaseSensitive+2BID")
	if err != nil {
		t.Fatal(err)
	}
	if params["RET"] != "full" || params["ENVID"] != "CaseSensitive+2BID" {
		t.Fatalf("parameter values were modified: %#v", params)
	}
}
