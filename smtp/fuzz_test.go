package smtp

import "testing"

func FuzzParseESMTPParameters(f *testing.F) {
	for _, seed := range []string{
		"FROM:<sender@example.test> SIZE=123 BODY=8BITMIME SMTPUTF8",
		"TO:<user@example.test> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;user@example.test",
		"FROM:<> RET=HDRS ENVID=case+2B1",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 64<<10 {
			t.Skip()
		}
		_, _ = parseESMTPParameters(input)
	})
}
