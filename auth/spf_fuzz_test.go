package auth

import "testing"

func FuzzSPFMacroGrammarAndExpansion(f *testing.F) {
	for _, seed := range []string{"%{ir}.%{v}._spf.%{d2}", "%{S}", "%%-%_-%-", "%{d2rr}", "%{p}"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 64<<10 {
			t.Skip()
		}
		if validateMacroString(input, true) == nil {
			ctx := &spfContext{senderIP: "192.0.2.1", localPart: "sender", domain: "example.test", helo: "mx.example.test", receiverDomain: "receiver.example.test", timestamp: 1}
			_ = expandMacros(input, ctx, false)
		}
	})
}
