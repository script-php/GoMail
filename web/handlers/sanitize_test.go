package handlers

import (
	"strings"
	"testing"
)

func TestSanitizeHTMLAllowlist(t *testing.T) {
	in := `<div onclick="steal()"><script>alert(1)</script><svg onload=x><circle/></svg><a href="javascript:bad" target=x>bad</a><a href="https://example.com">ok</a><img src=x onerror=x><img src="cid:one"><p style="background:url(https://track)">text</p></div>`
	out := sanitizeHTML(in)
	for _, bad := range []string{"script", "alert(1)", "svg", "onclick", "javascript:", "onerror", "background:url", "src=\"x\""} {
		if strings.Contains(strings.ToLower(out), bad) {
			t.Errorf("output contains %q: %s", bad, out)
		}
	}
	for _, good := range []string{"https://example.com", "cid:one", "noopener", "<p>text</p>"} {
		if !strings.Contains(out, good) {
			t.Errorf("output missing %q: %s", good, out)
		}
	}
}
