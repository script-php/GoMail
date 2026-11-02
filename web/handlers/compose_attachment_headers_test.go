package handlers

import (
	"mime"
	"strings"
	"testing"
)

func TestComposeAttachmentHeadersRoundTripUnicodeFilename(t *testing.T) {
	filename := "factură 2026.pdf"
	contentType, disposition, err := composeAttachmentHeaders(filename)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(contentType, "=?") || strings.Contains(disposition, "=?") {
		t.Fatalf("RFC 2047 encoded-word used in MIME parameter: %q / %q", contentType, disposition)
	}
	_, typeParams, err := mime.ParseMediaType(contentType)
	if err != nil || typeParams["name"] != filename {
		t.Fatalf("content type=%q params=%v err=%v", contentType, typeParams, err)
	}
	_, dispositionParams, err := mime.ParseMediaType(disposition)
	if err != nil || dispositionParams["filename"] != filename {
		t.Fatalf("disposition=%q params=%v err=%v", disposition, dispositionParams, err)
	}
	for _, invalid := range []string{"", "file\r\nBcc: victim@example.test", strings.Repeat("a", 181)} {
		if _, _, err := composeAttachmentHeaders(invalid); err == nil {
			t.Fatalf("accepted invalid filename %q", invalid)
		}
	}
}
