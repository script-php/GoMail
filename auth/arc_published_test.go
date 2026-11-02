package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// Fixtures are selected from ValiMail/arc_test_suite's published draft 12/16
// cases, with its MIT license in testdata. Three draft "Pass" fixtures sign
// ARC headers in AMS h=, forbidden by final RFC 8617 section 4.1.2; the final
// RFC validator must reject those historical fixtures.
func TestPublishedARCDraftVectorsUnderRFC8617(t *testing.T) {
	data, err := os.ReadFile("testdata/arc_published_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name, Message, Expected string
		Records                 map[string]string
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 10 {
		t.Fatal("published vector set unexpectedly small")
	}
	original := lookupARCKey
	defer func() { lookupARCKey = original }()
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			lookupARCKey = func(selector, domain string) (*DKIMRecord, error) {
				record := tc.Records[selector+"._domainkey."+domain]
				if record == "" {
					return nil, fmt.Errorf("missing published key")
				}
				parsed := parseDKIMRecord(strings.ReplaceAll(record, " ", ""))
				if parsed == nil {
					return nil, fmt.Errorf("%w", ErrDKIMInvalidRecord)
				}
				return parsed, nil
			}
			message := strings.ReplaceAll(tc.Message, "\r\n", "\n")
			message = strings.ReplaceAll(message, "\n", "\r\n")
			result := ValidateARCChain([]byte(message))
			expected := strings.ToLower(tc.Expected)
			if expected == "pass" {
				sets := ExtractArcHeaders([]byte(message))
				latest := 0
				for instance := range sets {
					if instance > latest {
						latest = instance
					}
				}
				ams := sets[latest]["message-signature"]
				if colon := strings.IndexByte(ams, ':'); colon >= 0 {
					tags := parseDKIMTags(ams[colon+1:])
					for _, name := range strings.Split(tags["h"], ":") {
						if strings.HasPrefix(strings.ToLower(strings.TrimSpace(name)), "arc-") {
							expected = "fail"
							break
						}
					}
				}
			}
			if result.Status != expected {
				seal := ExtractArcHeaders([]byte(message))[1]["seal"]
				t.Fatalf("got %s, want RFC 8617 %s (draft expected %s): %s; seal d=%q s=%q", result.Status, expected, tc.Expected, result.Details, extractTagValue(seal, "d="), extractTagValue(seal, "s="))
			}
		})
	}
}
