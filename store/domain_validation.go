package store

import (
	"fmt"
	"strings"
)

// ValidateMailDomain accepts DNS A-labels (including a single-label local
// development domain such as localhost), not Unicode U-labels or a root dot.
func ValidateMailDomain(domain string) error {
	if domain == "" || len(domain) > 253 {
		return fmt.Errorf("domain name must contain 1 to 253 ASCII characters")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid domain label %q", label)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return fmt.Errorf("invalid domain label %q; use DNS A-labels for internationalized names", label)
			}
		}
	}
	return nil
}
