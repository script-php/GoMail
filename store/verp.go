package store

import (
	"fmt"
	"strings"
)

// EncodeVERP generates a VERP (Variable Envelope Return Path) bounce address.
// VERP encodes the original recipient in the bounce address so bounces can be
// automatically processed and matched to the original message.
//
// Format: sender_local+recipient_local=recipient_domain@sender_domain
//
// Example:
//
//	Sender: newsletter@example.com
//	Recipient: user@external.com
//	VERP: newsletter+user=external.com@example.com
//
// When a bounce arrives at the VERP address, we can extract the original recipient.
func (db *DB) EncodeVERP(sender string, originalRecipient string) (string, error) {
	senderParts := strings.SplitN(sender, "@", 2)
	if len(senderParts) != 2 {
		return "", fmt.Errorf("invalid sender address: %s", sender)
	}
	senderLocal := senderParts[0]
	senderDomain := senderParts[1]

	recipientParts := strings.SplitN(originalRecipient, "@", 2)
	if len(recipientParts) != 2 {
		return "", fmt.Errorf("invalid recipient address: %s", originalRecipient)
	}
	recipientLocal := recipientParts[0]
	recipientDomain := recipientParts[1]

	// Encode recipient in VERP format: sender_local+recipient_local=recipient_domain@sender_domain
	// Use base36-like encoding for recipient domain to avoid special chars
	// Replace dots with hyphens to avoid abuse
	encodedRecipientDomain := strings.ReplaceAll(recipientDomain, ".", "-")

	verpAddress := fmt.Sprintf("%s+%s=%s@%s", senderLocal, recipientLocal, encodedRecipientDomain, senderDomain)
	return verpAddress, nil
}

// DecodeVERP extracts the original recipient from a VERP bounce address.
// Returns the original recipient email address.
//
// Example:
//
//	VERP: newsletter+user=external-com@example.com
//	Returns: user@external.com
func (db *DB) DecodeVERP(verpAddress string) (string, error) {
	// Parse VERP address: sender_local+recipient_local=recipient_domain@sender_domain
	parts := strings.SplitN(verpAddress, "@", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid VERP address: %s", verpAddress)
	}

	localPart := parts[0]
	// senderDomain := parts[1]  // Not needed for decoding

	// Split by + to separate sender_local and encoded recipient
	plusParts := strings.SplitN(localPart, "+", 2)
	if len(plusParts) != 2 {
		return "", fmt.Errorf("invalid VERP local part (missing +): %s", localPart)
	}

	// plusParts[0] is sender_local, plusParts[1] is "recipient_local=recipient_domain"
	encodedRecipient := plusParts[1]

	// Split by = to get recipient local and domain
	equalParts := strings.SplitN(encodedRecipient, "=", 2)
	if len(equalParts) != 2 {
		return "", fmt.Errorf("invalid VERP encoded recipient (missing =): %s", encodedRecipient)
	}

	recipientLocal := equalParts[0]
	encodedRecipientDomain := equalParts[1]

	// Decode domain (reverse the dot-to-hyphen replacement)
	recipientDomain := strings.ReplaceAll(encodedRecipientDomain, "-", ".")

	originalRecipient := fmt.Sprintf("%s@%s", recipientLocal, recipientDomain)
	return originalRecipient, nil
}

// IsVERPBounceAddress checks if an email address is a VERP-encoded bounce address.
// VERP addresses have the format: local+something=something@domain
func (db *DB) IsVERPBounceAddress(addr string) bool {
	// Must have format: something+something=something@domain
	if !strings.Contains(addr, "+") || !strings.Contains(addr, "=") {
		return false
	}

	parts := strings.SplitN(addr, "@", 2)
	if len(parts) != 2 {
		return false
	}

	localPart := parts[0]
	// Check +...= pattern in local part
	plusIdx := strings.Index(localPart, "+")
	eqIdx := strings.Index(localPart, "=")

	// Must have + before = in local part
	return plusIdx > 0 && eqIdx > plusIdx
}
