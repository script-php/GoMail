package store

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"

	"gomail/logging"
)

// EncodeVERP generates a VERP (Variable Envelope Return Path) bounce address.
// VERP encodes the original recipient in the bounce address so bounces can be
// automatically processed and matched to the original message.
//
// Format: sender_local+v1-<base64url(original_recipient)>@sender_domain
//
// Example:
//
//	Sender: newsletter@example.com
//	Recipient: user@external.com
//	VERP: newsletter+v1-dXNlckBleHRlcm5hbC5jb20@example.com
//
// When a bounce arrives at the VERP address, we can extract the original recipient.
func (db *DB) EncodeVERP(sender string, originalRecipient string) (string, error) {
	senderParts := strings.SplitN(sender, "@", 2)
	if len(senderParts) != 2 || senderParts[0] == "" || senderParts[1] == "" {
		logging.Warn(fmt.Sprintf("[store] invalid sender address for VERP encoding: %s", sender))
		return "", fmt.Errorf("invalid sender address: %s", sender)
	}
	senderLocal := senderParts[0]
	senderDomain := senderParts[1]

	recipientParts := strings.SplitN(originalRecipient, "@", 2)
	if len(recipientParts) != 2 || recipientParts[0] == "" || recipientParts[1] == "" || strings.Contains(recipientParts[1], "@") {
		logging.Warn(fmt.Sprintf("[store] invalid recipient address for VERP encoding: %s", originalRecipient))
		return "", fmt.Errorf("invalid recipient address: %s", originalRecipient)
	}
	// Encode the complete recipient. Separators in local parts and hyphens in
	// domains must survive round trips unchanged.
	verpLocal := senderLocal + "+v1-" + base64.RawURLEncoding.EncodeToString([]byte(originalRecipient))
	if len(verpLocal) > 64 {
		return "", fmt.Errorf("VERP local part exceeds 64 octets")
	}
	verpAddress := verpLocal + "@" + senderDomain
	return verpAddress, nil
}

// DecodeVERP extracts the original recipient from a VERP bounce address.
// Returns the original recipient email address.
//
// Example:
//
//	VERP: newsletter+v1-dXNlckBleHRlcm5hbC5jb20@example.com
//	Returns: user@external.com
func (db *DB) DecodeVERP(verpAddress string) (string, error) {
	// Parse the current encoding, then retain decoding support for older queued
	// addresses generated before the v1 format.
	parts := strings.SplitN(verpAddress, "@", 2)
	if len(parts) != 2 {
		logging.Debug(fmt.Sprintf("[store] invalid VERP address format: %s", verpAddress))
		return "", fmt.Errorf("invalid VERP address: %s", verpAddress)
	}

	localPart := parts[0]
	if marker := strings.LastIndex(localPart, "+v1-"); marker >= 0 {
		decoded, err := base64.RawURLEncoding.DecodeString(localPart[marker+4:])
		if err != nil {
			return "", fmt.Errorf("invalid VERP recipient encoding: %w", err)
		}
		recipient := string(decoded)
		pieces := strings.Split(recipient, "@")
		if len(pieces) != 2 || pieces[0] == "" || pieces[1] == "" {
			return "", fmt.Errorf("invalid VERP recipient")
		}
		return recipient, nil
	}
	// senderDomain := parts[1]  // Not needed for decoding

	// Split by + to separate sender_local and encoded recipient
	plusParts := strings.SplitN(localPart, "+", 2)
	if len(plusParts) != 2 {
		logging.Debug(fmt.Sprintf("[store] malformed VERP local part (missing +): %s", localPart))
		return "", fmt.Errorf("invalid VERP local part (missing +): %s", localPart)
	}

	// plusParts[0] is sender_local, plusParts[1] is "recipient_local=recipient_domain"
	encodedRecipient := plusParts[1]

	// Split by = to get recipient local and domain
	equalParts := strings.SplitN(encodedRecipient, "=", 2)
	if len(equalParts) != 2 {
		logging.Debug(fmt.Sprintf("[store] malformed VERP encoded recipient (missing =): %s", encodedRecipient))
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
	if strings.Contains(strings.SplitN(addr, "@", 2)[0], "+v1-") {
		_, err := db.DecodeVERP(addr)
		return err == nil
	}
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

// LookupIssuedVERP accepts only exact bounce addresses present in the outbound
// queue. Pattern matching alone would turn arbitrary lookalike recipients into
// local bounce sinks. The stored recipient also handles older, lossy encodings.
type IssuedVERP struct {
	Recipient string
	Sender    string
}

func (db *DB) LookupIssuedVERP(address string) (*IssuedVERP, error) {
	if !db.IsVERPBounceAddress(address) {
		return nil, nil
	}
	issued := &IssuedVERP{}
	err := db.QueryRow(`SELECT rcpt_to, mail_from FROM outbound_queue WHERE verp_bounce_address = ? AND status <> 'cancelled' ORDER BY id DESC LIMIT 1`, address).Scan(&issued.Recipient, &issued.Sender)
	if err == sql.ErrNoRows {
		err = db.QueryRow(`SELECT recipient, sender FROM issued_verp WHERE address = ?`, address).Scan(&issued.Recipient, &issued.Sender)
		if err == sql.ErrNoRows {
			return nil, nil
		}
	}
	if err != nil {
		return nil, err
	}
	return issued, nil
}
