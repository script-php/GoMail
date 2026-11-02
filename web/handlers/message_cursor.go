package handlers

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gomail/store"
)

type cursorSigner struct{ key []byte }

type signedMessageCursor struct {
	AccountID int64  `json:"a"`
	Scope     string `json:"s"`
	Direction string `json:"d"`
	Unix      int64  `json:"t"`
	ID        int64  `json:"i"`
}

func newCursorSigner(secret string) *cursorSigner {
	key := []byte(secret)
	if len(key) == 0 {
		key = make([]byte, 32)
		_, _ = rand.Read(key)
	}
	return &cursorSigner{key: key}
}

func (signer *cursorSigner) encode(accountID int64, scope, direction string, message *store.Message) string {
	payload, _ := json.Marshal(signedMessageCursor{AccountID: accountID, Scope: scope, Direction: direction, Unix: message.ReceivedAt.UTC().Unix(), ID: message.ID})
	mac := hmac.New(sha256.New, signer.key)
	_, _ = mac.Write(payload)
	signature := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (signer *cursorSigner) decode(value string, accountID int64, scope string) (*store.MessageCursor, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid cursor")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid cursor")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid cursor")
	}
	mac := hmac.New(sha256.New, signer.key)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return nil, fmt.Errorf("invalid cursor signature")
	}
	var signed signedMessageCursor
	if err := json.Unmarshal(payload, &signed); err != nil || signed.AccountID != accountID || signed.Scope != scope || signed.ID <= 0 || (signed.Direction != "older" && signed.Direction != "newer") {
		return nil, fmt.Errorf("cursor does not match mailbox")
	}
	return &store.MessageCursor{ReceivedAt: time.Unix(signed.Unix, 0).UTC(), ID: signed.ID, Direction: signed.Direction}, nil
}

func directionScope(direction string) string { return "direction:" + direction }
func folderScope(folderID int64) string      { return "folder:" + strconv.FormatInt(folderID, 10) }
func searchScope(query string) string {
	hash := sha256.Sum256([]byte(query))
	return "search:" + base64.RawURLEncoding.EncodeToString(hash[:])
}
