package store

import "time"

// Domain represents a mail domain managed by this server.
type Domain struct {
	ID                     int64     `json:"id"`
	Domain                 string    `json:"domain"`
	IsActive               bool      `json:"is_active"`
	DKIMSelector           string    `json:"dkim_selector"`
	DKIMAlgorithm          string    `json:"dkim_algorithm"`
	DKIMPrivateKey         string    `json:"-"`
	DKIMPublicKey          string    `json:"dkim_public_key"`
	RequireTLS             bool      `json:"require_tls"`                  // Fail delivery if TLS unavailable (RFC 8689)
	DANEEnforcement        string    `json:"dane_enforcement"`             // "disabled" (default), "optional" (log only), "required" (fail)
	GreylistingEnabled     bool      `json:"greylisting_enabled"`          // Enable greylisting for this domain
	GreylistingDelayMins   int       `json:"greylisting_delay_minutes"`    // Minutes to wait before accepting from new sender triplet
	TarpittingEnabled      bool      `json:"tarpitting_enabled"`           // Enable tarpitting for this domain
	TarpittingMaxDelaySecs int       `json:"tarpitting_max_delay_seconds"` // Max delay in seconds for repeated failures
	CreatedAt              time.Time `json:"created_at"`
}

// Account represents a user mailbox.
type Account struct {
	ID           int64     `json:"id"`
	DomainID     int64     `json:"domain_id"`
	Email        string    `json:"email"`
	DisplayName  string    `json:"display_name"`
	PasswordHash string    `json:"-"`
	IsAdmin      bool      `json:"is_admin"`
	IsActive     bool      `json:"is_active"`
	QuotaBytes   int64     `json:"quota_bytes"`
	CreatedAt    time.Time `json:"created_at"`
	// Joined fields (not stored)
	DomainName string `json:"domain_name,omitempty"`
}

// Message represents an email message stored in the database.
type Message struct {
	ID             int64     `json:"id"`
	AccountID      int64     `json:"account_id"`
	FolderID       *int64    `json:"folder_id,omitempty"` // NULL = inbox (for legacy compatibility)
	MessageID      string    `json:"message_id"`
	Direction      string    `json:"direction"` // "inbound" or "outbound"
	MailFrom       string    `json:"mail_from"`
	RcptTo         string    `json:"rcpt_to"`
	FromAddr       string    `json:"from_addr"`
	ToAddr         string    `json:"to_addr"`
	CcAddr         string    `json:"cc_addr"`
	ReplyTo        string    `json:"reply_to"`
	Subject        string    `json:"subject"`
	TextBody       string    `json:"text_body"`
	HTMLBody       string    `json:"html_body"`
	RawHeaders     string    `json:"raw_headers"`
	RawMessage     []byte    `json:"-"`
	Size           int64     `json:"size"`
	HasAttachments bool      `json:"has_attachments"`
	IsRead         bool      `json:"is_read"`
	IsStarred      bool      `json:"is_starred"`
	IsDeleted      bool      `json:"is_deleted"`
	SPFResult      string    `json:"spf_result"`
	DKIMResult     string    `json:"dkim_result"`
	DMARCResult    string    `json:"dmarc_result"`
	AuthResults    string    `json:"auth_results"`
	MDNRequested   bool      `json:"mdn_requested"` // Sender requested read receipt
	MDNAddress     string    `json:"mdn_address"`   // Where to send MDN
	MDNSent        bool      `json:"mdn_sent"`      // Whether MDN was sent
	ReceivedAt     time.Time `json:"received_at"`
	CreatedAt      time.Time `json:"created_at"`
}

// Attachment represents a file attached to a message.
type Attachment struct {
	ID          int64     `json:"id"`
	MessageID   int64     `json:"message_id"`
	Filename    string    `json:"filename"`
	ContentType string    `json:"content_type"`
	Size        int64     `json:"size"`
	StoragePath string    `json:"storage_path"`
	CreatedAt   time.Time `json:"created_at"`
}

// QueueEntry represents an outbound message waiting for delivery.
type QueueEntry struct {
	ID          int64     `json:"id"`
	MessageID   *int64    `json:"message_id,omitempty"`
	MailFrom    string    `json:"mail_from"`
	RcptTo      string    `json:"rcpt_to"`
	RawMessage  []byte    `json:"-"`
	Attempts    int       `json:"attempts"`
	MaxAttempts int       `json:"max_attempts"`
	NextRetry   time.Time `json:"next_retry"`
	LastError   string    `json:"last_error"`
	Status      string    `json:"status"`
	DSNNotify   string    `json:"dsn_notify"` // DSN NOTIFY flags
	DSNRet      string    `json:"dsn_ret"`    // FULL or HDRS
	DSNEnvID    string    `json:"dsn_envid"`  // Envelope ID
	DSNSent     bool      `json:"dsn_sent"`   // Whether DSN was sent
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
