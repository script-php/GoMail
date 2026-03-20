package store

import "time"

// Message represents an email message stored in the database.
type Message struct {
	ID             int64     `json:"id"`
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
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
