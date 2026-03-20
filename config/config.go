package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config holds all server configuration parsed from config.json.
type Config struct {
	Server   ServerConfig   `json:"server"`
	SMTP     SMTPConfig     `json:"smtp"`
	TLS      TLSConfig      `json:"tls"`
	DKIM     DKIMConfig     `json:"dkim"`
	Store    StoreConfig    `json:"store"`
	Web      WebConfig      `json:"web"`
	Delivery DeliveryConfig `json:"delivery"`
	DNS      DNSConfig      `json:"dns"`
	Security SecurityConfig `json:"security"`
	Logging  LoggingConfig  `json:"logging"`
}

type ServerConfig struct {
	Hostname   string `json:"hostname"`
	Domain     string `json:"domain"`
	AdminEmail string `json:"admin_email"`
}

type SMTPConfig struct {
	ListenAddr     string          `json:"listen_addr"`
	MaxMessageSize int64           `json:"max_message_size"`
	MaxRecipients  int             `json:"max_recipients"`
	ReadTimeout    int             `json:"read_timeout"`
	WriteTimeout   int             `json:"write_timeout"`
	MaxConnections int             `json:"max_connections"`
	RateLimit      RateLimitConfig `json:"ratelimit"`
}

type RateLimitConfig struct {
	ConnectionsPerMinute int `json:"connections_per_minute"`
	MessagesPerMinute    int `json:"messages_per_minute"`
}

type TLSConfig struct {
	Mode       string `json:"mode"`
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`
	ACMEEmail  string `json:"acme_email"`
	ACMEDir    string `json:"acme_dir"`
	MinVersion string `json:"min_version"`
}

type DKIMConfig struct {
	Selector  string `json:"selector"`
	KeyPath   string `json:"key_path"`
	Algorithm string `json:"algorithm"`
}

type StoreConfig struct {
	DBPath          string `json:"db_path"`
	AttachmentsPath string `json:"attachments_path"`
}

type WebConfig struct {
	ListenAddr    string         `json:"listen_addr"`
	HTTPAddr      string         `json:"http_addr"`
	EnableTLS     *bool          `json:"enable_tls"`
	SessionSecret string         `json:"session_secret"`
	SessionMaxAge int            `json:"session_max_age"`
	Admin         WebAdminConfig `json:"admin"`
}

// IsTLSEnabled returns whether TLS is enabled for the web interface (defaults to true).
func (w *WebConfig) IsTLSEnabled() bool {
	if w.EnableTLS == nil {
		return true
	}
	return *w.EnableTLS
}

type WebAdminConfig struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

type DeliveryConfig struct {
	QueueWorkers   int   `json:"queue_workers"`
	RetryIntervals []int `json:"retry_intervals"`
	MaxRetries     int   `json:"max_retries"`
}

type DNSConfig struct {
	CacheTTL int `json:"cache_ttl"`
}

type SecurityConfig struct {
	CSRFKey string `json:"csrf_key"`
}

type LoggingConfig struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

// Load reads and parses config.json from the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return &cfg, nil
}

// Validate checks that required fields are set and values are sane.
func (c *Config) Validate() error {
	if c.Server.Hostname == "" {
		return fmt.Errorf("server.hostname is required")
	}
	if c.Server.Domain == "" {
		return fmt.Errorf("server.domain is required")
	}
	if c.SMTP.ListenAddr == "" {
		c.SMTP.ListenAddr = ":25"
	}
	if c.SMTP.MaxMessageSize <= 0 {
		c.SMTP.MaxMessageSize = 25 * 1024 * 1024 // 25 MB
	}
	if c.SMTP.MaxRecipients <= 0 {
		c.SMTP.MaxRecipients = 100
	}
	if c.SMTP.ReadTimeout <= 0 {
		c.SMTP.ReadTimeout = 60
	}
	if c.SMTP.WriteTimeout <= 0 {
		c.SMTP.WriteTimeout = 60
	}
	if c.SMTP.MaxConnections <= 0 {
		c.SMTP.MaxConnections = 100
	}
	if c.TLS.Mode == "" {
		c.TLS.Mode = "autocert"
	}
	if c.TLS.Mode != "autocert" && c.TLS.Mode != "manual" {
		return fmt.Errorf("tls.mode must be 'autocert' or 'manual'")
	}
	if c.TLS.Mode == "manual" {
		if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			return fmt.Errorf("tls.cert_file and tls.key_file required when mode is 'manual'")
		}
	}
	if c.DKIM.Selector == "" {
		c.DKIM.Selector = "mail"
	}
	if c.DKIM.Algorithm == "" {
		c.DKIM.Algorithm = "ed25519"
	}
	if c.Store.DBPath == "" {
		c.Store.DBPath = "data/mail.db"
	}
	if c.Store.AttachmentsPath == "" {
		c.Store.AttachmentsPath = "data/attachments"
	}
	if c.Web.EnableTLS == nil {
		t := true
		c.Web.EnableTLS = &t
	}
	if !c.Web.IsTLSEnabled() {
		if c.Web.HTTPAddr == "" {
			c.Web.HTTPAddr = ":80"
		}
	}
	if c.Web.SessionMaxAge <= 0 {
		c.Web.SessionMaxAge = 86400
	}
	if c.Delivery.QueueWorkers <= 0 {
		c.Delivery.QueueWorkers = 4
	}
	if c.Delivery.MaxRetries <= 0 {
		c.Delivery.MaxRetries = 6
	}
	if len(c.Delivery.RetryIntervals) == 0 {
		c.Delivery.RetryIntervals = []int{60, 300, 900, 3600, 14400, 86400}
	}
	if c.DNS.CacheTTL <= 0 {
		c.DNS.CacheTTL = 300
	}
	return nil
}
