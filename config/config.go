package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Config holds all server configuration parsed from config.toml.
type Config struct {
	Server   ServerConfig   `toml:"server"`
	SMTP     SMTPConfig     `toml:"smtp"`
	TLS      TLSConfig      `toml:"tls"`
	DKIM     DKIMConfig     `toml:"dkim"`
	Store    StoreConfig    `toml:"store"`
	Web      WebConfig      `toml:"web"`
	Delivery DeliveryConfig `toml:"delivery"`
	DNS      DNSConfig      `toml:"dns"`
	Security SecurityConfig `toml:"security"`
	Logging  LoggingConfig  `toml:"logging"`
}

type ServerConfig struct {
	Hostname   string `toml:"hostname"`
	Domain     string `toml:"domain"`
	AdminEmail string `toml:"admin_email"`
}

type SMTPConfig struct {
	ListenAddr     string          `toml:"listen_addr"`
	MaxMessageSize int64           `toml:"max_message_size"`
	MaxRecipients  int             `toml:"max_recipients"`
	ReadTimeout    int             `toml:"read_timeout"`
	WriteTimeout   int             `toml:"write_timeout"`
	MaxConnections int             `toml:"max_connections"`
	RateLimit      RateLimitConfig `toml:"ratelimit"`
}

type RateLimitConfig struct {
	ConnectionsPerMinute int `toml:"connections_per_minute"`
	MessagesPerMinute    int `toml:"messages_per_minute"`
}

type TLSConfig struct {
	Mode       string `toml:"mode"`
	CertFile   string `toml:"cert_file"`
	KeyFile    string `toml:"key_file"`
	ACMEEmail  string `toml:"acme_email"`
	ACMEDir    string `toml:"acme_dir"`
	MinVersion string `toml:"min_version"`
}

type DKIMConfig struct {
	Selector  string `toml:"selector"`
	KeyPath   string `toml:"key_path"`
	Algorithm string `toml:"algorithm"`
}

type StoreConfig struct {
	DBPath          string `toml:"db_path"`
	AttachmentsPath string `toml:"attachments_path"`
}

type WebConfig struct {
	ListenAddr    string         `toml:"listen_addr"`
	HTTPAddr      string         `toml:"http_addr"`
	SessionSecret string         `toml:"session_secret"`
	SessionMaxAge int            `toml:"session_max_age"`
	Admin         WebAdminConfig `toml:"admin"`
}

type WebAdminConfig struct {
	Username     string `toml:"username"`
	PasswordHash string `toml:"password_hash"`
}

type DeliveryConfig struct {
	QueueWorkers   int   `toml:"queue_workers"`
	RetryIntervals []int `toml:"retry_intervals"`
	MaxRetries     int   `toml:"max_retries"`
}

type DNSConfig struct {
	CacheTTL int `toml:"cache_ttl"`
}

type SecurityConfig struct {
	CSRFKey string `toml:"csrf_key"`
}

type LoggingConfig struct {
	Level  string `toml:"level"`
	Format string `toml:"format"`
}

// Load reads and parses config.toml from the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
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
