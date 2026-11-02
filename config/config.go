package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/mail"
	"os"
	"strings"

	"gomail/logging"
)

// Config holds all server configuration parsed from config.json.
type Config struct {
	Server          ServerConfig          `json:"server"`
	SMTP            SMTPConfig            `json:"smtp"`
	TLS             TLSConfig             `json:"tls"`
	DKIM            DKIMConfig            `json:"dkim"`
	Store           StoreConfig           `json:"store"`
	Web             WebConfig             `json:"web"`
	Mail            MailConfig            `json:"mail"`
	Delivery        DeliveryConfig        `json:"delivery"`
	DNS             DNSConfig             `json:"dns"`
	Security        SecurityConfig        `json:"security"`
	MDN             MDNConfig             `json:"mdn"`
	DMARC           DMARCConfig           `json:"dmarc"`
	TLSRPT          TLSRPTConfig          `json:"tls_rpt"`
	Clients         MailClientsConfig     `json:"mail_clients"`
	Logging         LoggingConfig         `json:"logging"`
	Metrics         MetricsConfig         `json:"metrics"`
	StoragePressure StoragePressureConfig `json:"storage_pressure"`
	OutboundLimits  OutboundLimitsConfig  `json:"outbound_limits"`
}

// MailClientsConfig controls the optional protocols used by desktop and mobile
// mail clients. The master switch is intentionally false by default.
type MailClientsConfig struct {
	Enabled        bool                `json:"enabled"`
	IMAP           ClientServiceConfig `json:"imap"`
	POP3           ClientServiceConfig `json:"pop3"`
	Submission     ClientServiceConfig `json:"submission"`
	ReadTimeout    int                 `json:"read_timeout"`
	WriteTimeout   int                 `json:"write_timeout"`
	MaxConnections int                 `json:"max_connections"`
	AuthAttempts   int                 `json:"auth_attempts_per_minute"`
}

type ClientServiceConfig struct {
	Enabled    *bool  `json:"enabled"`
	ListenAddr string `json:"listen_addr"`
}

func (s ClientServiceConfig) IsEnabled(master bool) bool {
	if !master {
		return false
	}
	if s.Enabled == nil {
		return true
	}
	return *s.Enabled
}

type ServerConfig struct {
	Hostname        string `json:"hostname"`
	Domain          string `json:"domain"`
	TLSReportSender string `json:"tls_report_sender"`
	DSNSender       string `json:"dsn_sender"`
}

func (s ServerConfig) TLSReportSenderAddress() string {
	if s.TLSReportSender != "" {
		return s.TLSReportSender
	}
	return "noreply-smtp-tls-reporting@" + s.Domain
}

func (s ServerConfig) DSNSenderAddress() string {
	if s.DSNSender != "" {
		return s.DSNSender
	}
	return "Mailer-Daemon@" + s.Domain
}

func validateOperationalSender(field, address, domain string) error {
	if address == "" {
		return nil
	}
	parsed, err := mail.ParseAddress(address)
	if err != nil || parsed.Name != "" || parsed.Address != address || strings.ContainsAny(address, "\r\n") {
		return fmt.Errorf("%s must be one plain email address", field)
	}
	parts := strings.Split(address, "@")
	if len(parts) != 2 || !strings.EqualFold(parts[1], domain) {
		return fmt.Errorf("%s must use server.domain", field)
	}
	return nil
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
	DefaultSelector  string `json:"default_selector"`
	DefaultAlgorithm string `json:"default_algorithm"`
	KeysDir          string `json:"keys_dir"`
}

type StoreConfig struct {
	Database        string      `json:"database"`
	MySQL           MySQLConfig `json:"mysql"`
	DBPath          string      `json:"db_path"`
	AttachmentsPath string      `json:"attachments_path"`
}

// MySQLConfig configures the optional MySQL backend. Passwords are never logged.
type MySQLConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Name     string `json:"name"`
	TLS      string `json:"tls"` // "false" for local connections, "true" for verified TLS
}

func (s *StoreConfig) Validate() error {
	s.Database = strings.ToLower(strings.TrimSpace(s.Database))
	if s.Database == "" {
		s.Database = "sqlite"
	}
	if s.Database != "sqlite" && s.Database != "mysql" {
		return fmt.Errorf("store.database must be 'sqlite' or 'mysql'")
	}
	if s.DBPath == "" {
		s.DBPath = "data/mail.db"
	}
	if s.AttachmentsPath == "" {
		s.AttachmentsPath = "data/attachments"
	}
	if s.Database == "mysql" {
		m := &s.MySQL
		if m.Host == "" {
			m.Host = "127.0.0.1"
		}
		if m.Port == 0 {
			m.Port = 3306
		}
		if m.Port < 1 || m.Port > 65535 {
			return fmt.Errorf("store.mysql.port must be between 1 and 65535")
		}
		if m.User == "" || m.Name == "" {
			return fmt.Errorf("store.mysql.user and store.mysql.name are required")
		}
		if len(m.Name) > 64 || strings.ContainsAny(m.Name, "/\\.\x00") {
			return fmt.Errorf("invalid store.mysql.name")
		}
		if m.TLS == "" {
			m.TLS = "false"
		}
		if m.TLS != "false" && m.TLS != "true" {
			return fmt.Errorf("store.mysql.tls must be 'false' or 'true'")
		}
	}
	return nil
}

type WebConfig struct {
	ListenAddr      string         `json:"listen_addr"`
	HTTPAddr        string         `json:"http_addr"`
	EnableTLS       *bool          `json:"enable_tls"`
	SessionSecret   string         `json:"session_secret"`
	SessionMaxAge   int            `json:"session_max_age"`
	BootstrapAdmin  BootstrapAdmin `json:"bootstrap_admin"`
	RateLimitPerMin int            `json:"rate_limit_per_minute"`
	TrustedProxies  []string       `json:"trusted_proxies"`
	ExternalHTTPS   bool           `json:"external_https"`
}

// IsTLSEnabled returns whether TLS is enabled for the web interface (defaults to true).
func (w *WebConfig) IsTLSEnabled() bool {
	if w.EnableTLS == nil {
		return true
	}
	return *w.EnableTLS
}

// GetRateLimitPerMin returns the web rate limit per minute (default 300).
// This only applies to non-static requests (CSS/JS are exempt).
func (w *WebConfig) GetRateLimitPerMin() int {
	// Debug: log what value was loaded from config
	if w.RateLimitPerMin <= 0 {
		return 300 // Default: 300 req/min per IP (5 req/sec), static assets exempt
	}
	return w.RateLimitPerMin
}

// BootstrapAdmin is the initial admin created on first run (before any accounts exist).
type BootstrapAdmin struct {
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
}

// MailConfig contains outbound mail settings.
type MailConfig struct {
	StripOriginatingIP bool `json:"strip_originating_ip"` // If true, don't include X-Originating-IP header
}

type DeliveryConfig struct {
	QueueWorkers         int    `json:"queue_workers"`
	RetryIntervals       []int  `json:"retry_intervals"`
	MaxRetries           int    `json:"max_retries"`
	DSNDelayAfterSeconds int    `json:"dsn_delay_after_seconds"`
	Network              string `json:"network"`     // "tcp", "tcp4", "tcp6" - default "tcp" (both IPv4 and IPv6)
	EnableVERP           *bool  `json:"enable_verp"` // Enable per-recipient bounce tracking (default true)
}

// IsVERPEnabled returns whether VERP (Variable Envelope Return Path) is enabled (defaults to true).
func (d *DeliveryConfig) IsVERPEnabled() bool {
	if d.EnableVERP == nil {
		return true
	}
	return *d.EnableVERP
}

// GetNetwork returns the network type for outbound connections (default "tcp" for both IPv4 and IPv6).
// Valid values: "tcp" (both), "tcp4" (IPv4 only), "tcp6" (IPv6 only)
func (d *DeliveryConfig) GetNetwork() string {
	if d.Network == "" || (d.Network != "tcp4" && d.Network != "tcp6" && d.Network != "tcp") {
		return "tcp" // Default: both IPv4 and IPv6
	}
	return d.Network
}

type DNSConfig struct {
	CacheTTL int `json:"cache_ttl"`
}

type SecurityConfig struct {
	CSRFKey          string `json:"csrf_key"`
	AuthEnforcement  string `json:"auth_enforcement"`  // "none", "observe", "quarantine", "reject"
	QuarantineFolder string `json:"quarantine_folder"` // Folder name for failed auth emails (default: "Spam")
}

type MDNConfig struct {
	Enabled string `json:"enabled"` // "yes" or "no" (default: "no")
	Mode    string `json:"mode"`    // "auto" or "manual" (default: "manual")
}

type DMARCConfig struct {
	SendReports bool `json:"send_reports"` // Enable/disable DMARC report sending (default: false)
}

type TLSRPTConfig struct {
	SendReports bool `json:"send_reports"`
}

type LoggingConfig struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

// MetricsConfig controls the dedicated Prometheus-compatible operational
// endpoint. It is disabled by default and listens on loopback unless changed.
type MetricsConfig struct {
	Enabled     bool   `json:"enabled"`
	ListenAddr  string `json:"listen_addr"`
	BearerToken string `json:"bearer_token"`
}

// StoragePressureConfig protects all durable write paths from exhausting the
// filesystem. Zero thresholds preserve the legacy disabled behavior.
type StoragePressureConfig struct {
	WarningFreeBytes int64 `json:"warning_free_bytes"`
	MinimumFreeBytes int64 `json:"minimum_free_bytes"`
}

type OutboundLimitsConfig struct {
	Enabled                 bool `json:"enabled"`
	MessagesPerHour         int  `json:"messages_per_hour"`
	MessagesPerDay          int  `json:"messages_per_day"`
	RecipientsPerHour       int  `json:"recipients_per_hour"`
	RecipientsPerDay        int  `json:"recipients_per_day"`
	MaxRecipientsPerMessage int  `json:"max_recipients_per_message"`
	SuspensionMinutes       int  `json:"suspension_minutes"`
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

	// Debug logging for MDN config
	logging.Info(fmt.Sprintf("[config] Loaded MDN config: Enabled=%s, Mode=%s", cfg.MDN.Enabled, cfg.MDN.Mode))

	return &cfg, nil
}

// Validate checks that required fields are set and values are sane.
func (c *Config) Validate() error {
	if c.Server.Hostname == "" {
		return fmt.Errorf("server.hostname is required")
	}
	if err := validateOperationalSender("server.tls_report_sender", c.Server.TLSReportSender, c.Server.Domain); err != nil {
		return err
	}
	if err := validateOperationalSender("server.dsn_sender", c.Server.DSNSender, c.Server.Domain); err != nil {
		return err
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
	if c.SMTP.RateLimit.ConnectionsPerMinute <= 0 {
		c.SMTP.RateLimit.ConnectionsPerMinute = 60
	}
	if c.SMTP.RateLimit.MessagesPerMinute <= 0 {
		c.SMTP.RateLimit.MessagesPerMinute = 30
	}
	if c.TLS.Mode == "" {
		c.TLS.Mode = "autocert"
	}
	if c.TLS.Mode != "autocert" && c.TLS.Mode != "manual" && c.TLS.Mode != "none" {
		return fmt.Errorf("tls.mode must be 'autocert', 'manual', or 'none'")
	}
	if c.TLS.Mode == "manual" {
		if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			return fmt.Errorf("tls.cert_file and tls.key_file required when mode is 'manual'")
		}
	}
	if c.DKIM.DefaultSelector == "" {
		c.DKIM.DefaultSelector = "mail"
	}
	if c.DKIM.DefaultAlgorithm == "" {
		c.DKIM.DefaultAlgorithm = "ed25519"
	}
	if c.DKIM.KeysDir == "" {
		c.DKIM.KeysDir = "keys"
	}
	if err := c.Store.Validate(); err != nil {
		return err
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
		c.Delivery.MaxRetries = 11
	}
	if len(c.Delivery.RetryIntervals) == 0 {
		c.Delivery.RetryIntervals = []int{1800, 3600, 7200, 14400, 28800, 43200, 86400, 86400, 86400, 86400}
	}
	if c.Delivery.DSNDelayAfterSeconds <= 0 {
		c.Delivery.DSNDelayAfterSeconds = 14400
	}
	if c.DNS.CacheTTL <= 0 {
		c.DNS.CacheTTL = 300
	}
	if c.Clients.ReadTimeout <= 0 {
		c.Clients.ReadTimeout = 60
	}
	if c.Clients.WriteTimeout <= 0 {
		c.Clients.WriteTimeout = 60
	}
	if c.Clients.MaxConnections <= 0 {
		c.Clients.MaxConnections = 50
	}
	if c.Clients.AuthAttempts <= 0 {
		c.Clients.AuthAttempts = 10
	}
	if c.Clients.POP3.ListenAddr == "" {
		c.Clients.POP3.ListenAddr = ":995"
	}
	if c.Clients.IMAP.ListenAddr == "" {
		c.Clients.IMAP.ListenAddr = ":993"
	}
	if c.Clients.IMAP.Enabled == nil {
		disabled := false
		c.Clients.IMAP.Enabled = &disabled
	}
	if c.Clients.Submission.ListenAddr == "" {
		c.Clients.Submission.ListenAddr = ":587"
	}
	if c.Metrics.ListenAddr == "" {
		c.Metrics.ListenAddr = "127.0.0.1:9090"
	}
	if c.Metrics.Enabled {
		host, _, err := net.SplitHostPort(c.Metrics.ListenAddr)
		if err != nil {
			return fmt.Errorf("metrics.listen_addr must be host:port: %w", err)
		}
		ip := net.ParseIP(host)
		loopback := strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
		if !loopback && strings.TrimSpace(c.Metrics.BearerToken) == "" {
			return fmt.Errorf("metrics.bearer_token is required for a non-loopback listener")
		}
	}
	if c.StoragePressure.WarningFreeBytes < 0 || c.StoragePressure.MinimumFreeBytes < 0 {
		return fmt.Errorf("storage_pressure thresholds cannot be negative")
	}
	if c.StoragePressure.WarningFreeBytes > 0 && c.StoragePressure.WarningFreeBytes < c.StoragePressure.MinimumFreeBytes {
		return fmt.Errorf("storage_pressure.warning_free_bytes must be at least minimum_free_bytes")
	}
	if c.OutboundLimits.MessagesPerHour <= 0 {
		c.OutboundLimits.MessagesPerHour = 100
	}
	if c.OutboundLimits.MessagesPerDay <= 0 {
		c.OutboundLimits.MessagesPerDay = 500
	}
	if c.OutboundLimits.RecipientsPerHour <= 0 {
		c.OutboundLimits.RecipientsPerHour = 250
	}
	if c.OutboundLimits.RecipientsPerDay <= 0 {
		c.OutboundLimits.RecipientsPerDay = 1000
	}
	if c.OutboundLimits.MaxRecipientsPerMessage <= 0 {
		c.OutboundLimits.MaxRecipientsPerMessage = 100
	}
	if c.OutboundLimits.SuspensionMinutes <= 0 {
		c.OutboundLimits.SuspensionMinutes = 60
	}
	if c.OutboundLimits.Enabled {
		if c.OutboundLimits.MessagesPerDay < c.OutboundLimits.MessagesPerHour || c.OutboundLimits.RecipientsPerDay < c.OutboundLimits.RecipientsPerHour {
			return fmt.Errorf("outbound_limits daily limits must be at least hourly limits")
		}
		if c.OutboundLimits.MaxRecipientsPerMessage > c.SMTP.MaxRecipients {
			return fmt.Errorf("outbound_limits.max_recipients_per_message cannot exceed smtp.max_recipients")
		}
	}
	c.Logging.Format = strings.ToLower(strings.TrimSpace(c.Logging.Format))
	c.Logging.Level = strings.ToLower(strings.TrimSpace(c.Logging.Level))
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Level != "debug" && c.Logging.Level != "info" && c.Logging.Level != "warn" && c.Logging.Level != "error" {
		return fmt.Errorf("logging.level must be 'debug', 'info', 'warn', or 'error'")
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "text"
	}
	if c.Logging.Format != "text" && c.Logging.Format != "json" {
		return fmt.Errorf("logging.format must be 'text' or 'json'")
	}
	if c.Clients.Enabled && c.TLS.Mode == "none" {
		return fmt.Errorf("mail_clients requires TLS; tls.mode cannot be 'none'")
	}
	if c.Security.AuthEnforcement == "" {
		c.Security.AuthEnforcement = "observe" // observe, quarantine, reject, none
	}
	if c.Security.QuarantineFolder == "" {
		c.Security.QuarantineFolder = "Spam"
	}
	if c.MDN.Enabled == "" {
		c.MDN.Enabled = "no"
	}
	if c.MDN.Mode == "" {
		logging.Info("[config] MDN.Mode was empty, setting to default 'manual'")
		c.MDN.Mode = "manual"
	} else {
		logging.Info(fmt.Sprintf("[config] MDN.Mode was already set to: %s", c.MDN.Mode))
	}
	if c.MDN.Enabled != "yes" && c.MDN.Enabled != "no" {
		return fmt.Errorf("mdn.enabled must be 'yes' or 'no'")
	}
	if c.MDN.Mode != "auto" && c.MDN.Mode != "manual" {
		return fmt.Errorf("mdn.mode must be 'auto' or 'manual'")
	}
	return nil
}
