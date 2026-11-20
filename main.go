package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	backupops "gomail/backup"
	"gomail/config"
	"gomail/delivery"
	"gomail/dns"
	"gomail/logging"
	"gomail/mailclient"
	"gomail/metrics"
	"gomail/reporting"
	"gomail/smtp"
	"gomail/store"
	tlsconfig "gomail/tls"
	"gomail/web"
)

func main() {
	configPath := flag.String("config", "config.json", "Path to configuration file")
	hashPassword := flag.String("hash-password", "", "Generate bcrypt hash for a password")
	register := flag.Bool("register", false, "Install as systemd service (requires sudo)")
	backupPath := flag.String("backup", "", "Create a verified offline backup archive at this path")
	verifyBackupPath := flag.String("verify-backup", "", "Verify a GoMail backup archive")
	restoreBackupPath := flag.String("restore-backup", "", "Restore a verified offline backup archive")
	restoreStageDB := flag.String("restore-stage-db", "", "Import a MySQL restore into this pre-provisioned empty database before switching configuration")
	forceRestore := flag.Bool("force-restore", false, "Required destructive confirmation for -restore-backup")
	flag.Parse()
	if *verifyBackupPath != "" {
		manifest, err := backupops.Verify(*verifyBackupPath)
		if err != nil {
			log.Fatalf("Backup verification failed: %v", err)
		}
		fmt.Printf("Backup verified: version=%d created=%s database=%s files=%d counts=%v\n", manifest.FormatVersion, manifest.CreatedAt.Format(time.RFC3339), manifest.Database, len(manifest.Files), manifest.Counts)
		return
	}

	// Check for positional arguments (e.g., "./gomail register")
	args := flag.Args()
	if len(args) > 0 {
		command := args[0]
		switch command {
		case "register":
			registerSystemdService(*configPath)
			return
		case "hash-password":
			if len(args) < 2 {
				log.Fatalf("Usage: gomail hash-password <password>")
			}
			hash, err := hashPasswordBcrypt(args[1])
			if err != nil {
				log.Fatalf("Error hashing password: %v", err)
			}
			fmt.Printf("Password hash: %s\n", hash)
			fmt.Println("Add this to config.json under web.bootstrap_admin.password_hash")
			return
		default:
			log.Fatalf("Unknown command: %s", command)
		}
	}

	// Password hashing utility (flag style)
	if *hashPassword != "" {
		hash, err := hashPasswordBcrypt(*hashPassword)
		if err != nil {
			log.Fatalf("Error hashing password: %v", err)
		}
		fmt.Printf("Password hash: %s\n", hash)
		fmt.Println("Add this to config.json under web.bootstrap_admin.password_hash")
		return
	}

	// Systemd service registration (flag style)
	if *register {
		registerSystemdService(*configPath)
		return
	}

	// Load configuration
	if completed, err := backupops.CompleteDurableRestore(*configPath); err != nil {
		log.Fatalf("Refusing to start after restore: %v", err)
	} else if completed {
		log.Print("Verified and completed durable restore after interrupted cleanup")
	}
	if err := backupops.CheckRestoreJournal(*configPath); err != nil {
		log.Fatalf("Refusing to start: %v", err)
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	if *backupPath != "" {
		manifest, err := backupops.Create(cfg, *configPath, *backupPath, config.Version())
		if err != nil {
			log.Fatalf("Backup failed: %v", err)
		}
		fmt.Printf("Backup created and verified: %s (files=%d counts=%v)\n", *backupPath, len(manifest.Files), manifest.Counts)
		return
	}
	if *restoreBackupPath != "" {
		var manifest backupops.Manifest
		if *restoreStageDB != "" {
			manifest, err = backupops.RestoreStaged(cfg, *configPath, *restoreBackupPath, *restoreStageDB, *forceRestore)
		} else {
			manifest, err = backupops.Restore(cfg, *configPath, *restoreBackupPath, *forceRestore)
		}
		if err != nil {
			log.Fatalf("Restore failed: %v", err)
		}
		fmt.Printf("Backup restored: version=%d created=%s files=%d counts=%v\n", manifest.FormatVersion, manifest.CreatedAt.Format(time.RFC3339), len(manifest.Files), manifest.Counts)
		return
	}
	if *restoreStageDB != "" {
		log.Fatal("-restore-stage-db requires -restore-backup")
	}
	instanceLock, err := backupops.AcquireInstanceLock(cfg)
	if err != nil {
		log.Fatalf("Failed to acquire instance lock: %v", err)
	}
	defer instanceLock.Close()

	// Initialize logging from config
	logging.Configure(cfg.Logging.Level, cfg.Logging.Format)
	logging.Info(fmt.Sprintf("[main] GoMail %s starting (hostname=%s, log_level=%s)", config.Version(), cfg.Server.Hostname, logging.GetLevelName(logging.CurrentLevel)))

	// Initialize DNS cache
	dns.InitCache(cfg.DNS.CacheTTL)

	// Open database
	db, err := store.OpenConfig(cfg.Store)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()
	databaseDirectory := filepath.Dir(cfg.Store.DBPath)
	if cfg.Store.Database == "mysql" {
		databaseDirectory = cfg.Store.AttachmentsPath
	}
	db.ConfigureDiskPressure(cfg.StoragePressure.WarningFreeBytes, cfg.StoragePressure.MinimumFreeBytes, databaseDirectory, cfg.Store.AttachmentsPath)
	db.ConfigureOutboundLimits(cfg.OutboundLimits)
	if diskStatus, diskErr := db.DiskPressureStatus(); diskErr != nil {
		log.Fatalf("Failed to check storage pressure: %v", diskErr)
	} else if diskStatus.RefusingWrites {
		logging.Error(fmt.Sprintf("[storage] write refusal active: free=%d minimum=%d path=%s", diskStatus.FreeBytes, diskStatus.MinimumFree, diskStatus.Path))
	} else if diskStatus.Warning {
		logging.Warn(fmt.Sprintf("[storage] low free space: free=%d warning=%d path=%s", diskStatus.FreeBytes, diskStatus.WarningFree, diskStatus.Path))
	}
	logging.Info("[main] database opened")

	// Bootstrap admin: create initial domain + account if no accounts exist
	bootstrapAdmin(cfg, db)

	// Initialize TLS (skip for mode "none")
	certMgr, err := tlsconfig.NewCertManager(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize TLS: %v", err)
	}
	logging.Info("[main] TLS initialized")

	// Get TLS config for SMTP (nil when mode=none)
	var smtpTLS *tls.Config
	if cfg.TLS.Mode != "none" {
		smtpTLS, err = certMgr.GetCertificateForSMTP(cfg.Server.Hostname)
		if err != nil {
			logging.Warn(fmt.Sprintf("[main] warning: SMTP TLS config: %v (STARTTLS will be unavailable)", err))
		}
	} else {
		logging.Info("[main] SMTP STARTTLS disabled (tls.mode=none)")
	}

	var metricsServer *metrics.Server
	if cfg.Metrics.Enabled {
		var certificateExpiry *time.Time
		if expiry, available := certMgr.CertificateExpiry(cfg.Server.Hostname); available {
			certificateExpiry = &expiry
		}
		metricsServer = metrics.NewServer(cfg.Metrics, db, certificateExpiry)
		go func() {
			logging.Info(fmt.Sprintf("[metrics] listening on %s", cfg.Metrics.ListenAddr))
			if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logging.Error(fmt.Sprintf("[metrics] server error: %v", err))
			}
		}()
	}

	// Start SMTP inbound server
	smtpServer := smtp.NewInboundServer(cfg, db, smtpTLS)
	if err := smtpServer.Start(); err != nil {
		log.Fatalf("Failed to start SMTP server: %v", err)
	}

	// Start delivery queue workers
	deliveryPool := delivery.NewPool(cfg, db, certMgr.TLSConfig)
	deliveryPool.Start()

	// Start greylisting cleanup worker (runs daily)
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if err := db.CleanupGreylisting(); err != nil {
				logging.Error(fmt.Sprintf("[cleanup] greylisting cleanup error: %v", err))
			} else {
				logging.Info("[cleanup] greylisting cleanup completed")
			}
		}
	}()

	// Create delivery queue for the web interface (per-domain DKIM from DB)
	queue := delivery.NewQueue(db, cfg)

	// Desktop/mobile client protocols are opt-in and require TLS. POP3 uses
	// implicit TLS; SMTP submission requires STARTTLS before authentication.
	clientServer := mailclient.NewServer(cfg, db, queue, smtpTLS)
	if err := clientServer.Start(); err != nil {
		log.Fatalf("Failed to start mail-client services: %v", err)
	}

	// Start DMARC report scheduler (weekly reports)
	// Create a wrapper function to queue DMARC reports for delivery
	enqueueFunc := func(from, to, message string) error {
		// Queue the DMARC report for delivery through the SMTP system
		// Use account ID 0 for system-generated reports
		return queue.Enqueue(from, []string{to}, []byte(message), 0)
	}
	reporting.ScheduleDailyDMARCReports(cfg, db, enqueueFunc)
	tlsReportEnqueueFunc := func(from, to, message string) error {
		return queue.EnqueueTLSReport(from, []string{to}, []byte(message))
	}
	reporting.ScheduleDailyTLSReports(cfg, db, tlsReportEnqueueFunc)
	stopReportScanner := reporting.RunReceivedReportScanner(db)
	defer stopReportScanner()
	backupManager := backupops.NewManager(cfg, db, *configPath, config.Version())
	backupManager.Start()

	// Start web server
	webServer := web.NewServer(cfg, db, queue, enqueueFunc, backupManager)

	if cfg.Web.IsTLSEnabled() {
		// TLS mode: HTTPS on listen_addr, HTTP redirect + ACME on http_addr
		go func() {
			httpHandler := web.HTTPSRedirect(cfg.Web.ListenAddr)
			if certMgr.AutocertMgr != nil {
				httpHandler = certMgr.AutocertMgr.HTTPHandler(httpHandler)
			}
			httpAddr := cfg.Web.HTTPAddr
			if httpAddr == "" {
				httpAddr = ":80"
			}
			logging.Info(fmt.Sprintf("[main] HTTP redirect server on %s", httpAddr))
			if err := http.ListenAndServe(httpAddr, httpHandler); err != nil {
				logging.Error(fmt.Sprintf("[main] HTTP server error: %v", err))
			}
		}()

		go func() {
			httpServer := webServer.GetHTTPServer()
			httpServer.TLSConfig = certMgr.TLSConfig
			if err := webServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTPS server error: %v", err)
			}
		}()
	} else {
		// No TLS: plain HTTP web interface (e.g. behind nginx / reverse proxy)
		// If autocert is enabled, integrate it into the web server for ACME challenges
		logging.Info(fmt.Sprintf("[main] web.enable_tls=false, checking autocert: mode=%s, hasMgr=%v", cfg.TLS.Mode, certMgr.AutocertMgr != nil))
		if cfg.TLS.Mode == "autocert" && certMgr.AutocertMgr != nil {
			webServer.IntegrateAutocert(certMgr.AutocertMgr)
			logging.Info("[main] autocert integrated for /.well-known/acme-challenge/ (proxy port 80 through nginx)")
		} else if cfg.TLS.Mode == "autocert" {
			logging.Warn("[main] WARNING: autocert mode but no AutocertMgr (check acme_dir and acme_email config)")
		}

		go func() {
			if err := webServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTP server error: %v", err)
			}
		}()
	}

	// Log active domains
	domainNames, _ := db.ListAllDomainNames()
	if len(domainNames) > 0 {
		logging.Info(fmt.Sprintf("[main] accepting mail for domains: %s", strings.Join(domainNames, ", ")))
	} else {
		logging.Warn("[main] warning: no domains configured. Add domains via the admin panel.")
	}

	logging.Info("[main] GoMail is running. Press Ctrl+C to stop.")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logging.Info("[main] shutting down...")
	smtpServer.Stop()
	clientServer.Stop()
	if err := webServer.Shutdown(); err != nil {
		logging.Warn(fmt.Sprintf("[main] web shutdown deadline exceeded: %v", err))
	}
	backupManager.Stop()
	deliveryPool.Stop()
	if metricsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := metricsServer.Shutdown(ctx); err != nil {
			logging.Warn(fmt.Sprintf("[metrics] shutdown error: %v", err))
		}
	}
	logging.Info("[main] GoMail stopped.")
}

// bootstrapAdmin creates the initial domain and admin account on first run
// using the bootstrap_admin settings from config.json.
func bootstrapAdmin(cfg *config.Config, db *store.DB) {
	count, _ := db.CountAccounts()
	if count > 0 {
		return // Accounts already exist, skip bootstrap
	}

	if cfg.Web.BootstrapAdmin.Email == "" || cfg.Web.BootstrapAdmin.PasswordHash == "" {
		logging.Info("[main] no accounts exist and no bootstrap_admin configured.")
		logging.Info("[main] set web.bootstrap_admin.email and web.bootstrap_admin.password_hash in config.json")
		logging.Info("[main] generate a password hash with: gomail -hash-password 'your-password'")
		return
	}

	email := cfg.Web.BootstrapAdmin.Email
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		logging.Warn(fmt.Sprintf("[main] bootstrap_admin.email '%s' is not a valid email address", email))
		return
	}
	domainName := parts[1]

	logging.Info(fmt.Sprintf("[main] bootstrapping: creating domain '%s' and admin account '%s'", domainName, email))

	// Create the domain
	domain := &store.Domain{
		Domain:        domainName,
		IsActive:      true,
		DKIMSelector:  cfg.DKIM.DefaultSelector,
		DKIMAlgorithm: cfg.DKIM.DefaultAlgorithm,
	}
	domainID, err := db.CreateDomain(domain)
	if err != nil {
		logging.Error(fmt.Sprintf("[main] bootstrap: failed to create domain: %v", err))
		return
	}

	// Create the admin account
	account := &store.Account{
		DomainID:     domainID,
		Email:        email,
		DisplayName:  "Administrator",
		PasswordHash: cfg.Web.BootstrapAdmin.PasswordHash,
		IsAdmin:      true,
		IsActive:     true,
		QuotaBytes:   0, // unlimited
	}
	_, err = db.CreateAccount(account)
	if err != nil {
		logging.Error(fmt.Sprintf("[main] bootstrap: failed to create admin account: %v", err))
		return
	}

	logging.Info(fmt.Sprintf("[main] bootstrap complete. Login with: %s", email))
	logging.Info("[main] generate DKIM keys via the admin panel: /admin/domains")
}

func hashPasswordBcrypt(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// registerSystemdService installs GoMail as a systemd service
func registerSystemdService(configPath string) {
	// Check if running as root (required for systemd installation)
	if os.Geteuid() != 0 {
		log.Fatalf("Error: register command requires sudo\nUsage: sudo ./gomail register")
	}

	// Get the absolute path of the gomail binary
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}

	// Get current working directory once
	pwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get working directory: %v", err)
	}

	// Get the absolute path of the config file
	absConfigPath := configPath
	if !strings.HasPrefix(configPath, "/") {
		absConfigPath = pwd + "/" + configPath
	}

	// Check if config file exists and is valid
	if _, err := os.Stat(absConfigPath); os.IsNotExist(err) {
		log.Fatalf("Config file not found: %s", absConfigPath)
	}

	// Validate config by attempting to load it
	if _, err := config.Load(absConfigPath); err != nil {
		log.Fatalf("Config file is invalid: %v", err)
	}

	// Get the current user running sudo (the one who should own the service)
	currentUser := os.Getenv("SUDO_USER")
	if currentUser == "" {
		currentUser = "root"
	}

	// Create systemd service file - simple setup, runs in release folder
	serviceContent := fmt.Sprintf(`[Unit]
Description=GoMail Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=%s
WorkingDirectory=%s
ExecStart=%s -config %s
Restart=always
RestartSec=5
StartLimitBurst=5

LimitNOFILE=65535
LimitNPROC=65535

StandardOutput=journal
StandardError=journal
SyslogIdentifier=gomail

[Install]
WantedBy=multi-user.target
`, currentUser, pwd, exePath, absConfigPath)

	fmt.Println("[register] GoMail Systemd Service Installation")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()
	fmt.Printf("Binary: %s\n", exePath)
	fmt.Printf("Config: %s\n", absConfigPath)
	fmt.Printf("WorkingDirectory: %s\n", pwd)
	fmt.Printf("User: %s\n\n", currentUser)

	// Install systemd service file
	fmt.Println("Installing systemd service...")
	serviceFile := "/etc/systemd/system/gomail.service"

	// Write to temp file first, then copy with sudo
	tmpFile := "/tmp/gomail.service"
	if err := os.WriteFile(tmpFile, []byte(serviceContent), 0644); err != nil {
		log.Fatalf("Failed to write temp service file: %v", err)
	}
	defer os.Remove(tmpFile)

	// Copy service file (already running as root, no sudo needed)
	cmd := exec.Command("cp", tmpFile, serviceFile)
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to copy service file: %v", err)
	}

	// Set permissions (already running as root, no sudo needed)
	cmd = exec.Command("chmod", "644", serviceFile)
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to set service file permissions: %v", err)
	}

	// Reload systemd daemon (already running as root, no sudo needed)
	fmt.Println("Reloading systemd daemon...")
	cmd = exec.Command("systemctl", "daemon-reload")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to reload systemd: %v", err)
	}

	// Enable service on boot (already running as root, no sudo needed)
	fmt.Println("Enabling on boot...")
	cmd = exec.Command("systemctl", "enable", "gomail")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to enable service: %v", err)
	}

	// Start service (already running as root, no sudo needed)
	fmt.Println("Starting service...")
	cmd = exec.Command("systemctl", "start", "gomail")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to start service: %v", err)
	}

	// Check status (already running as root, no sudo needed)
	fmt.Println()
	fmt.Println("Service status:")
	cmd = exec.Command("systemctl", "status", "gomail", "--no-pager")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("✓ GoMail registered as systemd service!")
	fmt.Println()
	fmt.Println("Service file: " + serviceFile)
	fmt.Println()
	fmt.Println("Useful commands:")
	fmt.Println("  sudo systemctl status gomail")
	fmt.Println("  sudo systemctl restart gomail")
	fmt.Println("  sudo journalctl -u gomail -f")
	fmt.Println()
}

// runCommand executes a command and handles errors
func runCommand(name string, args ...string) {
	runCommandWithIgnore(name, nil, args...)
}

// runCommandWithIgnore executes a command and ignores specific exit codes
func runCommandWithIgnore(name string, ignoreExitCodes []int, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()

	if err != nil {
		// Check if exit code should be ignored
		if exitErr, ok := err.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			for _, ignoreCode := range ignoreExitCodes {
				if code == ignoreCode {
					return // Exit code is acceptable, ignore the error
				}
			}
		}
		log.Fatalf("Command failed: %s %v", name, args)
	}
}
