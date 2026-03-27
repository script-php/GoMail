package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/crypto/bcrypt"

	"gomail/config"
	"gomail/delivery"
	"gomail/dns"
	"gomail/smtp"
	"gomail/store"
	tlsconfig "gomail/tls"
	"gomail/web"
)

func main() {
	configPath := flag.String("config", "config.json", "Path to configuration file")
	hashPassword := flag.String("hash-password", "", "Generate bcrypt hash for a password")
	flag.Parse()

	// Password hashing utility
	if *hashPassword != "" {
		hash, err := hashPasswordBcrypt(*hashPassword)
		if err != nil {
			log.Fatalf("Error hashing password: %v", err)
		}
		fmt.Printf("Password hash: %s\n", hash)
		fmt.Println("Add this to config.json under web.bootstrap_admin.password_hash")
		return
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("[main] GoMail %s starting (hostname=%s)", config.Version(), cfg.Server.Hostname)

	// Initialize DNS cache
	dns.InitCache(cfg.DNS.CacheTTL)

	// Open database
	db, err := store.Open(cfg.Store.DBPath, cfg.Store.AttachmentsPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()
	log.Println("[main] database opened")

	// Bootstrap admin: create initial domain + account if no accounts exist
	bootstrapAdmin(cfg, db)

	// Initialize TLS (skip for mode "none")
	certMgr, err := tlsconfig.NewCertManager(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize TLS: %v", err)
	}
	log.Println("[main] TLS initialized")

	// Get TLS config for SMTP (nil when mode=none)
	var smtpTLS *tls.Config
	if cfg.TLS.Mode != "none" {
		smtpTLS, err = certMgr.GetCertificateForSMTP(cfg.Server.Hostname)
		if err != nil {
			log.Printf("[main] warning: SMTP TLS config: %v (STARTTLS will be unavailable)", err)
		}
	} else {
		log.Println("[main] SMTP STARTTLS disabled (tls.mode=none)")
	}

	// Start SMTP inbound server
	smtpServer := smtp.NewInboundServer(cfg, db, smtpTLS)
	if err := smtpServer.Start(); err != nil {
		log.Fatalf("Failed to start SMTP server: %v", err)
	}

	// Start delivery queue workers
	deliveryPool := delivery.NewPool(cfg, db, certMgr.TLSConfig)
	deliveryPool.Start()

	// Create delivery queue for the web interface (per-domain DKIM from DB)
	queue := delivery.NewQueue(db, cfg)

	// Start web server
	webServer := web.NewServer(cfg, db, queue)

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
			log.Printf("[main] HTTP redirect server on %s", httpAddr)
			if err := http.ListenAndServe(httpAddr, httpHandler); err != nil {
				log.Printf("[main] HTTP server error: %v", err)
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
		log.Printf("[main] web.enable_tls=false, checking autocert: mode=%s, hasMgr=%v", cfg.TLS.Mode, certMgr.AutocertMgr != nil)
		if cfg.TLS.Mode == "autocert" && certMgr.AutocertMgr != nil {
			webServer.IntegrateAutocert(certMgr.AutocertMgr)
			log.Printf("[main] autocert integrated for /.well-known/acme-challenge/ (proxy port 80 through nginx)")
		} else if cfg.TLS.Mode == "autocert" {
			log.Printf("[main] WARNING: autocert mode but no AutocertMgr (check acme_dir and acme_email config)")
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
		log.Printf("[main] accepting mail for domains: %s", strings.Join(domainNames, ", "))
	} else {
		log.Println("[main] warning: no domains configured. Add domains via the admin panel.")
	}

	log.Println("[main] GoMail is running. Press Ctrl+C to stop.")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[main] shutting down...")
	smtpServer.Stop()
	deliveryPool.Stop()
	webServer.Shutdown()
	log.Println("[main] GoMail stopped.")
}

// bootstrapAdmin creates the initial domain and admin account on first run
// using the bootstrap_admin settings from config.json.
func bootstrapAdmin(cfg *config.Config, db *store.DB) {
	count, _ := db.CountAccounts()
	if count > 0 {
		return // Accounts already exist, skip bootstrap
	}

	if cfg.Web.BootstrapAdmin.Email == "" || cfg.Web.BootstrapAdmin.PasswordHash == "" {
		log.Println("[main] no accounts exist and no bootstrap_admin configured.")
		log.Println("[main] set web.bootstrap_admin.email and web.bootstrap_admin.password_hash in config.json")
		log.Println("[main] generate a password hash with: gomail -hash-password 'your-password'")
		return
	}

	email := cfg.Web.BootstrapAdmin.Email
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		log.Printf("[main] bootstrap_admin.email '%s' is not a valid email address", email)
		return
	}
	domainName := parts[1]

	log.Printf("[main] bootstrapping: creating domain '%s' and admin account '%s'", domainName, email)

	// Create the domain
	domain := &store.Domain{
		Domain:        domainName,
		IsActive:      true,
		DKIMSelector:  cfg.DKIM.DefaultSelector,
		DKIMAlgorithm: cfg.DKIM.DefaultAlgorithm,
	}
	domainID, err := db.CreateDomain(domain)
	if err != nil {
		log.Printf("[main] bootstrap: failed to create domain: %v", err)
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
		log.Printf("[main] bootstrap: failed to create admin account: %v", err)
		return
	}

	log.Printf("[main] bootstrap complete. Login with: %s", email)
	log.Println("[main] generate DKIM keys via the admin panel: /admin/domains")
}

func hashPasswordBcrypt(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
