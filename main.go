package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/bcrypt"

	"gomail/auth"
	"gomail/config"
	"gomail/delivery"
	"gomail/dns"
	"gomail/smtp"
	"gomail/store"
	tlsconfig "gomail/tls"
	"gomail/web"
)

func main() {
	configPath := flag.String("config", "config.toml", "Path to configuration file")
	setupMode := flag.Bool("setup", false, "Run first-time setup (generate DKIM keys, print DNS records)")
	hashPassword := flag.String("hash-password", "", "Generate bcrypt hash for a password")
	flag.Parse()

	// Password hashing utility
	if *hashPassword != "" {
		hash, err := hashPasswordBcrypt(*hashPassword)
		if err != nil {
			log.Fatalf("Error hashing password: %v", err)
		}
		fmt.Printf("Password hash: %s\n", hash)
		fmt.Println("Add this to config.toml under [web.admin] password_hash")
		return
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("[main] GoMail starting for %s (%s)", cfg.Server.Hostname, cfg.Server.Domain)

	// Setup mode: generate keys and show DNS records
	if *setupMode {
		runSetup(cfg)
		return
	}

	// Initialize DNS cache
	dns.InitCache(cfg.DNS.CacheTTL)

	// Open database
	db, err := store.Open(cfg.Store.DBPath, cfg.Store.AttachmentsPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()
	log.Println("[main] database opened")

	// Initialize TLS
	certMgr, err := tlsconfig.NewCertManager(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize TLS: %v", err)
	}
	log.Println("[main] TLS initialized")

	// Initialize DKIM signer (optional — only if key exists)
	var dkimSigner *auth.DKIMSigner
	if _, err := os.Stat(cfg.DKIM.KeyPath); err == nil {
		dkimSigner, err = auth.NewDKIMSigner(
			cfg.Server.Domain, cfg.DKIM.Selector,
			cfg.DKIM.KeyPath, cfg.DKIM.Algorithm,
		)
		if err != nil {
			log.Printf("[main] warning: DKIM signer init failed: %v (outbound mail will not be DKIM-signed)", err)
		} else {
			log.Printf("[main] DKIM signer ready (selector=%s, algo=%s)", cfg.DKIM.Selector, cfg.DKIM.Algorithm)
		}
	} else {
		log.Println("[main] warning: DKIM key not found; run with -setup to generate")
	}

	// Get TLS config for SMTP
	smtpTLS, err := certMgr.GetCertificateForSMTP(cfg.Server.Hostname)
	if err != nil {
		log.Printf("[main] warning: SMTP TLS config: %v (STARTTLS will be unavailable)", err)
	}

	// Start SMTP inbound server
	smtpServer := smtp.NewInboundServer(cfg, db, smtpTLS)
	if err := smtpServer.Start(); err != nil {
		log.Fatalf("Failed to start SMTP server: %v", err)
	}

	// Start delivery queue workers
	deliveryPool := delivery.NewPool(cfg, db, certMgr.TLSConfig)
	deliveryPool.Start()

	// Create delivery queue for the web interface
	queue := delivery.NewQueue(db, cfg, dkimSigner)

	// Start web server
	webServer := web.NewServer(cfg, db, queue)

	// HTTP server for ACME challenges and HTTPS redirect
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

	// Start HTTPS server
	go func() {
		httpServer := webServer.GetHTTPServer()
		httpServer.TLSConfig = certMgr.TLSConfig
		log.Printf("[main] HTTPS server on %s", cfg.Web.ListenAddr)
		if err := httpServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTPS server error: %v", err)
		}
	}()

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

func runSetup(cfg *config.Config) {
	log.Println("[setup] Generating DKIM keys...")

	if err := auth.GenerateDKIMKeys("keys"); err != nil {
		log.Fatalf("Failed to generate DKIM keys: %v", err)
	}

	log.Println("[setup] DKIM keys generated in keys/")
	log.Println("")
	log.Println("=== DNS Records to Configure ===")
	log.Println("")
	log.Printf("1. MX Record:")
	log.Printf("   %s.  IN  MX  10  %s.", cfg.Server.Domain, cfg.Server.Hostname)
	log.Println("")
	log.Printf("2. A Record (point to your server IP):")
	log.Printf("   %s.  IN  A  <YOUR_SERVER_IP>", cfg.Server.Hostname)
	log.Println("")
	log.Printf("3. SPF Record:")
	log.Printf("   %s.  IN  TXT  \"v=spf1 mx a -all\"", cfg.Server.Domain)
	log.Println("")
	log.Printf("4. DKIM Record (paste contents of keys/dkim_dns_record.txt):")
	log.Printf("   %s._domainkey.%s.  IN  TXT  \"<see keys/dkim_dns_record.txt>\"", cfg.DKIM.Selector, cfg.Server.Domain)
	log.Println("")
	log.Printf("5. DMARC Record:")
	log.Printf("   _dmarc.%s.  IN  TXT  \"v=DMARC1; p=quarantine; rua=mailto:admin@%s\"", cfg.Server.Domain, cfg.Server.Domain)
	log.Println("")
	log.Printf("6. MTA-STS Record:")
	log.Printf("   _mta-sts.%s.  IN  TXT  \"v=STSv1; id=%d\"", cfg.Server.Domain, 1)
	log.Println("")
	log.Printf("7. TLS-RPT Record:")
	log.Printf("   _smtp._tls.%s.  IN  TXT  \"v=TLSRPTv1; rua=mailto:admin@%s\"", cfg.Server.Domain, cfg.Server.Domain)
	log.Println("")
	log.Printf("8. PTR Record (configure with your hosting provider):")
	log.Printf("   <YOUR_SERVER_IP>  PTR  %s.", cfg.Server.Hostname)
	log.Println("")
	log.Println("Next steps:")
	log.Println("  1. Set these DNS records")
	log.Println("  2. Generate a password hash: gomail -hash-password 'your-password'")
	log.Println("  3. Add the hash to config.toml [web.admin] password_hash")
	log.Println("  4. Start the server: gomail -config config.toml")
}

func hashPasswordBcrypt(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
