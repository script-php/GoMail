package tlsconfig

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"os"

	"gomail/config"

	"golang.org/x/crypto/acme/autocert"
)

// CertManager wraps certificate management — either autocert or manual.
type CertManager struct {
	AutocertMgr *autocert.Manager
	TLSConfig   *tls.Config
	Mode        string
}

// NewCertManager creates the appropriate certificate manager based on config.
func NewCertManager(cfg *config.Config) (*CertManager, error) {
	baseTLS, err := NewTLSConfig(&cfg.TLS)
	if err != nil {
		return nil, err
	}

	cm := &CertManager{Mode: cfg.TLS.Mode}

	switch cfg.TLS.Mode {
	case "none":
		// No TLS — for local testing or behind a reverse proxy
		cm.TLSConfig = baseTLS
		log.Println("[tls] TLS disabled (mode=none)")

	case "autocert":
		if err := os.MkdirAll(cfg.TLS.ACMEDir, 0700); err != nil {
			return nil, fmt.Errorf("creating ACME dir: %w", err)
		}

		cm.AutocertMgr = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Email:      cfg.TLS.ACMEEmail,
			Cache:      autocert.DirCache(cfg.TLS.ACMEDir),
			HostPolicy: autocert.HostWhitelist(cfg.Server.Hostname),
		}

		baseTLS.GetCertificate = cm.AutocertMgr.GetCertificate
		baseTLS.NextProtos = append(baseTLS.NextProtos, "h2", "http/1.1", "acme-tls/1")
		cm.TLSConfig = baseTLS

		log.Printf("[tls] autocert enabled for %s", cfg.Server.Hostname)

	case "manual":
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading TLS cert/key: %w", err)
		}
		baseTLS.Certificates = []tls.Certificate{cert}
		baseTLS.NextProtos = append(baseTLS.NextProtos, "h2", "http/1.1")
		cm.TLSConfig = baseTLS

		log.Printf("[tls] manual cert loaded from %s", cfg.TLS.CertFile)

	default:
		return nil, fmt.Errorf("unknown TLS mode: %s", cfg.TLS.Mode)
	}

	return cm, nil
}

// GetCertificate returns a tls.Certificate for use in SMTP STARTTLS.
func (cm *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if cm.AutocertMgr != nil {
		return cm.AutocertMgr.GetCertificate(hello)
	}
	if len(cm.TLSConfig.Certificates) > 0 {
		return &cm.TLSConfig.Certificates[0], nil
	}
	return nil, fmt.Errorf("no certificate available")
}

// GetCertificateForSMTP returns TLS config suitable for SMTP STARTTLS.
func (cm *CertManager) GetCertificateForSMTP(hostname string) (*tls.Config, error) {
	smtpTLS := cm.TLSConfig.Clone()
	smtpTLS.ServerName = hostname

	if cm.AutocertMgr != nil {
		// Trigger cert fetch if not cached
		hello := &tls.ClientHelloInfo{ServerName: hostname}
		_, err := cm.AutocertMgr.GetCertificate(hello)
		if err != nil {
			// For SMTP, we can use a self-signed cert as fallback
			// Most SMTP is opportunistic TLS
			log.Printf("[tls] warning: autocert for SMTP %s: %v (will use opportunistic)", hostname, err)
		}

		smtpTLS.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			ctx := context.Background()
			cert, err := cm.AutocertMgr.GetCertificate(hello)
			if err != nil {
				_ = ctx
				return nil, err
			}
			return cert, nil
		}
	}

	return smtpTLS, nil
}
