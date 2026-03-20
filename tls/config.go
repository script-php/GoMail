package tlsconfig

import (
	"crypto/tls"
	"fmt"
	"gomail/config"
)

// NewTLSConfig builds a *tls.Config based on app configuration.
func NewTLSConfig(cfg *config.TLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}

	switch cfg.MinVersion {
	case "1.3":
		tlsCfg.MinVersion = tls.VersionTLS13
	case "1.2", "":
		tlsCfg.MinVersion = tls.VersionTLS12
	default:
		return nil, fmt.Errorf("unsupported TLS min version: %s", cfg.MinVersion)
	}

	return tlsCfg, nil
}
