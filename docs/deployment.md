# Deployment Guide

## Prerequisites
- Linux server (Ubuntu/Debian recommended)
- Go 1.21+ installed
- Domain name with DNS control
- Port 25, 80, 443 open
- A static IP with configurable PTR record

## Build

```bash
cd /path/to/gomail
go build -o gomail .
```

## First-Time Setup

```bash
# Run setup wizard
./scripts/setup.sh

# Or manually:
./gomail -setup                           # Generate DKIM keys + DNS instructions
./gomail -hash-password 'your-password'   # Generate password hash
```

Edit `config.toml`:
- Set `server.hostname` and `server.domain`
- Set `web.admin.password_hash` to the bcrypt hash
- Set `tls.acme_email` for Let's Encrypt
- Adjust paths as needed

## Systemd Service

Create `/etc/systemd/system/gomail.service`:

```ini
[Unit]
Description=GoMail Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=gomail
Group=gomail
WorkingDirectory=/opt/gomail
ExecStart=/opt/gomail/gomail -config /opt/gomail/config.toml
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/gomail/data /opt/gomail/keys
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true

# Allow binding to privileged ports
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=gomail

[Install]
WantedBy=multi-user.target
```

```bash
# Create service user
sudo useradd -r -s /bin/false gomail

# Copy files
sudo mkdir -p /opt/gomail
sudo cp gomail config.toml /opt/gomail/
sudo cp -r web/templates web/static /opt/gomail/web/
sudo mkdir -p /opt/gomail/data /opt/gomail/keys
sudo chown -R gomail:gomail /opt/gomail

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable gomail
sudo systemctl start gomail
sudo systemctl status gomail

# View logs
sudo journalctl -u gomail -f
```

## Firewall Rules

```bash
# UFW (Ubuntu)
sudo ufw allow 25/tcp    # SMTP
sudo ufw allow 80/tcp    # HTTP (ACME + redirect)
sudo ufw allow 443/tcp   # HTTPS (web interface)

# iptables
sudo iptables -A INPUT -p tcp --dport 25 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

## Port 25 Considerations

Many cloud providers (AWS, GCP, Azure) block outbound port 25 by default.
You may need to:
- Request a port 25 unblock from your provider
- Use a VPS provider that allows port 25 (Vultr, Hetzner, OVH, etc.)

## SSL Certificate

GoMail uses Let's Encrypt by default (`tls.mode = "autocert"`).
- Port 80 must be accessible for HTTP-01 ACME challenges
- Certificates are auto-renewed
- Stored in the `tls.acme_dir` path

For manual certificates:
```toml
[tls]
mode = "manual"
cert_file = "/path/to/fullchain.pem"
key_file = "/path/to/privkey.pem"
```

## Updating

```bash
cd /path/to/gomail-source
git pull
go build -o gomail .
sudo cp gomail /opt/gomail/
sudo systemctl restart gomail
```

## Backups

Back up these paths regularly:
- `data/mail.db` — The SQLite database with all messages
- `data/attachments/` — Attachment files
- `keys/` — DKIM signing keys
- `config.toml` — Configuration
