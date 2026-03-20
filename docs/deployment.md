# Deployment Guide

This guide covers deploying GoMail to a production server. For configuration details, see [docs/config.md](config.md). For DNS setup, see [docs/dns_records.md](dns_records.md).

## Quick Links

- **Architecture:** [docs/architecture.md](architecture.md) — System design, database schema, security model
- **Configuration Reference:** [docs/config.md](config.md) — All config.json options
- **DNS Setup:** [docs/dns_records.md](dns_records.md) — MX, SPF, DKIM, DMARC, CAA records
- **README:** [README.md](../README.md) — Features, quick start, troubleshooting

## Prerequisites

**Hardware:**
- Linux server (Ubuntu 20.04+, Debian 11+, or CentOS 8+ recommended)
- Minimum: 2 CPU cores, 2GB RAM, 10GB disk
- For high-volume: 4+ CPU cores, 8GB+ RAM, 50GB+ SSD

**Network:**
- Static IP address with configurable PTR record (contact hosting provider)
- Port 25 (SMTP inbound) — open and NOT rate-limited
- Port 80 (HTTP) — for Let's Encrypt ACME challenges
- Port 443 (HTTPS) — for web interface
- Outbound SMTP (port 25) — not rate-limited or blocked
- Domain name with full DNS control

**Software:**
- Go 1.21+ (if building from source)
- sudo access on server

**Pre-Deployment Checklist:**

```bash
# Check ports are open
sudo netstat -tulpn | grep -E ':25|:80|:443'

# Check reverse DNS (A record)
dig +short mail.example.com

# Check reverse DNS (PTR record)
dig +short -x YOUR_IP_HERE
# Should return: mail.example.com

# Verify DNS is propagated
nslookup example.com
# Should show your server IP in A record
```

## Build

```bash
cd /path/to/gomail
go build -o gomail .
chmod +x gomail
./gomail -version  # Verify build
```

## First-Time Setup

### 1. Prepare Configuration

```bash
# Generate DKIM keys for your domain
./gomail -setup

# Generate admin password hash
./gomail -hash-password 'your-secure-password'
# Output: $2a$10$... (copy this)
```

### 2. Edit config.json

Copy from [docs/config.md](config.md) production example. Key settings:

```json
{
  "server": {
    "hostname": "mail.example.com"
  },
  "smtp": {
    "listen_addr": ":25",
    "max_connections": 100
  },
  "tls": {
    "mode": "autocert",
    "acme_email": "admin@example.com",
    "acme_dir": "/opt/gomail/data/certs"
  },
  "store": {
    "db_path": "/opt/gomail/data/mail.db",
    "attachments_path": "/opt/gomail/data/attachments"
  },
  "web": {
    "listen_addr": ":443",
    "http_addr": ":80",
    "enable_tls": true,
    "session_secret": "generate-random-32-char-string",
    "bootstrap_admin": {
      "email": "admin@example.com",
      "password_hash": "$2a$10$..."  // from -hash-password above
    }
  },
  "delivery": {
    "queue_workers": 2
  }
}
```

See [docs/config.md](config.md) for all options and environment variable overrides.

### 3. Configure DNS Records

Before starting the server, add DNS records (see [docs/dns_records.md](dns_records.md)):

```
example.com         A        YOUR_IP
mail.example.com    A        YOUR_IP
example.com         MX   10  mail.example.com.
example.com         TXT      "v=spf1 mx ~all"
mail._domainkey.example.com  TXT  "v=DKIM1; k=ed25519; p=..."
```

**Note:** DNS propagation takes 1-24 hours. Proceed to systemd setup while waiting.

### 4. PTR Record (Reverse DNS)

Contact your hosting provider to set:
```
YOUR_IP  PTR  mail.example.com.
```

This is **critical** for email deliverability. Verify:
```bash
dig -x YOUR_IP
# Should return: mail.example.com
```

## Systemd Service

### Install Service File

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
ExecStart=/opt/gomail/gomail -config /opt/gomail/config.json
Restart=always
RestartSec=5
StartLimitBurst=5
StartLimitIntervalSec=60

# Process management
KillMode=mixed
KillSignal=SIGTERM

# Resource limits (adjust for your needs)
LimitNOFILE=65535
LimitNPROC=65535

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/gomail/data /opt/gomail/keys
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=true
LockPersonality=true

# Allow binding to port 25, 80, 443
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
SecureBits=keep-caps

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=gomail
SyslogFacility=mail

[Install]
WantedBy=multi-user.target
```

### Bootstrap Installation

```bash
# 1. Create service user
sudo useradd -r -s /bin/false -m -d /var/lib/gomail gomail

# 2. Create directories
sudo mkdir -p /opt/gomail
sudo mkdir -p /opt/gomail/data/attachments
sudo mkdir -p /opt/gomail/web/{templates,static}
sudo mkdir -p /etc/gomail

# 3. Copy binaries and config
sudo cp gomail /opt/gomail/
sudo cp config.json /opt/gomail/
sudo chmod 755 /opt/gomail/gomail
sudo chmod 640 /opt/gomail/config.json

# 4. Copy web assets (if in source directory)
sudo cp -r web/templates /opt/gomail/web/
sudo cp -r web/static /opt/gomail/web/

# 5. Set ownership and permissions
sudo chown -R gomail:gomail /opt/gomail
sudo chmod 700 /opt/gomail/data
sudo chmod 700 /opt/gomail/data/attachments

# 6. Copy systemd service file
sudo cp /path/to/gomail.service /etc/systemd/system/
sudo chmod 644 /etc/systemd/system/gomail.service

# 7. Reload systemd
sudo systemctl daemon-reload

# 8. Enable on boot
sudo systemctl enable gomail

# 9. Start service
sudo systemctl start gomail

# 10. Check status
sudo systemctl status gomail
sudo journalctl -u gomail -f -n 50
```

## Firewall Rules

### UFW (Ubuntu/Debian)

```bash
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Mail services
sudo ufw allow 25/tcp    # SMTP inbound
sudo ufw allow 587/tcp   # SMTP auth (future feature)
sudo ufw allow 993/tcp   # IMAP SSL (future feature)

# Web interface
sudo ufw allow 80/tcp    # HTTP → Let's Encrypt, redirect to 443
sudo ufw allow 443/tcp   # HTTPS → Web UI

# SSH (if not already open)
sudo ufw allow 22/tcp

# Verify
sudo ufw status
```

### iptables

```bash
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 25 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -P INPUT DROP

# Save (varies by distro)
sudo apt-get install iptables-persistent
sudo netfilter-persistent save
```

## Port 25 Considerations

**Important:** Many cloud providers (AWS, GCP, Azure, Digital Ocean tier 1) block outbound port 25 by default.

**If port 25 is blocked:**
1. Contact your provider and request unblock (may require owner verification)
2. Switch to a provider that allows port 25 (Vultr, Hetzner, OVH, DigitalOcean business, Linode)
3. Use alternate inbound port if recommended by provider

**Verify port 25:**

```bash
# From your server
telnet smtp.gmail.com 25
# Should connect and respond with 220...

# From another server (external test)
nmap -p 25 YOUR_IP
# Should show: PORT   STATE SERVICE
#            25/tcp open  smtp
```

## SSL/TLS Certificate

### Let's Encrypt (Recommended)

GoMail uses automatic Let's Encrypt by default:

```json
"tls": {
  "mode": "autocert",
  "acme_email": "admin@example.com",
  "acme_dir": "/opt/gomail/data/certs"
}
```

**Requirements:**
- Port 80 accessible for HTTP-01 ACME challenges
- Domain resolves to your server IP
- Valid email address in `acme_email`

**Certificate renewal:**
- Auto-renewed 30 days before expiry
- Check logs: `sudo journalctl -u gomail -f | grep -i cert`
- Certs stored in `acme_dir`

**Renewal failure indicators:**
```bash
# Check certificate expiry
openssl s_client -connect mail.example.com:443 -showcerts | grep "notAfter"

# If renewal fails, check:
sudo journalctl -u gomail -n 100 | grep -i "acme\|cert"

# Verify port 80 is accessible
sudo netstat -tulpn | grep ':80'

# Verify DNS resolution
nslookup mail.example.com
```

### Manual Certificates

If using manual certificates:

```json
"tls": {
  "mode": "manual",
  "cert_file": "/opt/gomail/certs/fullchain.pem",
  "key_file": "/opt/gomail/certs/privkey.pem"
}
```

Then:
```bash
sudo cp fullchain.pem privkey.pem /opt/gomail/certs/
sudo chown gomail:gomail /opt/gomail/certs/*
sudo systemctl restart gomail
```

## Testing Deployment

### 1. Verify Web UI

```bash
# Test HTTPS
curl -k https://mail.example.com/
# Should return login page HTML

# If using self-signed cert
curl -k https://mail.example.com/login
# -k = insecure (ignore cert warnings)
```

### 2. Test SMTP

```bash
# From command line
telnet mail.example.com 25

# Commands to test:
EHLO mail.example.com
MAIL FROM:<test@example.com>
RCPT TO:<user@example.com>
DATA
Subject: Test

Test body.
.
QUIT
```

### 3. Send Test Email

1. Open web UI: https://mail.example.com
2. Login with admin credentials
3. Admin → Domains → Add a domain
4. Add admin account: Admin → Accounts → Add account
5. Login as admin account
6. Compose → Send test email
7. Check inbox for delivery

### 4. Verify DKIM

```bash
# Check DKIM is active
dig mail._domainkey.example.com TXT

# Should return your DKIM record:
# v=DKIM1; k=ed25519; p=...
```

### 5. Check Logs

```bash
sudo journalctl -u gomail -f

# Should show:
# - Server starting on :25, :80, :443
# - Certificate fetched from Let's Encrypt
# - Ready for connections
```

## Monitoring

### Service Health

```bash
# Check service status
sudo systemctl status gomail

# Check if listening on required ports
sudo netstat -tulpn | grep gomail
# Should show: :smtp, :web (http), :web (https)

# Continuous monitoring
sudo journalctl -u gomail -f
```

### Database Health

```bash
# SSH into server as gomail
sudo -u gomail sqlite3 /opt/gomail/data/mail.db

# Inside sqlite3:
.tables
SELECT COUNT(*) FROM messages;
SELECT COUNT(*) FROM outbound_queue;
.quit
```

### Email Delivery Status

Check outbound queue:
```bash
sudo -u gomail sqlite3 /opt/gomail/data/mail.db
SELECT COUNT(*) FROM outbound_queue WHERE status='pending';
SELECT COUNT(*) FROM outbound_queue WHERE status='sending';
SELECT COUNT(*) FROM outbound_queue WHERE status='sent';
.quit
```

### System Resources

```bash
# CPU and memory
top -b -n 1 | grep gomail

# Disk space
df -h /opt/gomail
du -sh /opt/gomail/data

# Network connections
ss -tulpn | grep gomail
```

## Database Maintenance

### Vacuum (Optimize)

```bash
# Monthly optimization
sudo -u gomail sqlite3 /opt/gomail/data/mail.db "VACUUM;"
```

### Backup

```bash
# Daily backup script
#!/bin/bash
BACKUP_DIR="/backups/gomail"
mkdir -p "$BACKUP_DIR"

# Backup database
sudo cp /opt/gomail/data/mail.db \
  "$BACKUP_DIR/mail.db.$(date +%Y%m%d_%H%M%S)"

# Backup config
sudo cp /opt/gomail/config.json \
  "$BACKUP_DIR/config.json.$(date +%Y%m%d_%H%M%S)"

# Backup attachments
sudo tar -czf "$BACKUP_DIR/attachments.$(date +%Y%m%d).tar.gz" \
  /opt/gomail/data/attachments

# Clean old backups (keep 30 days)
find "$BACKUP_DIR" -mtime +30 -delete
```

Add to crontab:
```bash
sudo crontab -e
# Add: 0 2 * * * /usr/local/bin/backup-gomail.sh
```

### Archive Old Messages

```bash
# Archive messages older than 1 year
sudo -u gomail sqlite3 /opt/gomail/data/mail.db << EOF
DELETE FROM messages WHERE created_at < date('now', '-1 year');
DELETE FROM attachments WHERE message_id NOT IN (SELECT id FROM messages);
VACUUM;
EOF
```

## Logging

### Log Location

```bash
# View logs
sudo journalctl -u gomail -f

# Search logs
sudo journalctl -u gomail -p warn     # Warnings+errors
sudo journalctl -u gomail -p err      # Errors only
sudo journalctl -u gomail -S "2 hours ago"

# Export logs
sudo journalctl -u gomail -o short > gomail.log
```

### Configure Log Rotation

Edit `/etc/logrotate.d/gomail`:

```
/var/log/gomail.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 gomail gomail
    postrotate
        systemctl reload gomail > /dev/null 2>&1 || true
    endscript
}
```

## Updating

### Backup Before Updating

```bash
# ALWAYS backup before update
sudo -u gomail cp /opt/gomail/data/mail.db \
  /opt/gomail/data/mail.db.backup.$(date +%Y%m%d)
```

### Update Process

```bash
# 1. Get latest code
cd /path/to/gomail-source
git pull origin main

# 2. Build
go build -o gomail

# 3. Check binary
./gomail -version

# 4. Stop service
sudo systemctl stop gomail

# 5. Backup current binary
sudo cp /opt/gomail/gomail /opt/gomail/gomail.backup

# 6. Deploy new binary
sudo cp gomail /opt/gomail/

# 7. Test config
/opt/gomail/gomail -config /opt/gomail/config.json -test

# 8. Restart
sudo systemctl start gomail

# 9. Verify
sudo systemctl status gomail
sudo journalctl -u gomail -n 20
```

### Rollback

```bash
# If something goes wrong
sudo systemctl stop gomail
sudo cp /opt/gomail/gomail.backup /opt/gomail/gomail
sudo systemctl start gomail
```

## Troubleshooting

### Server won't start

```bash
# Check logs
sudo journalctl -u gomail -n 50

# Common issues:
# - Port already in use: sudo netstat -tulpn | grep :25
# - Database locked: check permissions on /opt/gomail/data
# - Config invalid: /opt/gomail/gomail -config /opt/gomail/config.json
```

### Certificate renewal failing

```bash
# Check Let's Encrypt logs
sudo journalctl -u gomail | grep acme

# Verify port 80
sudo netstat -tulpn | grep :80

# Verify domain DNS
nslookup mail.example.com

# Manual renewal test
sudo -u gomail /opt/gomail/gomail -config /opt/gomail/config.json -check-cert
```

### Emails not sending

```bash
# Check queue
sudo -u gomail sqlite3 /opt/gomail/data/mail.db \
  "SELECT * FROM outbound_queue LIMIT 5;"

# Check logs for delivery errors
sudo journalctl -u gomail | grep -i "deliver\|error"

# Test DNS resolution
dig mx example.com
dig a mail.example.com

# See delivery worker status
sudo systemctl status gomail
```

### High memory/CPU usage

```bash
# Check what's consuming resources
top -b -p $(pidof gomail)

# Check for stuck processes
ps aux | grep gomail

# Check queue size
sudo -u gomail sqlite3 /opt/gomail/data/mail.db \
  "SELECT COUNT(*) FROM outbound_queue;"

# If queue is huge, increase workers in config.json:
# "delivery": { "queue_workers": 4 }
```

### Inbound SMTP not accepting mail

```bash
# Check port 25 is listening
sudo netstat -tulpn | grep :25

# Test connection
telnet localhost 25

# Check logs
sudo journalctl -u gomail -f | grep -i smtp

# Verify DNS MX record
dig mx example.com
# Should show: example.com MX 10 mail.example.com.
```

## Backups & Disaster Recovery

### What to Backup

```bash
/opt/gomail/data/mail.db          # All messages, accounts, domains
/opt/gomail/data/attachments/     # Email attachments
/opt/gomail/config.json           # Database paths, credentials
```

### Automated Backup

```bash
#!/bin/bash
# /usr/local/bin/backup-gomail.sh

BACKUP_BASE="/backups/gomail"
RETENTION_DAYS=30
TODAY=$(date +%Y-%m-%d)
BACKUP_DIR="$BACKUP_BASE/$TODAY"

mkdir -p "$BACKUP_DIR"

# Backup database
sudo cp /opt/gomail/data/mail.db "$BACKUP_DIR/"

# Backup config
sudo cp /opt/gomail/config.json "$BACKUP_DIR/"

# Backup attachments
tar -czf "$BACKUP_DIR/attachments.tar.gz" \
  /opt/gomail/data/attachments

# Compress
cd "$BACKUP_BASE"
tar -czf "$TODAY.tar.gz" "$TODAY"

# Cleanup old backups
find "$BACKUP_BASE" -type d -mtime +$RETENTION_DAYS -exec rm -rf {} \; 2>/dev/null
find "$BACKUP_BASE" -type f -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete

chmod 600 "$BACKUP_DIR"/*
```

### Restore from Backup

```bash
# 1. Stop service
sudo systemctl stop gomail

# 2. Restore database
sudo cp /backups/gomail/YYYY-MM-DD/mail.db /opt/gomail/data/

# 3. Restore attachments
sudo tar -xzf /backups/gomail/YYYY-MM-DD/attachments.tar.gz -C /opt/gomail/data/

# 4. Fix permissions
sudo chown -R gomail:gomail /opt/gomail/data

# 5. Restart
sudo systemctl start gomail

# 6. Verify
sudo systemctl status gomail
```

## Performance Tuning

### For High Volume (1M+ messages/day)

```json
{
  "smtp": {
    "max_connections": 200,
    "listen_addr": ":25"
  },
  "delivery": {
    "queue_workers": 4
  },
  "store": {
    "db_path": "/opt/gomail/data/mail.db"
  }
}
```

Plus systemd limits:
```ini
LimitNOFILE=200000
LimitNPROC=200000
```

### Database Indexing

```bash
# Check current indexes
sudo -u gomail sqlite3 /opt/gomail/data/mail.db \
  ".indexes"

# Add indexes for common queries (if not present)
sudo -u gomail sqlite3 /opt/gomail/data/mail.db << EOF
CREATE INDEX IF NOT EXISTS idx_messages_account_created 
ON messages(account_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_outbound_status 
ON outbound_queue(status);
EOF
```

### Network Tuning

```bash
# Increase system limits
sudo sysctl -w net.core.somaxconn=4096
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=2048

# Make persistent in /etc/sysctl.conf
```

## Security Hardening

**Already in systemd service:**
- Strict system protection
- Limited capabilities (only CAP_NET_BIND_SERVICE)
- PrivateTmp, ProtectHome
- Resource limits
