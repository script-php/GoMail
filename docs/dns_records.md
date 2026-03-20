# DNS Records Guide

This guide covers DNS configuration for each domain added to GoMail.

## Overview

When you add a domain to GoMail via the admin panel, the server displays:
1. **DKIM public key** (for signing outbound emails)
2. **DNS records required** for authentication and delivery

These must be configured in your domain's DNS provider.

## Quick Start: Required Records

For each domain, configure 3 essential records:

| Record | Example | Purpose |
|--------|---------|---------|
| MX | `example.com MX 10 mail.example.com.` | Route mail to your server |
| SPF | `example.com TXT "v=spf1 mx ~all"` | Sender authentication |
| DKIM | `mail._domainkey.example.com TXT "v=DKIM1; k=ed25519; p=..."` | Email signing |

Optional but recommended:
- **DMARC** — Policy for failed auth checks
- **CAA** — Certificate authority authorization
- **Reverse DNS (PTR)** — Critical for deliverability

## Detailed Record Configuration

### 1. A Record (Infrastructure)

Maps mail server hostname to IP address.

```
mail.example.com     A    203.0.113.1
```

| Field | Value |
|-------|-------|
| Type | A |
| Name | `mail.example.com` |
| Value | Your server IP (e.g., 203.0.113.1) |
| TTL | 3600 |

**For IPv6:**
```
mail.example.com     AAAA    2001:db8::1
```

### 2. MX Record (Mail Routing)

Tells other servers where to send emails for your domain.

```
example.com     MX     10     mail.example.com.
```

| Field | Value |
|-------|-------|
| Type | MX |
| Name | `@` (root domain, or leave blank) |
| Mail Server | `mail.example.com.` (with trailing dot) |
| Priority | `10` (lower = higher priority) |
| TTL | 3600 |

**For multiple mail servers:**
```
example.com     MX    10    mail1.example.com.
example.com     MX    20    mail2.example.com.
```

### 3. SPF Record (Sender Policy Framework)

Specifies which servers can send email for your domain.

```
example.com     TXT    "v=spf1 mx ~all"
```

| Field | Value |
|-------|-------|
| Type | TXT |
| Name | `@` (root domain) |
| Value | `v=spf1 mx ~all` |
| TTL | 3600 |

**Explanation:**
- `v=spf1` — SPF version
- `mx` — Allow MX servers
- `a` — Allow A record
- `~all` — Soft fail (treat others as suspicious)
- `-all` — Hard fail (reject others) - use after testing

**Multi-provider example:**
```
v=spf1 mx include:sendgrid.net include:mailgun.org ~all
```

### 4. DKIM Record (Email Signing)

Proves emails from your domain are genuine. GoMail generates unique keys per domain.

```
mail._domainkey.example.com     TXT     "v=DKIM1; k=ed25519; p=fD0qv..."
```

| Field | Value |
|-------|-------|
| Type | TXT |
| Name | `mail._domainkey.example.com` (selector=mail) |
| Value | Full key from admin panel |
| TTL | 3600 |

**How to get your key:**

1. Go to GoMail Admin → Domains
2. Click your domain
3. Scroll to "DNS Records"
4. Find DKIM TXT record
5. Copy entire `v=DKIM1...` string
6. Paste into DNS provider

**Different algorithms:**

**ED25519 (smaller, faster):**
```
v=DKIM1; k=ed25519; p=fD0qv7dVKOLqgK1X...
```

**RSA (wider compatibility):**
```
v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4...
```

### 5. DMARC Record (Failure Policy)

Specifies how receivers handle emails failing DKIM/SPF.

```
_dmarc.example.com     TXT     "v=DMARC1; p=quarantine; rua=mailto:admin@example.com"
```

| Field | Value |
|-------|-------|
| Type | TXT |
| Name | `_dmarc.example.com` (exact) |
| Value | See below |
| TTL | 3600 |

**Policies (choose one):**

```
# Monitor only (recommended start)
v=DMARC1; p=none; rua=mailto:admin@example.com; fo=1

# Quarantine (spam folder)
v=DMARC1; p=quarantine; rua=mailto:admin@example.com

# Reject (strict, use after testing)
v=DMARC1; p=reject; rua=mailto:admin@example.com
```

**Parameters:**
- `p=none|quarantine|reject` — Action policy
- `rua=mailto:email` — Aggregate report recipient
- `ruf=mailto:email` — Forensic report recipient
- `adkim=r|s` — Relaxed (r) or strict (s) DKIM alignment
- `aspf=r|s` — Relaxed (r) or strict (s) SPF alignment
- `fo=0|1` — Report all failures (1) or only policy fails (0)

### 6. CAA Record (Certificate Authority)

Restricts which CAs can issue certificates for your domain.

```
example.com     CAA     0 issue "letsencrypt.org"
```

| Field | Value |
|-------|-------|
| Type | CAA |
| Name | `@` (root domain) |
| Flags | 0 |
| Tag | issue |
| Value | `letsencrypt.org` |
| TTL | 3600 |

**For multiple CAs:**
```
example.com     CAA     0 issue "letsencrypt.org"
example.com     CAA     0 issue "digicert.com"
```

### 7. PTR Record (Reverse DNS)

Critical for email deliverability. Configure with your hosting provider.

| Field | Value |
|-------|-------|
| Type | PTR |
| IP | 203.0.113.1 (your server) |
| Hostname | mail.example.com. |

**Verify:**
```bash
dig -x 203.0.113.1
# Should return: mail.example.com
```

### 8. MTA-STS (Optional but Recommended)

Forces TLS connections and prevents downgrade attacks.

```
_mta-sts.example.com     TXT     "v=STSv1; id=20250101"
```

| Field | Value |
|-------|-------|
| Type | TXT |
| Name | `_mta-sts.example.com` (exact) |
| Value | `v=STSv1; id=<date>` |
| TTL | 3600 |

**Plus HTTP-served policy file** at `https://mta-sts.example.com/.well-known/mta-sts.txt`:

```
version: STSv1
mode: enforce
max_age: 604800
mx: mail.example.com
```

### 9. TLS-RPT (Optional)

Receive reports about TLS connection failures.

```
_smtp._tls.example.com     TXT     "v=TLSRPTv1; rua=mailto:admin@example.com"
```

| Field | Value |
|-------|-------|
| Type | TXT |
| Name | `_smtp._tls.example.com` (exact) |
| Value | `v=TLSRPTv1; rua=mailto:admin@example.com` |
| TTL | 3600 |

## Complete Single Domain Example

For `example.com` on server `mail.example.com` (IP: 203.0.113.1):

```
# Infrastructure
example.com         A        203.0.113.1
mail.example.com    A        203.0.113.1

# Mail routing
example.com         MX   10  mail.example.com.

# Authentication
example.com         TXT      "v=spf1 mx ~all"
mail._domainkey.example.com  TXT  "v=DKIM1; k=ed25519; p=fD0qv..."
_dmarc.example.com  TXT      "v=DMARC1; p=quarantine; rua=mailto:admin@example.com"

# Security (optional)
example.com         CAA      0 issue "letsencrypt.org"
_mta-sts.example.com TXT     "v=STSv1; id=20250101"
_smtp._tls.example.com TXT   "v=TLSRPTv1; rua=mailto:admin@example.com"
```

**With PTR record** (configured at hosting provider):
- 203.0.113.1 PTR mail.example.com.

## Multi-Domain Setup

For domains `example.com`, `example.org`, `example.net` all pointing to same server:

```
# example.com
example.com       MX     10  mail.example.com.
example.com       TXT    "v=spf1 mx ~all"
mail._domainkey.example.com  TXT  "v=DKIM1; k=ed25519; p=<unique-key-1>"

# example.org
example.org       MX     10  mail.example.com.
example.org       TXT    "v=spf1 mx ~all"
mail._domainkey.example.org  TXT  "v=DKIM1; k=ed25519; p=<unique-key-2>"

# example.net
example.net       MX     10  mail.example.com.
example.net       TXT    "v=spf1 mx ~all"
mail._domainkey.example.net  TXT  "v=DKIM1; k=ed25519; p=<unique-key-3>"

# Shared server records (one A record for all domains)
mail.example.com  A      203.0.113.1
```

**Key points:**
- All domains have **different DKIM keys** (generated per domain in admin panel)
- All domains point MX to **same mail server** (mail.example.com)
- Single **A record** for mail server IP
- Different DKIM **name** per domain:
  - `mail._domainkey.example.com` for example.com
  - `mail._domainkey.example.org` for example.org
  - etc.

## Verification

After adding records, verify propagation:

```bash
# Check MX
dig example.com MX

# Check SPF
dig example.com TXT | grep spf

# Check DKIM
dig mail._domainkey.example.com TXT

# Check DMARC
dig _dmarc.example.com TXT

# Check CAA
dig example.com CAA
```

**Online tools:**
- [MXToolbox](https://mxtoolbox.com) — MX, SPF, DKIM, DMARC
- [mail-tester](https://www.mail-tester.com/) — Complete email auth test
- [DMARC Analyzer](https://mxtoolbox.com/dmarc) — DMARC validation
- [What is my PTR](https://whatismyptr.com/) — Reverse DNS check

## GoMail Admin Panel

All required records displayed in **Admin** → **Domains** → **[Domain Name]**:

1. **DKIM Public Key** — Full TXT record value (copy directly)
2. **Selector** — Usually "mail" (matches _domainkey name)
3. **Algorithm** — ED25519 or RSA
4. **Key generation date** — When DKIM key was created
5. **DNS Records** section — All recommended records with exact names/values

## Propagation Timeline

- **Immediate:** A/MX records cached locally
- **5-15 minutes:** Usually global propagation
- **24 hours:** Guarantee all nameservers updated (TTL)
- **Recommendation:** Add SPF/DKIM/DMARC and wait 1 hour before testing

## Troubleshooting

### Mail not being delivered
- Verify MX record: `dig example.com MX` → should show mail.example.com
- Verify A record: `dig mail.example.com A` → should show your IP
- Check MX priority (lower = preferred)
- Verify server is listening on port 25

### DKIM not signing/verifying
- Check TXT record name: exactly `mail._domainkey.example.com`
- Verify full key copied (no truncation in TLS limit)
- Check selector matches config (`dkim.default_selector`)
- Wait for TTL if recently added
- Verify DKIM key hasn't rotated in admin panel

### Emails marked as spam
- Set SPF policy: change `~all` to `-all` (hard fail)
- Verify DKIM signature is valid (check with mail-tester)
- Set DMARC policy: start with `p=none`, monitor, then upgrade
- Configure Reverse DNS (PTR) — critical for deliverability
- Reduce email frequency (spam filter sees patterns)

### Let's Encrypt certificate won't renew
- Verify mail.example.com A record exists
- Ensure port 80 is open (ACME challenge)
- Check CAA record (if present) includes letsencrypt.org
- Verify `acme_email` in config is valid

### High bounce rate
- Check SPF includes all sender IPs
- Verify DKIM signing enabled (admin panel shows key)
- Check email content (spam patterns, formatting)
- Verify recipient lists (no role accounts like postmaster@)

## DNS Provider Guide

### AWS Route 53
1. Go to Hosted Zone
2. Create record:
   - Type: MX, Name: example.com, Value: 10 mail.example.com
   - Type: TXT, Name: mail._domainkey.example.com, Value: v=DKIM1...

### Cloudflare
1. DNS section
2. Add record (Type, Name, Content)
3. Leave proxy OFF for MX/TXT (gray cloud)

### GoDaddy
1. DNS Management
2. Points to table
3. Add new record (Type, Host, Value, TTL)

### Namecheap
1. Domain → Manage → Nameserver → DNS Records
2. Add record (Type, Host, Value, TTL)

## Security Best Practices

- **DKIM rotation:** Rotate keys annually (admin panel: generate new key)
- **SPF policy:** Use `-all` (hard fail) in production, start with `~all` (soft fail)
- **DMARC policy:** Start `p=none`, monitor, upgrade to `p=quarantine` or `p=reject`
- **CAA records:** Restrict to authorized CAs only
- **PTR record:** Configure reverse DNS (ask hosting provider)
- **TLS:** Enable MTA-STS to force TLS connections
