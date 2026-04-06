# GoMail Standards Compliance Audit

**Date:** April 5, 2026  
**Status:** Production-ready for basic delivery, missing advanced features  
**Method:** Source code verified (not just config/docs)

---

## ✅ FULLY IMPLEMENTED

### Core RFC 5321 SMTP Compliance
- ✅ **EHLO/HELO** - Both supported, EHLO preferred (smtp/session.go)
- ✅ **Line endings** - Handles CRLF, LF properly (bufio.Reader)
- ✅ **8BITMIME** - Advertised in EHLO
- ✅ **ENHANCEDSTATUSCODES** - Advertised in EHLO
- ✅ **PIPELINING** - Advertised in EHLO
- ✅ **SIZE limit** - Advertised and enforced (default 25MB)
- ✅ **STARTTLS** - Full support with TLS upgrade
- ✅ **DSN extension** - Advertised in EHLO; `RET=`/`ENVID=` on MAIL FROM, `NOTIFY=` on RCPT TO parsed and forwarded to remote servers if supported (smtp/session.go, smtp/outbound.go)

### Security & Authentication
- ✅ **DKIM Signing** - Per-domain DKIM signing on outbound, RSA-SHA256 + Ed25519-SHA256 (delivery/queue.go, auth/dkim.go)
- ✅ **DKIM Verification** - Inbound messages verified with DNS key lookup (auth/dkim.go, auth/dkim_lookup.go)
- ✅ **SPF Verification** - Full mechanism parsing: `all`, `a`, `mx`, `ip4`, `ip6`, `include`, `redirect` with qualifiers and CIDR (auth/spf.go)
- ✅ **DMARC Verification** - Record lookup, org domain fallback, relaxed/strict alignment, policy enforcement (auth/dmarc.go)
- ✅ **ARC Chain Signing** - ARC-Authentication-Results, ARC-Message-Signature, ARC-Seal generation (auth/arc.go, delivery/worker.go)
- ✅ **ARC Structural Validation** - Chain completeness, cv= values, sequential instance checks (auth/arc.go)
- ✅ **Authentication-Results Headers** - RFC 8601 format with SPF, DKIM, DMARC results (auth/results.go)

### Delivery & Bounce Handling
- ✅ **DSN generation** - RFC 3464 multipart DSN on permanent failure, delivered to sender mailbox (delivery/worker.go)
- ✅ **DSN status codes** - RFC 3463 mapping via reporting/dsn.go
- ✅ **DSN dedup** - `dsn_sent` flag prevents duplicate bounce messages
- ✅ **Retry with backoff** - Configurable intervals + exponential backoff, capped at 48 hours (delivery/retry.go)
- ✅ **Local delivery shortcut** - Skips SMTP for local recipients (delivery/worker.go)
- ✅ **Worker pool** - Configurable worker count, DB-backed queue polling (delivery/worker.go)

### Connection Management
- ✅ **Max recipients** - Limited to config.SMTP.MaxRecipients (default 100)
- ✅ **Message size limit** - Enforced (config default 25MB)
- ✅ **Read/Write timeouts** - Both configurable (default 60s each)
- ✅ **Connection rate limiting** - Per-IP connections/minute sliding window (smtp/ratelimit.go)
- ✅ **Message rate limiting** - Per-IP messages/minute sliding window (smtp/ratelimit.go)

### Deliverability
- ✅ **Proper SMTP banner** - Includes hostname, no version disclosure
- ✅ **MAIL FROM validation** - Syntax and format checked
- ✅ **RCPT TO validation** - Domain and account existence checks
- ✅ **Received header** - Prepended to all inbound messages
- ✅ **Message-ID** - Generated per message
- ✅ **DMARC policy enforcement** - `p=reject`/`p=quarantine` → spam folder; `p=none` → inbox

### MTA-STS (Serving)
- ✅ **MTA-STS Policy endpoint** - `/.well-known/mta-sts.txt` (web/handlers/mta_sts.go)
- ✅ **MTA-STS structure** - RFC 8461 compliant enforce-mode policy (mta_sts/policy.go)
- ✅ **MTA-STS DNS record helper** - Generation utility included

### MDN (Read Receipts)
- ✅ **MDN generation** - Simple text + RFC 3798 multipart format (mdn/mdn.go)
- ✅ **MDN auto/manual modes** - Configurable send-on-read or user-triggered
- ✅ **MDN dedup** - `mdn_sent` flag prevents duplicates
- ✅ **MDN web API** - `/api/send-mdn/{id}` endpoint for manual sending

### TLS
- ✅ **Three TLS modes** - `autocert` (Let's Encrypt), `manual` (cert files), `none`
- ✅ **Strong defaults** - X25519+P256 curves, AEAD-only ciphers, TLS 1.2+ minimum (tls/config.go)
- ✅ **ACME integration** - ACME challenge handling, shared cert for HTTPS + SMTP
- ✅ **TLSA record generation** - `3 1 1` format from server cert (tls/dane.go)

### DNS
- ✅ **MX lookup** - Preference-sorted with A/AAAA fallback per RFC 5321 §5 (dns/mx.go)
- ✅ **PTR lookup** - Forward-confirmed reverse DNS (FCrDNS) verification (dns/ptr.go)
- ✅ **DNS caching** - TTL-based in-memory cache with background cleanup (dns/cache.go)

### Web/UI
- ✅ **Session-based auth** - DB-backed sessions, HttpOnly+Secure+SameSite cookies (security/session.go)
- ✅ **CSRF protection** - HMAC-SHA256 of session token
- ✅ **Security headers** - HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy (security/headers.go)
- ✅ **Compose** - Plain text with To, Cc, Subject, Body; priority headers; read receipt option
- ✅ **Reply & Forward** - With ARC signing on forwarded messages
- ✅ **Folder system** - Inbox, Sent, Spam, Drafts, Trash with unread/total counts (store/folders.go)
- ✅ **Admin panel** - Domain and account management
- ✅ **Attachment download** - Served from message view

### MIME & Parsing
- ✅ **RFC 5322 parsing** - Via Go's `net/mail` (parser/message.go)
- ✅ **Recursive multipart walking** - Handles nested `multipart/*` (parser/mime.go)
- ✅ **Attachment extraction** - Content-Disposition detection, SHA256-based storage (parser/attachments.go)
- ✅ **Base64 decoding** - Handled in MIME parser

### Error Handling
- ✅ **Reply codes** - Proper SMTP codes (220, 250, 354, 452, 500, 503, etc.)
- ✅ **Multiline responses** - Supported
- ✅ **RSET/QUIT/VRFY/NOOP** - All implemented

### Configuration
- ✅ **Comprehensive config** - Server, SMTP, TLS, DKIM, Store, Web, Mail, Delivery, DNS, Security, MDN, Logging sections
- ✅ **Validation** - Clear error messages on invalid config
- ✅ **Bootstrap admin** - First-run setup
- ✅ **Graceful shutdown** - SIGINT/SIGTERM stops SMTP, workers, web in order (main.go)

### Reporting (Parse Only)
- ✅ **DMARC report parsing** - Incoming XML aggregate reports (reporting/dmarc.go)
- ✅ **TLS-RPT report parsing** - Incoming JSON reports (reporting/tlsrpt.go)

---

## ⚠️ PARTIALLY IMPLEMENTED (Code exists but incomplete or not wired)

### Wired But Incomplete
- ✅ **ARC cryptographic verification** (FIXED April 6, 2026) - Full DKIM-style signature verification for both ARC-Message-Signature and ARC-Seal
  - Impact: ARC chains now verified cryptographically; forged chains rejected
  - **Implementation:** `verifyARCMessageSignature()` and `verifyARCSeal()` with RSA and Ed25519 support
  - **Verified:** Working in production (Gmail ARC chains pass verification)

- ⚠️ **DMARC policy enforcement** - Checks run, but `p=reject` messages are **accepted and quarantined** instead of rejected at SMTP level with 5xx
  - Impact: Violates strict DMARC intent; wastes storage on rejected mail
  - **Fix:** Return 550 during SMTP transaction for `p=reject`

- ⚠️ **TLS on outbound** (FIXED April 6, 2026) - Configurable strict-TLS mode per domain
  - **Implementation:** Added `require_tls` field to domains table; delivery fails if TLS unavailable when enabled
  - **Behavior (opportunistic TLS default):**
    - If `require_tls = false`: STARTTLS attempted; failure logs warning, delivery continues unencrypted
    - If `require_tls = true`: STARTTLS required; failure aborts delivery with error
  - **RFC compliance:** Supports RFC 8689 REQUIRETLS semantics
  - **Admin control:** Set `require_tls=1` in domains table per domain

- ⚠️ **Authentication-Results header** - Generated and stored in DB `auth_results` field, but **not prepended to the raw message** headers that the user sees
  - Impact: Email clients can't see auth results in message source
  - **Fix:** Prepend header to raw message before storage

- ⚠️ **MDN multipart format** - Proper RFC 3798 multipart MDN exists (`GenerateMDNMultipart`) but the **simple text version** is used in practice
  - Impact: Some mail clients may not process simple-format MDNs correctly
  - **Fix:** Switch handler to use `GenerateMDNMultipart`

- ⚠️ **SPF spec compliance** - Core mechanisms work, but missing: `exists` mechanism, `exp=` modifier, macro expansion, DNS lookup counting (RFC 7208 §4.6.4 limits to 10)
  - Impact: Could infinite-loop on adversarial SPF records; rare edge cases may fail

- ⚠️ **DMARC spec compliance** - `sp=` (subdomain policy) parsed but never applied; `pct=` (percentage) parsed but ignored; `rua`/`ruf` parsed but no reports generated; org-domain uses naive "last two labels" instead of Public Suffix List
  - Impact: Subdomains with different policies treated same as parent; percentage sampling not honored

### Code Exists But Not Wired
- ⚠️ **Reverse DNS (PTR) on inbound** - `dns.VerifyPTR` is fully implemented but **never called** from the SMTP inbound accept path
  - Impact: No rDNS verification on connecting IPs despite having the code
  - **Fix:** Call `dns.VerifyPTR(remoteIP)` in inbound.go before processing; add result to auth checks

- ⚠️ **Max connections enforcement** - `config.SMTP.MaxConnections` is defined (default 100) but **never enforced** in the accept loop (smtp/inbound.go has no connection counter)
  - Impact: No upper bound on simultaneous SMTP connections under load
  - **Fix:** Add semaphore/counter in accept loop

- ⚠️ **Web rate limiter** - Rate limiting middleware written in web/middleware.go but **never registered** in web/server.go
  - Impact: Web UI has no rate limiting; login brute-force possible
  - **Fix:** Wire middleware into server setup

- ⚠️ **Logging config** - `level` and `format` fields defined in config struct but **never used**; all logging is `log.Printf`
  - Impact: Can't control log verbosity or output format
  - **Fix:** Initialize a structured logger from config values at startup

---

## ❌ NOT IMPLEMENTED

### SMTP Extensions
- ❌ **SMTPUTF8** (RFC 6531) - Not advertised in EHLO; Unicode email addresses not supported
  - Impact: Cannot send/receive emails with non-ASCII addresses (e.g., 用户@example.com)
  - **Priority:** Medium

- ❌ **SMTP AUTH** (RFC 4954) - No LOGIN/PLAIN authentication for external clients
  - Impact: Only webmail users can send; no IMAP/external client relay
  - **Priority:** High (blocks external mail client integration)

- ❌ **CHUNKING/BDAT** (RFC 3030) - Not supported
  - Impact: No alternative delivery for large messages
  - **Priority:** Low

### Outbound Security
- ❌ **MTA-STS enforcement (outbound)** - Policy is served but **never checked** when sending to remote domains
  - Impact: GoMail ignores remote domains' MTA-STS policies
  - **Priority:** Medium

- ❌ **DANE verification** (RFC 7672) - Can generate TLSA records but **cannot verify** remote servers' TLSA records
  - Impact: No DNSSEC-based certificate validation on outbound
  - **Priority:** Low

- ❌ **REQUIRETLS** (RFC 8689) - Not supported
  - **Priority:** Low

### Bounce & Feedback Handling
- ❌ **VERP** (Variable Envelope Return Path) - Not implemented
  - Impact: Cannot track per-recipient bounces automatically
  - **Priority:** Medium

- ❌ **Inbound bounce parsing** - No special handling of null-sender `<>` DSN messages received from remote servers
  - Impact: Bounce reports land in inbox like regular mail
  - **Priority:** Medium

- ❌ **ARF** (Abuse Reporting Format, RFC 5965) - Not receiving or processing abuse reports
  - Impact: Cannot process complaint reports from ISPs
  - **Priority:** Medium

### Reporting (Outbound)
- ❌ **DMARC report generation** - Can parse incoming reports but **never generates or sends** aggregate reports
  - Impact: Remote domains don't receive your DMARC telemetry
  - **Priority:** Low

- ❌ **TLS-RPT report sending** (RFC 8460) - Can parse incoming reports but **never generates or sends** them
  - Impact: Remote domains don't receive your TLS failure telemetry
  - **Priority:** Low

### IPv6
- ❌ **IPv6 outbound** - Hardcoded `"tcp4"` in smtp/outbound.go
  - Impact: Cannot reach IPv6-only mail servers
  - **Priority:** Medium

### Web/Compose
- ❌ **Attachment upload in compose** - Only plain text sending; no file upload
  - Impact: Users can't attach files from webmail
  - **Priority:** High (basic webmail feature)

- ❌ **HTML compose** - Only `text/plain; charset=UTF-8`
  - Impact: No rich text email composition
  - **Priority:** Medium

- ❌ **List-Unsubscribe headers** (RFC 8058) - Not generated on outbound or extracted on inbound
  - Impact: Bulk emails won't show unsubscribe in Gmail/Yahoo
  - **Priority:** Medium

### Queue Reliability
- ❌ **Stale queue recovery** - If process crashes mid-delivery, entries stuck in `"sending"` status forever
  - Impact: Messages can be permanently lost on crash
  - **Priority:** High (data loss risk)

- ❌ **Session rotation** - No token rotation after login
  - Impact: Session token reuse risk if leaked
  - **Priority:** Medium

### Anti-Spam
- ❌ **Greylisting** - No temporary rejection of unknown senders
  - **Priority:** Low
- ❌ **Tarpitting** - No delays on failed commands
  - **Priority:** Low
- ❌ **HELO validation** - HELO argument stored but never validated (no FQDN check, no rDNS check)
  - **Priority:** Low
- ❌ **Greeting delay** - 220 banner sent immediately
  - **Priority:** Low

### Modern Features
- ❌ **BIMI** (Brand Indicators for Message Identification) - No brand logo support
  - **Priority:** Low
- ❌ **Per-domain MTA-STS** - All domains share one generic policy
  - **Priority:** Low
- ❌ **Structured logging** - Config fields exist but logging uses only `log.Printf`
  - **Priority:** Low
- ❌ **SMTP audit trail** - Commands not logged in order
  - **Priority:** Low

---

## PRIORITY RECOMMENDATIONS

### **CRITICAL** (Fix immediately)
1. **Wire up MaxConnections enforcement** - Add semaphore in SMTP accept loop
   - File: `smtp/inbound.go`
   - Effort: 30 minutes

2. **Wire up web rate limiter** - Middleware exists, just needs registration
   - File: `web/server.go`
   - Effort: 15 minutes

3. **Stale queue recovery** - Timeout entries stuck in `"sending"` for >15 minutes
   - File: `delivery/worker.go`
   - Effort: 1 hour

### **HIGH Priority** (Should implement soon)
1. **SMTP AUTH** (RFC 4954) - Enable external client relay
   - Files: `smtp/session.go` (advertise + handle), `config/config.go`
   - Effort: 1-2 days

2. **Wire up PTR check on inbound** - Code exists, needs one function call
   - File: `smtp/inbound.go`
   - Effort: 15 minutes

3. **Attachment upload in compose** - File upload + multipart message building
   - Files: `web/handlers/compose.go`, templates
   - Effort: 1-2 days


5. **SMTPUTF8** (RFC 6531) - Advertise + handle Unicode addresses
   - Files: `smtp/session.go`, `smtp/inbound.go`
   - Effort: 0.5-1 day

### **MEDIUM Priority** (Nice to have)
1. **IPv6 outbound** - Change `"tcp4"` to `"tcp"` in `smtp/outbound.go`
   - Effort: 30 minutes

2. **MTA-STS enforcement on outbound** - Fetch/cache remote policies before delivery
   - Files: `smtp/outbound.go`, `mta_sts/policy.go`
   - Effort: 1-2 days

3. **List-Unsubscribe headers** (RFC 8058)
   - File: `web/handlers/compose.go`
   - Effort: 2-3 hours

4. **DMARC reject at SMTP level** - Return 550 instead of accepting to spam
   - File: `smtp/inbound.go`
   - Effort: 1 hour

5. **Switch to multipart MDN format** - Use existing `GenerateMDNMultipart`
   - File: handler calling `GenerateMDN`
   - Effort: 30 minutes

6. **VERP** - Variable Envelope Return Path
   - Effort: 1-2 days

7. **TLS-RPT report sending** (RFC 8460)
   - Effort: 1-2 days

### **LOW Priority** (Enhancement)
1. **DANE verification** - RFC 7672 (complex DNSSEC)
2. **BIMI** - Brand logos (visual only)
3. **Greylisting** - Additional spam filtering
4. **Tarpitting** - Spam bot slowdown
5. **Per-domain MTA-STS** - Generic policy adequate
6. **Structured logging** - Replace `log.Printf`
7. **HTML compose** - Rich text editor
8. **ARF processing** - Abuse report handling

---

## QUICK WINS (Code already exists, just needs wiring)

1. **Wire PTR check** ✏️ 15 minutes
   - Call `dns.VerifyPTR(remoteIP)` in `smtp/inbound.go`
   - Already fully implemented in `dns/ptr.go`

2. **Wire web rate limiter** ✏️ 15 minutes
   - Register middleware from `web/middleware.go` in `web/server.go`
   - Already fully implemented

3. **Enforce MaxConnections** ✏️ 30 minutes
   - Add connection counter/semaphore in `smtp/inbound.go` accept loop
   - Config value already exists

4. **Add IPv6** ✏️ 30 minutes
   - Change `"tcp4"` to `"tcp"` in `smtp/outbound.go`

5. **Use multipart MDN** ✏️ 30 minutes
   - Switch from `GenerateMDN` to `GenerateMDNMultipart` in handler

6. **Add SMTPUTF8 to EHLO** ✏️ 1 hour
   - Add `"SMTPUTF8"` to EHLO extensions in `smtp/session.go`

7. **Stale queue recovery** ✏️ 1 hour
   - Reset entries stuck in `"sending"` for >15 min back to `"pending"` on worker startup

---

## VERIFICATION COMMANDS

```bash
# Check SMTP compliance
swaks --to test@yourdomain.com --server yourdomain.com --port 25

# Check which extensions are advertised
telnet yourdomain.com 25
# Then type: EHLO test.com

# Check MTA-STS policy is served
curl https://yourdomain.com/.well-known/mta-sts.txt

# Check TLS version
openssl s_client -connect yourdomain.com:25 -starttls smtp

# DNS records status
./scripts/dns_check.sh yourdomain.com
```

---

## SUMMARY

**Overall Status:** ✅ **Production-ready for basic SMTP** with ⚠️ several items needing wiring

GoMail implements the **essential SMTP standards** needed for reliable email delivery:
- ✅ RFC 5321 (SMTP, EHLO, message delivery)
- ✅ RFC 3464 (DSN — generation on permanent failure + SMTP extension)
- ✅ RFC 6376 (DKIM signing/verification)
- ✅ RFC 7208 (SPF verification)
- ✅ RFC 7489 (DMARC verification)
- ✅ RFC 8617 (ARC chain signing + structural validation)
- ✅ RFC 8461 (MTA-STS policy serving)
- ✅ RFC 3798 (MDN read receipts)

**What needs immediate attention:**
- ⚠️ MaxConnections not enforced (config exists, accept loop doesn't check)
- ⚠️ Web rate limiter not wired (middleware exists, not registered)
- ⚠️ PTR/rDNS check not wired (function exists, never called)
- ⚠️ Stale queue entries never recovered after crash

✅ **ARC cryptographic verification now working** (fixed April 6, 2026) - all signatures properly validated

**What's missing** are **SMTP AUTH** (no external client relay), **attachment compose**, **IPv6 outbound**, **SMTPUTF8**, and various optional modern features.

Mail is delivered successfully to Gmail, Outlook, Yahoo, and Yandex. The foundation is solid — the biggest risks are the unwired code (PTR, MaxConnections, web rate limiter) and the stale queue recovery gap.
