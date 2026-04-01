# GoMail Standards Compliance Audit

**Date:** March 31, 2026  
**Status:** Production-ready for basic delivery, missing advanced features  

---

## ✅ IMPLEMENTED STANDARDS

### Core RFC 5321 SMTP Compliance
- ✅ **EHLO/HELO** - Both supported, EHLO preferred (session.go:177)
- ✅ **Line endings** - Handles CRLF, LF properly (session.go uses bufio.Reader)
- ✅ **8BITMIME** - Advertised in EHLO (session.go:124)
- ✅ **ENHANCEDSTATUSCODES** - Advertised (session.go:125)  
- ✅ **PIPELINING** - Advertised (session.go:126)
- ✅ **SIZE limit** - Advertised and enforced (session.go:123, 241-244)
- ✅ **STARTTLS** - Full support with TLS upgrade (session.go:159-186)

### Security & Authentication
- ✅ **DKIM Signing** - Per-domain DKIM signing on outbound (delivery/queue.go:44-68)
- ✅ **DKIM Verification** - Inbound messages verified (smtp/inbound.go:auth checks)
- ✅ **SPF Verification** - Checked on inbound (auth/spf.go)
- ✅ **DMARC Verification** - Checked on inbound (auth/dmarc.go)
- ✅ **ARC Chain** - Full implementation with signing (delivery/worker.go:283-351)
- ✅ **Authentication-Results Headers** - Added to inbound (smtp/inbound.go)
- ✅ **Reverse DNS (PTR)** - Verified (dns/ptr.go with forward-confirmed lookup)

### Connection Management  
- ✅ **Max connections** - Limited to config.SMTP.MaxConnections (default 100)
- ✅ **Max recipients** - Limited to config.SMTP.MaxRecipients (default 100)
- ✅ **Message size limit** - Enforced (config default 25MB, ~26MB)
- ✅ **Read/Write timeouts** - Both configurable (config default 60s each)
- ✅ **Connection rate limiting** - Per IP (smtp/ratelimit.go)
- ✅ **Message rate limiting** - Per IP (smtp/ratelimit.go, messages_per_minute)

### Deliverability
- ✅ **Proper SMTP banner** - Includes hostname, no version disclosure (session.go:81)
- ✅ **MAIL FROM validation** - Checked syntax and format
- ✅ **RCPT TO validation** - Checks domain and account existence
- ✅ **Received header** - Added to all inbound messages
- ✅ **Message-ID** - Generated per message

### MTA-STS & Security Policies
- ✅ **MTA-STS Policy** - Endpoint at `/.well-known/mta-sts.txt` (web/handlers/mta_sts.go)
- ✅ **MTA-STS structure** - RFC 8461 compliant policy (mta_sts/policy.go)
- ✅ **TLS enforcement** - Enforced via STARTTLS (smtp/outbound.go:94-110)

### Error Handling
- ✅ **Reply codes** - Proper SMTP codes (220, 250, 354, 452, 500, 503, etc.)
- ✅ **Multiline responses** - Supported (session.go:345-349)
- ✅ **RSET support** - Connection reset (session.go:338-342)
- ✅ **QUIT support** - Graceful closure (session.go:104-106)
- ✅ **VRFY command** - Accepted (session.go:108)
- ✅ **NOOP command** - Accepted (session.go:101)

### Configuration
- ✅ **Configurable parameters** - Per docs/config.md
- ✅ **Rate limiting config** - connections_per_minute, messages_per_minute
- ✅ **TLS mode selection** - autocert, manual, none
- ✅ **DKIM algorithm choice** - ed25519, rsa

---

## ❌ NOT IMPLEMENTED

### SMTP Extensions
- ❌ **SMTPUTF8** (RFC 6531) - Not advertised in EHLO; Unicode email addresses not supported
  - Impact: Cannot send/receive emails with non-ASCII addresses (e.g., 用户@example.com)
  - **Priority:** Medium (increasingly important for international email)

- ❌ **DSN** (RFC 3464) - Delivery Status Notifications not implemented
  - Impact: Cannot provide detailed bounce reports (e.g., "user unknown", "mailbox full")
  - **Priority:** High (essential for real-world deployments)

- ❌ **CHUNKING** (RFC 3030) - Not supported for large messages
  - Impact: No alternative delivery mechanism for large files
  - **Priority:** Low (SIZE limit works adequately)

### Bounce & Feedback Handling
- ❌ **VERP** (Variable Envelope Return Path) - Not implemented
  - Impact: Cannot track per-recipient bounces automatically
  - **Priority:** Medium (useful for bulk email analytics)

- ❌ **ARF** (Abuse Reporting Format) - Structure exists but not receiving/processing
  - Impact: Cannot process complaint reports from ISPs
  - **Priority:** Medium (important for abuse management)

- ❌ **Enhanced Status Codes** - Generic codes used; no RFC 3463 specifics
  - Example: `550 User not found` instead of `5.1.1 User not found`
  - **Priority:** Low (basic codes work for compatibility)

### TLS & Security
- ❌ **DANE** (RFC 7672) - DNSSEC-based certificate validation not implemented
  - Impact: No cryptographic verification of mail server certificates via DNS
  - **Priority:** Low (STARTTLS + CA verification is adequate for now)

- ❌ **TLS-RPT Sending** - Structure exists but doesn't send reports
  - Impact: Cannot report TLS failures to remote domains for analysis
  - **Priority:** Low (internal reporting only)

- ❌ **Greeting delay** - 220 banner sent immediately
  - Impact: Cannot slow down lightweight spam bots
  - **Priority:** Low (rate limiting already in place)

### Modern Features
- ❌ **IPv6 Support** - Only IPv4 connections (outbound: "tcp4", inbound works but no AAAA)
  - Impact: Cannot connect to IPv6-only mail servers
  - **Priority:** Medium (future-proofing, not critical today)

- ❌ **BIMI** (Brand Indicators for Message Identification)
  - Impact: No brand logo display in Gmail/Yahoo inboxes
  - **Priority:** Low (visual enhancement only)

- ❌ **List-Unsubscribe Headers** - Not automatically added
  - Impact: Bulk emails won't show unsubscribe options
  - **Priority:** Medium (important for compliance)

- ❌ **SMTP-specific domain policies** - MTA-STS is generic for all domains
  - Impact: All domains use same MTA-STS policy (works but not flexible)
  - **Priority:** Low (current implementation adequate)

### Anti-Spam Mechanisms
- ❌ **Greylisting** - Not implemented
  - Impact: No temporary rejection of unknown senders
  - **Priority:** Low (you're already selective with RCPT TO checks)

- ❌ **Tarpitting** - No delays on failed commands
  - Impact: Cannot slow down brute-force attempts
  - **Priority:** Low (rate limiting covers most cases)

- ❌ **HELO validation** - No strict checks on client HELO/EHLO
  - Missing: `reject_non_fqdn_helo_hostname`, `reject_unknown_sender_domain`, etc.
  - **Priority:** Low (trust-based model is simpler for now)

### Logging & Observability
- ❌ **Complete transaction logging** - Basic logs exist but not comprehensive
  - Missing: Full TLS cipher info, command-by-command logging, structured logs
  - **Priority:** Low (current logging adequate for debugging)

- ❌ **SMTP audit trail** - Commands not logged in order
  - **Priority:** Low (optional for compliance)

---

## PRIORITY RECOMMENDATIONS

### **HIGH Priority** (Should implement)
1. **DSN (Delivery Status Notifications)** - RFC 3464
   - Enables bounce handling, delivery reports
   - File: New module `smtp/dsn.go` or extension to `delivery/`
   - Effort: Medium (1-2 days)

2. **SMTPUTF8** - RFC 6531
   - Support Unicode in email addresses
   - Files: `smtp/session.go` (advertise), `smtp/inbound.go` (handle), database schema update
   - Effort: Low (0.5-1 day)

3. **List-Unsubscribe Headers** - RFC 8367
   - Add to compose handler for bulk emails
   - Files: `web/handlers/compose.go`
   - Effort: Low (2-3 hours)

### **MEDIUM Priority** (Nice to have)
1. **IPv6 Support** - RFC 5321
   - Enable connection to IPv6-only servers
   - Files: `smtp/outbound.go` (change "tcp4" to "tcp"), DNS MX lookup
   - Effort: Low (1-2 hours)

2. **VERP** - Variable Envelope Return Path
   - Per-recipient bounce tracking
   - Files: `smtp/session.go`, `delivery/`
   - Effort: Medium (1-2 days)

3. **ARF Processing** - RFC 5965
   - Handle abuse reports from ISPs
   - Files: New module `reporting/arf.go`
   - Effort: Medium (1-2 days)

4. **TLS-RPT Sending** - RFC 8460 
   - Report TLS failures to remote domains
   - Files: Extend `reporting/tlsrpt.go`, add sending logic
   - Effort: Medium (1-2 days)

### **LOW Priority** (Enhancement)
1. **DANE** - RFC 7672 (complex DNSSEC)
2. **BIMI** - Brand logos (visual only)
3. **Greylisting** - Additional spam filtering
4. **Tarpitting** - Spam bot slowdown
5. **Enhanced Status Codes** - RFC 3463 (cosmetic)
6. **Per-domain MTA-STS** - Generic policy adequate
7. **SMTP command logging** - Current logs sufficient

---

## QUICK WINS (Low effort, good impact)

1. **Add SMTPUTF8 support** ✏️ 1 hour
   - Add to EHLO response: `"SMTPUTF8"`
   - File: `smtp/session.go` line 124

2. **Add IPv6** ✏️ 30 minutes
   - Change `"tcp4"` to `"tcp"` in `smtp/outbound.go` line 45
   - Verify DNS AAAA records work

3. **Fix DNS check script** ✏️ 10 minutes
   - Already checks SMTPUTF8 but it's not advertised yet

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

**Overall Status:** ✅ **Production-ready for basic SMTP**

GoMail implements the **essential SMTP standards** needed for reliable email delivery:
- ✅ RFC 5321 (EHLO, message delivery)
- ✅ RFC 6376 (DKIM signing/verification)
- ✅ RFC 7208 (SPF verification)  
- ✅ RFC 7489 (DMARC verification)
- ✅ RFC 8617 (ARC chain)
- ✅ RFC 8461 (MTA-STS policy)

**What's missing** are primarily **optional modern features** (DSN, SMTPUTF8, IPv6, etc.) that improve deliverability and robustness but aren't strictly necessary for basic operation.

Since mail is already being delivered successfully to Gmail, Outlook, Yahoo, and Yandex, you have a **solid foundation**. The recommended next steps are the quick wins above (SMTPUTF8, IPv6, DSN).
