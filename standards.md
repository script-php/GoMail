Great question! Since your server already successfully delivers to major providers, you're doing most things right. Here are the current port 25 standards and best practices that matter today:

## Core SMTP Standards (RFC 5321)

### 1. **Strict RFC Compliance**
- **EHLO/HELO** - Must handle both, EHLO preferred
- **Line endings** - Must accept CRLF, LF, and CR (many senders are sloppy)
- **8BITMIME** - Advertise and handle 8-bit content correctly
- **SMTPUTF8** - Unicode in email addresses (increasingly important)
- **PIPELINING** - Command pipelining for performance
- **CHUNKING** (RFC 3030) - Large message handling

### 2. **Required Extensions to Advertise**
```
250-PIPELINING
250-SIZE 52428800
250-8BITMIME
250-SMTPUTF8
250-STARTTLS
250-AUTH (optional, for submission port)
250-DSN (Delivery Status Notifications)
250-ENHANCEDSTATUSCODES
```

## Security Standards

### 3. **STARTTLS Strict Mode**
- **MTA-STS** (RFC 8461) - Enforce TLS for your domain
- **TLS-RPT** (RFC 8460) - Report TLS failures
- **DANE** (RFC 7672) - DNSSEC-based TLSA records
- **Do not** downgrade to plaintext if peer supports TLS

### 4. **Authentication Results Headers**
You're already adding these, but ensure:
```
Authentication-Results: mail.yourdomain.com;
    spf=pass smtp.mailfrom=example.com;
    dkim=pass header.d=example.com;
    dmarc=pass header.from=example.com;
    arc=pass
```
Modern receiving servers **require** these for good deliverability.

### 5. **SMTP Strict Transport Security**
Implement per-domain policies:
- `_mta-sts.yourdomain.com` TXT record with policy
- Enforce TLS, valid certificates, specific CAs

## Deliverability Standards

### 6. **Bounce Handling**
- **DSN** (RFC 3464) - Delivery status notifications with machine-readable codes
- **Variable envelope return path (VERP)** - Track bounces per recipient
- **RFC 3463** - Enhanced status codes (e.g., `5.1.1` for bad mailbox)

### 7. **Feedback Loops (FBL)**
- Register with major providers (Google, Microsoft, Yahoo, etc.)
- Handle ARF (Abuse Reporting Format) reports
- Process complaints automatically

### 8. **List-Unsubscribe**
For bulk/digest emails:
```
List-Unsubscribe: <mailto:unsubscribe@domain.com?subject=unsubscribe>,
    <https://domain.com/unsubscribe>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
```

## Anti-Spam & Reputation

### 9. **Rate Limiting Best Practices**
- **Per-IP**: 60 connections/minute, 30 messages/minute
- **Per-domain**: Track reputation
- **Greylisting** for suspicious sources
- **Tarpitting** on repeated failures

### 10. **Reverse DNS (PTR)**
- Must match your HELO/EHLO hostname
- IP → hostname → IP should match
- Major providers check this strictly

### 11. **SMTP Banner Best Practices**
```
220 mail.yourdomain.com ESMTP GoMail ready
```
- Include hostname that resolves to your IP
- No version disclosure
- No "Welcome" or unnecessary text

## Modern Requirements

### 12. **BIMI** (Brand Indicators)
```
https://yourdomain.com/logo.svg
```
Display brand logos in supported clients (Gmail, Yahoo, Fastmail)

### 13. **SMTP TLS Reporting**
- `smtp-tls-report@yourdomain.com` receives reports
- Process and fix TLS issues proactively

### 14. **IPv6 Support**
- AAAA records for all mail hosts
- Many providers prefer IPv6 for better deliverability

### 15. **Message Size Optimization**
- Advertise `SIZE` correctly
- Handle large messages via chunking
- 25-50MB is standard max

## Connection Management

### 16. **Connection Limits**
```
Max concurrent: 100-200
Max per IP: 10-20
Queue size: 50-100
Timeout: 300 seconds (RFC requirement)
```

### 17. **Greeting Delay**
Delay initial banner by 2-5 seconds to filter out spam bots that don't wait

### 18. **Postfix-style Checks**
```
- reject_non_fqdn_helo_hostname
- reject_unknown_helo_hostname
- reject_unknown_sender_domain
- reject_unknown_recipient_domain
```

## Error Handling Standards

### 19. **Enhanced Status Codes**
Use proper codes:
| Code | Meaning |
|------|---------|
| `2.1.5` | Destination address valid |
| `4.2.2` | Mailbox full (temporary) |
| `5.1.1` | Bad destination mailbox |
| `5.7.1` | Relay denied / policy |

### 20. **SMTPUTF8 Handling**
```
MAIL FROM:<user@example.com> SMTPUTF8
RCPT TO:<用户@例子.com>
```
Support for non-ASCII email addresses (IDNA2008)

## Monitoring & Compliance

### 21. **SMTP Logging**
Log all transactions with:
- Timestamp (UTC)
- IP, HELO, MAIL FROM, RCPT TO
- Message ID
- Delivery status
- TLS cipher used

### 22. **CAN-SPAM / GDPR Compliance**
- `List-Help` header for subscription info
- Clear unsubscribe mechanisms
- Honor unsubscribe requests within 48 hours

## Testing Checklist

You can verify compliance with:
```bash
# Check SMTP compliance
swaks --to test@yourdomain.com --server yourdomain.com --tls

# Check MTA-STS
openssl s_client -connect yourdomain.com:25 -starttls smtp

# Check all records
dig +short _mta-sts.yourdomain.com TXT
dig +short yourdomain.com TLSA _25._tcp
```

## What Major Providers Look For

| Provider | Strict About |
|----------|--------------|
| **Gmail** | IP reputation, DMARC alignment, reverse DNS, TLS, no spam traps |
| **Outlook** | Sender score, consistent volume, low bounce rate, FBL registration |
| **Yahoo** | Domain age, authentication, complaint rate <0.1% |
| **Yandex** | DKIM signature, IP not in RBL, volume patterns |

Since you're already delivering to all these providers, you likely have most of this covered. The main areas to double-check would be:
- **MTA-STS** and **TLS-RPT** implementation
- **BIMI** for brand display
- **List-Unsubscribe** for bulk emails
- **IPv6** readiness
- **Enhanced status codes** for better bounce handling

Is there a specific area you'd like to dive deeper into or verify in your implementation?