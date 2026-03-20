# DNS Records Configuration

This document lists ALL DNS records needed for a fully compliant mail server.

Replace `example.com` with your domain and `mail.example.com` with your mail server hostname.

## 1. MX Record
Points your domain's mail to your server.
```
example.com.  IN  MX  10  mail.example.com.
```

## 2. A Record
Points your mail hostname to your server IP.
```
mail.example.com.  IN  A  203.0.113.1
```

## 3. AAAA Record (optional, if you have IPv6)
```
mail.example.com.  IN  AAAA  2001:db8::1
```

## 4. SPF Record
Tells the world only your server sends mail for your domain.
```
example.com.  IN  TXT  "v=spf1 mx a -all"
```
- `mx` — allow servers in MX records
- `a` — allow servers in A records
- `-all` — reject everything else (hard fail)

## 5. DKIM Record
Publish your public key so receivers can verify signatures.

After running `gomail -setup`, paste the content from `keys/dkim_dns_record.txt`:
```
mail._domainkey.example.com.  IN  TXT  "v=DKIM1; k=ed25519; p=<BASE64_PUBLIC_KEY>"
```

**Note:** The selector (`mail`) matches `dkim.selector` in config.json.

## 6. DMARC Record
Policy for what receivers should do with failed SPF/DKIM checks.
```
_dmarc.example.com.  IN  TXT  "v=DMARC1; p=quarantine; rua=mailto:admin@example.com; adkim=r; aspf=r; pct=100"
```
- `p=quarantine` — quarantine failing messages (use `reject` once confident)
- `rua=mailto:...` — where to send aggregate reports
- `adkim=r` — relaxed DKIM alignment
- `aspf=r` — relaxed SPF alignment

## 7. MTA-STS Record
Enables MTA Strict Transport Security.
```
_mta-sts.example.com.  IN  TXT  "v=STSv1; id=20260101"
```
**Note:** Update the `id` value whenever you change your MTA-STS policy.

## 8. TLS Reporting (TLS-RPT)
Receive reports about TLS connection failures.
```
_smtp._tls.example.com.  IN  TXT  "v=TLSRPTv1; rua=mailto:admin@example.com"
```

## 9. PTR Record (Reverse DNS)
Configure with your hosting provider. Your server IP must resolve back to your hostname.
```
203.0.113.1  PTR  mail.example.com.
```

## 10. TLSA Record (DANE, optional)
If your domain uses DNSSEC, add a TLSA record for certificate pinning.
Run `gomail` and check the logs for the TLSA record value.
```
_25._tcp.mail.example.com.  IN  TLSA  3 1 1  <SHA256_HASH>
```

## Verification

Run the DNS check script:
```bash
./scripts/dns_check.sh example.com mail.example.com mail
```

External tools:
- [MXToolbox](https://mxtoolbox.com/)
- [Mail-tester](https://www.mail-tester.com/)
- [DMARC Analyzer](https://www.dmarcanalyzer.com/)
