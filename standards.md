# Standards deployment checklist

This is the operator checklist. Implementation details and limitations are in
[STANDARDS_AUDIT.md](STANDARDS_AUDIT.md).

## Before accepting Internet mail

- Publish A/AAAA and MX records for the server hostname.
- Configure matching forward and PTR DNS.
- Publish SPF, generate/publish the current DKIM key, and begin DMARC with
  `p=none` plus aggregate reporting before increasing enforcement.
- Use a valid TLS certificate and TLS 1.2 or newer.
- Confirm port 25 inbound and outbound connectivity.
- Test remote delivery, bounce behavior and local delivery.

## Optional transport policies

- MTA-STS requires `_mta-sts.<domain>` TXT plus an HTTPS policy at
  `https://mta-sts.<domain>/.well-known/mta-sts.txt`.
- TLS-RPT uses `_smtp._tls.<domain>` TXT. GoMail reporting is partial; monitor
  delivery logs independently.
- DANE requires DNSSEC from the zone through the TLSA record. Publish TLSA at
  `_25._tcp.<mx-host>`. Use optional mode while validating deployment, then
  required mode only if DNSSEC/TLSA availability is operationally reliable.

## Mail clients

Mail-client services are disabled by default. When explicitly enabled:

- POP3: port 995 with implicit TLS.
- SMTP submission: port 587 with STARTTLS and authentication.
- Username: full mailbox email address.
- IMAP: port 993 with implicit TLS, when its separate switch is enabled.
- Thunderbird autoconfiguration and Microsoft Autodiscover advertise only
  enabled, TLS-backed services.

## Continuous checks

- SPF, DKIM and DMARC results on representative inbound/outbound mail.
- Queue age, retry/failure rate and available disk space.
- Certificate and DNSSEC signature expiry.
- `/healthz` and `/readyz`.
- Backup integrity and isolated restore drills.
- Abuse reports, blocklists and IP reputation.

Authentication success improves trust but does not guarantee inbox placement.
