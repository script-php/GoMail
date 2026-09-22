# DANE and DNSSEC behavior

GoMail applies DANE/TLSA to outbound SMTP MX connections. The implementation is
split between `dns/tlsa.go` (authenticated lookup/parsing), `tls/dane.go`
(certificate matching), and `smtp/outbound.go` (policy and handshake behavior).

## Security invariant

TLSA data is never treated as authoritative merely because a record was returned.
The DNS response must be authenticated by DNSSEC. The default resolver path uses
DNS-over-TLS resolvers with certificate verification and requires authenticated
data. A custom plain DNS resolver is safe only when it is local or reached over a
trusted network; a remote custom resolver should use
`host:853#tls-server-name`.

## Supported record semantics

| Usage | Name | Candidate and trust behavior |
|---:|---|---|
| 0 | PKIX-TA | Matching chain trust anchor; PKIX validation still required |
| 1 | PKIX-EE | Matching leaf/end entity; PKIX validation still required |
| 2 | DANE-TA | Matching chain trust anchor can establish DANE trust |
| 3 | DANE-EE | Matching leaf/end entity can establish DANE trust |

Selectors:

- `0`: complete DER certificate.
- `1`: DER SubjectPublicKeyInfo.

Matching types:

- `0`: exact selected bytes.
- `1`: SHA-256.
- `2`: SHA-512.

Malformed fields, unsupported values and invalid hex data are rejected. Usage 0
and 2 consider appropriate chain candidates; Usage 1 and 3 match the leaf.

## Policy modes

DANE enforcement is stored on the managed sender-domain record:

- `disabled` — no TLSA lookup; normal SMTP TLS/PKIX policy applies.
- `optional` — authenticated TLSA is evaluated when available. A lookup,
  malformed-record or mismatch problem is logged and delivery may fall back to
  ordinary PKIX according to the outbound TLS policy.
- `required` — authenticated usable TLSA must exist and authenticate the peer;
  otherwise delivery fails and retries according to queue classification.

Optional mode intentionally permits downgrade to PKIX if the DANE path is
unavailable. Use required mode only when DNSSEC and TLSA availability are
monitored and operationally reliable.

## Interaction with MTA-STS

MTA-STS and DANE are evaluated as separate transport-policy signals. Neither is
fabricated when its DNS discovery record is absent. The strictest applicable
requirement determines whether delivery may proceed. DANE authentication does
not make an out-of-policy MTA-STS MX name valid.

## Tests

`dns/tlsa_test.go` and `tls/dane_test.go` cover authenticated/unauthenticated
responses, all four usages, both selectors, all matching types, malformed
records, leaf/chain handling, PKIX requirements and enforcement behavior.

```bash
go test ./dns ./tls ./smtp
```

These deterministic tests do not replace live DNSSEC rollover, resolver outage,
certificate rotation and external SMTP interoperability exercises.

## Operational checks

```bash
dig +dnssec TLSA _25._tcp.mail.example.com
dig +dnssec DNSKEY example.com
```

Verify the AD bit through the resolver path actually used by GoMail. Monitor
DNSSEC signature expiry, TLSA/certificate rotation ordering and repeated lookup
or mismatch failures. Never publish a new required TLSA pin after replacing the
certificate; overlap records during controlled rotation.

## Known remaining work

- Broader live resolver and DNSSEC rollover tests.
- Complete TLS-RPT event/policy accounting for successful and failed DANE paths.
- Administrative configuration model clarity: enforcement currently belongs to
  managed sender domains, not arbitrary recipient-policy rows.
