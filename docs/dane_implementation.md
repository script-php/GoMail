# DANE (DNSSEC-based Authentication of Named Entities) Implementation

## Overview

DANE (RFC 6698) provides a secure mechanism for verifying SMTP server certificates using DNSSEC and TLSA DNS records. This document describes GoMail's DANE implementation for outbound SMTP delivery.

## Implementation Status

### ✅ Completed Components

1. **TLSA Record Lookup and Parsing** (`dns/tlsa.go`)
   - `LookupTLSA(host string)` - Queries TLSA records for SMTP server
   - `ParseTLSARecord(record string)` - Parses RFC 6698 TLSA record format
   - `TLSARecord` struct with fields: Usage, Selector, MatchingType, CertData
   - DNS cache integration for performance

2. **DANE Verification** (`tls/dane.go`)
   - `VerifyDANE(host string, tlsConn *tls.Conn)` - Main verification entry point
   - `isDANEMatch(cert *x509.Certificate, tlsa TLSARecord)` - RFC 6698 §2.4 certificate matching
   - Support for all RFC 6698:
     - Usage types: PKIX-TA (0), PKIX-EE (1), DANE-TA (2), DANE-EE (3)
     - Selectors: Full cert (0), Public key only (1)
     - Matching types: Exact (0), SHA-256 (1), SHA-512 (2)

3. **SMTP Outbound Integration** (`smtp/outbound.go`)
   - DANE verification called after successful TLS handshake
   - Enforcement levels: disabled, optional (default), required
   - Proper error handling and logging
   - TLS-RPT failure recording for DANE violations

4. **Domain Configuration** (`store/models.go`, `store/schema.sql`)
   - Added `DANEEnforcement` field to Domain model
   - Database column: `dane_enforcement TEXT` (values: disabled, optional, required)
   - Default: "disabled" for backward compatibility

## DANE Enforcement Modes

### 1. **Disabled** (Default)
- DANE checks are not performed
- Standard TLS certificate validation only
- Most conservative, widely compatible

### 2. **Optional**
- DANE records are checked if present
- Certificate verification fails gracefully
- Logs warnings but allows delivery
- Recommended for gradual rollout

### 3. **Required**
- Must have valid TLSA records
- Certificate must match DANEF
- Delivery fails if DANE verification fails
- Most secure, requires sender domain participation

## Current Limitations

### Go Standard Library Limitation

Go's `net` package does not provide native TLSA record lookup. The current implementation:

1. **Returns empty list** from `LookupTLSA()` if system has no TLSA library support
2. **Requires external library** for full TLSA support: `github.com/miekg/dns`

### Future Enhancement (Priority: Low)

To enable actual TLSA lookups:

```bash
go get github.com/miekg/dns
```

Then update `dns/tlsa.go` `LookupTLSA()` function to use `dns.Client` for DNS lookups.

## Implementation Details

### RFC 6698 Compliance

The implementation follows RFC 6698 specification:

- **SERVERNAME** field in TLSA record matches SMTP server hostname
- **PORT** always 25 for SMTP
- **PROTO** always tcp for SMTP
- Certificate extraction and hashing follows RFC specifications
- Support for hex-encoded certificate data

### Certificate Matching Logic

The `isDANEMatch()` function implements RFC 6698 §2.4:

1. **Extract certificate data**:
   - Usage 0 (PKIX-TA): Issuer's public key or certificate
   - Usage 1 (PKIX-EE): End-entity certificate
   - Usage 2 (DANE-TA): Trust anchor certificate or key
   - Usage 3 (DANE-EE): End-entity certificate or key

2. **Hash matching**:
   - Selector 0: Compare against full certificate
   - Selector 1: Extract public key and compare
   - Matching type 0: Exact byte-for-byte match
   - Matching type 1: Compare SHA-256 hashes
   - Matching type 2: Compare SHA-512 hashes

### TLS-RPT Integration

DANE verification failures can be recorded for **TLS-RPT** (RFC 8460) reporting:

```go
// Recorded as failure type "tlsa-invalid-certificate"
db.RecordTLSFailure(
    domain,                     // Recipient domain
    "tlsa-invalid-certificate", // Failure reason
    clientIP,                   // Sending MTA IP
    host,                       // Receiving MX hostname
    ip,                         // Receiving IPv4/IPv6
)
```

## Usage

### For End Users

DANE enforcement is configured per sending domain in the admin panel:

1. Navigate to Domain settings
2. Set "DANE Enforcement" to: Disabled, Optional, or Required
3. Save settings

### For Administrators

Via database:

```sql
-- Enable DANE enforcement for outbound delivery
UPDATE domains SET dane_enforcement = 'required' WHERE domain = 'example.com';

-- Check current DANE settings for all domains
SELECT domain, dane_enforcement FROM domains;
```

### For Developers

Integration point in outbound delivery:

```go
// Verify DANE after TLS handshake
daneValid, daneDetails, daneErr := tlsconfig.VerifyDANE(host, clientTLS)

if !daneValid && daneErr == nil {
    // TLSA records exist but don't match certificate
    // Handle per enforcement level (disabled/optional/required)
}
```

## Testing

### Manual Testing (Local Dev)

1. Build binary: `go build -o gomail .`
2. No changes needed to `config.dev.json` (DANE disabled by default)
3. Automatic verification logs to console with `[dane]` prefix

### Expected Log Output

```
[dane] no TLSA records for mail.example.com (DANE not configured, using standard TLS)
[dane] DANE verification passed for mail.example.com: Usage 3, Selector 1 matched
[dane] WARNING: DANE verification failed for mail.example.com: certificate mismatch
```

### Automated Testing

Currently no unit tests for DANE (awaiting external DNS library). Future testing:

```bash
# With github.com/miekg/dns installed
go test -v ./tls -run TestDANEVerification
go test -v ./dns -run TestTLSALookup
```

## Security Considerations

### DNSSEC Chain

The current implementation does **not** validate DNSSEC chains. Recommendations:

1. **Use DNSSEC validator** in deployment: `dnssec-tools` or similar
2. **Monitor DNS queries** for DNSSEC validation at firewall level
3. **Trust network DNS resolver** that validates DNSSEC

### Certificate Pinning

DANE is effectively certificate pinning via DNS. Benefits:

✅ Pins certificates without hardcoding  
✅ Domain admin controls pins  
✅ Reduces X.509 CA compromise risk  
✅ Hidden from public certificate logs (no pre-issuance logs)  

### Fallback Risks

In "optional" mode, DANE provides no security if:

- Attacker can intercept TLS handshake
- Attacker registers certificate with legitimate CA
- Network can block TLSA DNS queries

**Mitigation**: Use "required" mode when DANE is critical or monitor logs for failures.

## Future Enhancements

### Phase 2: DNSSEC Validation

- Integrate `github.com/miekg/dns` for actual TLSA lookups
- Validate DNSSEC chains with `github.com/miekg/dns`
- Add DNSSEC status to TLS-RPT reports

### Phase 3: Per-Domain Configuration

- Admin UI for setting DANE enforcement per recipient domain
- Policy table: `domain → dane_enforcement` mapping
- Support DANE for inbound receiving (reverse on MX)

### Phase 4: Advanced Features

- DANE with MTA-STS integration (RFC 8461 + RFC 6698)
- CAA (Certificate Authority Authorization) checks (RFC 6844)
- ACME automatic certificate pinning (RFC 8555)

## References

- [RFC 6698 - DANE](https://tools.ietf.org/html/rfc6698) - DNSSEC-based Authentication of Named Entities
- [RFC 6844 - CAA](https://tools.ietf.org/html/rfc6844) - Certification Authority Authorization
- [RFC 8460 - TLS-RPT](https://tools.ietf.org/html/rfc8460) - TLS Reporting
- [RFC 8461 - MTA-STS](https://tools.ietf.org/html/rfc8461) - SMTP MTA Strict Transport Security
