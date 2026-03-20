#!/usr/bin/env bash
# Verify all DNS records for GoMail are correctly configured
set -euo pipefail

DOMAIN="${1:-example.com}"
HOSTNAME="${2:-mail.$DOMAIN}"
SELECTOR="${3:-mail}"

echo "==============================="
echo "  GoMail DNS Record Check"
echo "  Domain: $DOMAIN"
echo "  Hostname: $HOSTNAME"
echo "==============================="
echo ""

PASS=0
FAIL=0

check() {
    local name="$1"
    local query="$2"
    local type="$3"
    local expect="$4"

    echo -n "[$name] "
    result=$(dig +short "$query" "$type" 2>/dev/null || echo "LOOKUP_FAILED")

    if echo "$result" | grep -qi "$expect"; then
        echo "PASS - $result"
        ((PASS++))
    else
        echo "FAIL"
        echo "  Expected: $expect"
        echo "  Got: $result"
        ((FAIL++))
    fi
}

# MX Record
echo "--- Mail Exchange ---"
check "MX" "$DOMAIN" MX "$HOSTNAME"
echo ""

# A Record
echo "--- Address Records ---"
check "A" "$HOSTNAME" A "."
echo ""

# SPF Record
echo "--- SPF ---"
check "SPF" "$DOMAIN" TXT "v=spf1"
echo ""

# DKIM Record
echo "--- DKIM ---"
check "DKIM" "${SELECTOR}._domainkey.${DOMAIN}" TXT "v=DKIM1"
echo ""

# DMARC Record
echo "--- DMARC ---"
check "DMARC" "_dmarc.${DOMAIN}" TXT "v=DMARC1"
echo ""

# MTA-STS Record
echo "--- MTA-STS ---"
check "MTA-STS" "_mta-sts.${DOMAIN}" TXT "v=STSv1"
echo ""

# TLS-RPT Record
echo "--- TLS-RPT ---"
check "TLS-RPT" "_smtp._tls.${DOMAIN}" TXT "v=TLSRPTv1"
echo ""

# PTR Record (reverse DNS)
echo "--- Reverse DNS ---"
IP=$(dig +short "$HOSTNAME" A 2>/dev/null | head -1)
if [ -n "$IP" ]; then
    PTR=$(dig +short -x "$IP" 2>/dev/null || echo "LOOKUP_FAILED")
    echo -n "[PTR] "
    if echo "$PTR" | grep -qi "$HOSTNAME"; then
        echo "PASS - $PTR"
        ((PASS++))
    else
        echo "FAIL"
        echo "  Expected: $HOSTNAME"
        echo "  Got: $PTR"
        ((FAIL++))
    fi
else
    echo "[PTR] SKIP - No A record found"
fi

echo ""
echo "==============================="
echo "  Results: $PASS passed, $FAIL failed"
echo "==============================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
