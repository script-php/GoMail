#!/usr/bin/env bash
# GoMail First-Run Setup Script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "==============================="
echo "  GoMail First-Run Setup"
echo "==============================="
echo ""

cd "$PROJECT_DIR"

# 1. Generate DKIM keys
echo "[1/4] Generating DKIM keys..."
go run main.go -setup
echo ""

# 2. Create password hash
echo "[2/4] Setting admin password..."
read -sp "Enter admin password: " ADMIN_PASS
echo ""
read -sp "Confirm admin password: " ADMIN_PASS2
echo ""

if [ "$ADMIN_PASS" != "$ADMIN_PASS2" ]; then
    echo "Error: Passwords do not match!"
    exit 1
fi

HASH=$(go run main.go -hash-password "$ADMIN_PASS" | grep "Password hash:" | cut -d' ' -f3)
echo ""
echo "Password hash generated."
echo ""
echo "Add this to your config.json under web.admin:"
echo "  password_hash = \"$HASH\""
echo ""

# 3. Create data directories
echo "[3/4] Creating data directories..."
mkdir -p data/attachments data/certs
echo "Done."
echo ""

# 4. Build
echo "[4/4] Building GoMail..."
go build -o gomail .
echo "Build complete: ./gomail"
echo ""

echo "==============================="
echo "  Setup Complete!"
echo "==============================="
echo ""
echo "Next steps:"
echo "  1. Edit config.json with your domain settings"
echo "  2. Add the password hash to config.json"
echo "  3. Configure DNS records (see docs/dns_records.md)"
echo "  4. Run: ./gomail -config config.json"
echo ""
echo "For systemd service setup, see docs/deployment.md"
