#!/bin/bash
set -euo pipefail

# Ubuntu install script for the passkey demo.
# Run this from the project root.
#
# Usage:
#   sudo bash deploy/install.sh

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$APP_DIR"

ENV_FILE=".env"

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)."
  exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
  echo ".env not found. Creating from .env.example."
  cp .env.example .env
  echo "Please edit .env and run this script again."
  exit 1
fi

set -a
source "$ENV_FILE"
set +a

DOMAIN="${RP_ID:-}"
if [ -z "$DOMAIN" ]; then
  echo "RP_ID is not set in .env"
  exit 1
fi

if [ "$DOMAIN" = "yourdomain.duckdns.org" ]; then
  echo "Please replace the placeholder domain in .env before running this script."
  exit 1
fi

APP_PORT="${PORT:-8443}"

echo "=== Installing system dependencies ==="
apt-get update
apt-get install -y build-essential python3 make curl git

# Install Node.js LTS if not present
if ! command -v node &> /dev/null; then
  echo "=== Installing Node.js LTS ==="
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
fi

echo "=== Installing Node dependencies ==="
rm -rf node_modules package-lock.json
npm install

echo "=== Creating data and certificate directories ==="
mkdir -p data certs
chmod 700 data

OWNER="${SUDO_USER:-$USER}"
chown -R "$OWNER:$OWNER" "$APP_DIR"
chmod 600 .env || true

echo "=== Installing Certbot and obtaining certificate ==="
apt-get install -y certbot

certbot certonly --standalone --non-interactive --agree-tos --register-unsafely-without-email -d "$DOMAIN"

echo "=== Copying initial certificate ==="
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" certs/
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" certs/
chown "$OWNER:$OWNER" certs/privkey.pem certs/fullchain.pem
chmod 600 certs/*.pem

echo "=== Configuring firewall ==="
apt-get install -y ufw
ufw allow 22/tcp || true
ufw allow 80/tcp || true
ufw allow "$APP_PORT/tcp" || true
ufw --force enable

echo ""
echo "=== Installation complete ==="
echo "Start the app with: ./start.sh"
echo "Stop the app with:  ./stop.sh"
echo "Renew certs with:   ./renew-certs.sh"
echo "App URL:            https://$DOMAIN:$APP_PORT"
