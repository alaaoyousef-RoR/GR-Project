#!/bin/bash
set -euo pipefail

# Renew the Let's Encrypt certificate and copy it into the project.
# Run this from the project root.

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

if [ ! -f .env ]; then
  echo ".env not found."
  exit 1
fi

set -a
source .env
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

echo "Renewing certificate for $DOMAIN..."
sudo certbot renew --non-interactive --standalone --agree-tos

echo "Copying certificates..."
mkdir -p certs
sudo cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" certs/
sudo cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" certs/

OWNER="${SUDO_USER:-$USER}"
sudo chown "$OWNER:$OWNER" certs/privkey.pem certs/fullchain.pem
chmod 600 certs/*.pem

echo "Done."
echo "If the app is running, restart it with: ./stop.sh && ./start.sh"
