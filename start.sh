#!/bin/bash
set -euo pipefail

# Start the passkey app manually.
# Run this from the project root.

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

if [ ! -f .env ]; then
  echo ".env not found. Copy .env.example to .env and fill it in first."
  exit 1
fi

if [ -f passkeyapp.pid ]; then
  PID=$(cat passkeyapp.pid)
  if kill -0 "$PID" 2>/dev/null; then
    echo "Passkey app is already running (PID $PID)"
    exit 1
  fi
  rm -f passkeyapp.pid
fi

echo "Starting passkey app from $(pwd)..."
node server.js &
PID=$!
echo "$PID" > passkeyapp.pid
echo "PID: $PID"
echo "Logs are printed below. Press Ctrl+C to stop."

trap 'rm -f passkeyapp.pid' EXIT
wait "$PID"
