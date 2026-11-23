#!/bin/bash
set -euo pipefail

# Stop the manually running passkey app.
# Run this from the project root.

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

if [ ! -f passkeyapp.pid ]; then
  echo "PID file not found. Is the app running?"
  exit 1
fi

PID=$(cat passkeyapp.pid)
if kill -0 "$PID" 2>/dev/null; then
  kill "$PID"
  echo "Stopped passkey app (PID $PID)."
else
  echo "Process $PID is not running."
fi

rm -f passkeyapp.pid
