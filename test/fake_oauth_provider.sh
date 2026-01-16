#!/bin/bash
# Wrapper script to start the fake OAuth provider service

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROVIDER_SCRIPT="${SCRIPT_DIR}/fake_oauth_provider.py"

# Default configuration
PORT="${OAUTH_PROVIDER_PORT:-8000}"
HOST="${OAUTH_PROVIDER_HOST:-localhost}"

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is not installed or not in PATH"
    exit 1
fi

# Check if the provider script exists
if [ ! -f "$PROVIDER_SCRIPT" ]; then
    echo "Error: Provider script not found at $PROVIDER_SCRIPT"
    exit 1
fi

# Make the script executable
chmod +x "$PROVIDER_SCRIPT"

# Start the provider
echo "Starting fake UAC OAuth provider..."
python3 "$PROVIDER_SCRIPT" --host "$HOST" --port "$PORT"
