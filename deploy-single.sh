#!/bin/bash
# Deploy V3 Relay to a single server (for testing)
# Usage: ./deploy-single.sh user@host [ssh-key-file]

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 user@host [ssh-key-file]"
    echo "Example: $0 root@139.162.54.73"
    echo "Example: $0 ubuntu@54.255.205.216 keys/LightsailDefaultKey-ap-southeast-1.pem"
    exit 1
fi

SERVER="$1"
KEY_FILE="$2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH_PASS="SwiftTunnel2026secure123"

if [ -n "$KEY_FILE" ]; then
    SSH_CMD="ssh -i $KEY_FILE -o StrictHostKeyChecking=no"
    SCP_CMD="scp -i $KEY_FILE -o StrictHostKeyChecking=no"
    SUDO="sudo"
else
    if ! command -v sshpass &> /dev/null; then
        echo "sshpass required for password auth. Install: brew install hudochenkov/sshpass/sshpass"
        exit 1
    fi
    SSH_CMD="sshpass -p $SSH_PASS ssh -o StrictHostKeyChecking=no"
    SCP_CMD="sshpass -p $SSH_PASS scp -o StrictHostKeyChecking=no"
    SUDO=""
fi

echo "📦 Building and deploying to $SERVER..."

# Copy source
$SSH_CMD "$SERVER" "rm -rf /tmp/v3-relay && mkdir -p /tmp/v3-relay/src"
$SCP_CMD "$SCRIPT_DIR/Cargo.toml" "$SERVER:/tmp/v3-relay/"
$SCP_CMD "$SCRIPT_DIR/src/main.rs" "$SERVER:/tmp/v3-relay/src/"
$SCP_CMD "$SCRIPT_DIR/v3-relay.service" "$SERVER:/tmp/v3-relay/"

# Build and install
$SSH_CMD "$SERVER" "
    # Install Rust if needed
    if ! command -v cargo &> /dev/null; then
        echo 'Installing Rust...'
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source ~/.cargo/env
    fi
    source ~/.cargo/env 2>/dev/null || true

    # Build
    cd /tmp/v3-relay
    cargo build --release

    # Install
    $SUDO cp target/release/v3-relay /usr/local/bin/
    $SUDO chmod +x /usr/local/bin/v3-relay
    $SUDO cp v3-relay.service /etc/systemd/system/

    # Enable and start
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable v3-relay
    $SUDO systemctl restart v3-relay

    # Firewall
    if command -v ufw &> /dev/null; then
        $SUDO ufw allow 51821/udp
    fi

    # Verify
    sleep 2
    $SUDO systemctl status v3-relay --no-pager
"

echo "✅ Deployed to $SERVER"
