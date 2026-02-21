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
PASS_MD="$(cd "$SCRIPT_DIR/.." && pwd)/swifttunnel-web/pass.md"

get_generic_pass() {
    # Best-effort: extract password from a markdown snippet like: `root / PASSWORD`
    if [ ! -f "$PASS_MD" ]; then
        return 1
    fi
    sed -n 's/.*`root \\/ \\([^`]*\\)`.*/\\1/p' "$PASS_MD" | head -n1
}

SSH_PASS="${SWIFTTUNNEL_SSH_PASS:-}"
if [ -z "$SSH_PASS" ] && [ -z "$KEY_FILE" ]; then
    SSH_PASS="$(get_generic_pass || true)"
fi

if [ -n "$KEY_FILE" ]; then
    SSH_CMD="ssh -i $KEY_FILE -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null"
    SCP_CMD="scp -i $KEY_FILE -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null"
    SUDO="sudo"
else
    if ! command -v sshpass &> /dev/null; then
        echo "sshpass required for password auth. Install: brew install hudochenkov/sshpass/sshpass"
        exit 1
    fi
    if [ -z "$SSH_PASS" ]; then
        echo "Missing SWIFTTUNNEL_SSH_PASS and couldn't infer from $PASS_MD"
        exit 1
    fi
    SSH_CMD="sshpass -p $SSH_PASS ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null"
    SCP_CMD="sshpass -p $SSH_PASS scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null"
    SUDO=""
fi

echo "📦 Building and deploying to $SERVER..."

# Copy source
$SSH_CMD "$SERVER" "rm -rf /tmp/v3-relay && mkdir -p /tmp/v3-relay/src"
$SCP_CMD "$SCRIPT_DIR/Cargo.lock" "$SERVER:/tmp/v3-relay/" 2>/dev/null || true
$SCP_CMD "$SCRIPT_DIR/Cargo.toml" "$SERVER:/tmp/v3-relay/"
$SCP_CMD "$SCRIPT_DIR/src/main.rs" "$SERVER:/tmp/v3-relay/src/"
$SCP_CMD "$SCRIPT_DIR/src/datapath_v2.rs" "$SERVER:/tmp/v3-relay/src/"
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

    # Install (stop first; atomic replace avoids ETXTBSY)
    $SUDO systemctl stop v3-relay >/dev/null 2>&1 || true
    $SUDO mkdir -p /usr/local/bin
    $SUDO cp target/release/swifttunnel-relay /usr/local/bin/swifttunnel-relay.new
    $SUDO chmod +x /usr/local/bin/swifttunnel-relay.new
    $SUDO mv -f /usr/local/bin/swifttunnel-relay.new /usr/local/bin/swifttunnel-relay
    $SUDO cp v3-relay.service /etc/systemd/system/

    # Enable and start
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable v3-relay
    $SUDO systemctl start v3-relay

    # Firewall
    if command -v ufw &> /dev/null; then
        $SUDO ufw allow 51821/udp
    fi

    # Verify
    sleep 2
    $SUDO systemctl status v3-relay --no-pager
"

echo "✅ Deployed to $SERVER"
