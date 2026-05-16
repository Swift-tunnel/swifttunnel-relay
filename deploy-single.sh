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
source "$SCRIPT_DIR/deploy-utils.sh"

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
    export SSHPASS="$SSH_PASS"
    SSH_CMD="sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null"
    SCP_CMD="sshpass -e scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null"
    SUDO=""
fi

echo "📦 Building and deploying to $SERVER..."

# Copy source
$SSH_CMD "$SERVER" "rm -rf /tmp/v3-relay && mkdir -p /tmp/v3-relay/src"
$SCP_CMD "$SCRIPT_DIR/Cargo.lock" "$SERVER:/tmp/v3-relay/" 2>/dev/null || true
$SCP_CMD "$SCRIPT_DIR/Cargo.toml" "$SERVER:/tmp/v3-relay/"
$SCP_CMD "$SCRIPT_DIR/src/main.rs" "$SERVER:/tmp/v3-relay/src/"
$SCP_CMD "$SCRIPT_DIR/src/datapath_v2.rs" "$SERVER:/tmp/v3-relay/src/"
$SCP_CMD "$SCRIPT_DIR/src/tcp_tun.rs" "$SERVER:/tmp/v3-relay/src/"
$SCP_CMD "$SCRIPT_DIR/v3-relay.service" "$SERVER:/tmp/v3-relay/"
$SCP_CMD "$SCRIPT_DIR/setup-tun.sh" "$SERVER:/tmp/v3-relay/"

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
    $SUDO install -m 0755 setup-tun.sh /usr/local/sbin/swifttunnel-setup-tun
    $SUDO /usr/local/sbin/swifttunnel-setup-tun >/tmp/swifttunnel-setup-tun.log

    # Ensure env + TCP API tunneling + forced UDP-TUN rollback override exist
    $SUDO mkdir -p /etc/swifttunnel
    $SUDO mkdir -p /etc/systemd/system/v3-relay.service.d
    if [ ! -f /etc/swifttunnel/relay.env ]; then
        $SUDO touch /etc/swifttunnel/relay.env
    fi
    grep -q '^RELAY_STATS_PORT=' /etc/swifttunnel/relay.env || echo 'RELAY_STATS_PORT=51822' | $SUDO tee -a /etc/swifttunnel/relay.env >/dev/null
    grep -q '^RELAY_FLOW_CHANNEL_CAPACITY=' /etc/swifttunnel/relay.env || echo 'RELAY_FLOW_CHANNEL_CAPACITY=256' | $SUDO tee -a /etc/swifttunnel/relay.env >/dev/null
    grep -q '^RELAY_AUTH_MODE=' /etc/swifttunnel/relay.env || echo 'RELAY_AUTH_MODE=required' | $SUDO tee -a /etc/swifttunnel/relay.env >/dev/null
    auth_mode=\$(grep -E '^RELAY_AUTH_MODE=' /etc/swifttunnel/relay.env | head -n1 | cut -d= -f2- || true)
    auth_key=\$(grep -E '^RELAY_AUTH_PUBLIC_KEY_B64=' /etc/swifttunnel/relay.env | head -n1 | cut -d= -f2- || true)
    auth_server=\$(grep -E '^RELAY_SERVER_ID=' /etc/swifttunnel/relay.env | head -n1 | cut -d= -f2- || true)
    allow_insecure=\$(grep -E '^RELAY_ALLOW_INSECURE=' /etc/swifttunnel/relay.env | head -n1 | cut -d= -f2- || true)
    if [ \"\$auth_mode\" = 'off' ] && [ \"\$allow_insecure\" != '1' ]; then
        echo 'RELAY_AUTH_MODE=off requires RELAY_ALLOW_INSECURE=1' >&2
        exit 1
    fi
    if [ \"\$auth_mode\" != 'off' ] && { [ -z \"\$auth_key\" ] || [ -z \"\$auth_server\" ]; }; then
        echo 'Relay auth is required but RELAY_AUTH_PUBLIC_KEY_B64 or RELAY_SERVER_ID is missing in /etc/swifttunnel/relay.env' >&2
        exit 1
    fi
    cat > /tmp/10-env.conf <<EOF
[Service]
EnvironmentFile=/etc/swifttunnel/relay.env
EOF
    $SUDO mv -f /tmp/10-env.conf /etc/systemd/system/v3-relay.service.d/10-env.conf
    cat > /tmp/90-disable-tun-udp.conf <<EOF
[Service]
Environment=RELAY_TUN_UDP=false
EOF
    $SUDO mv -f /tmp/90-disable-tun-udp.conf /etc/systemd/system/v3-relay.service.d/90-disable-tun-udp.conf
    cat > /tmp/20-tcp.conf <<EOF
[Service]
Environment=RELAY_TCP_ENABLED=true
EOF
    $SUDO mv -f /tmp/20-tcp.conf /etc/systemd/system/v3-relay.service.d/20-tcp.conf

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

unset SSHPASS 2>/dev/null || true

echo "✅ Deployed to $SERVER"
