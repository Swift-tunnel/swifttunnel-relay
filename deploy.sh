#!/bin/bash
# SwiftTunnel V3 UDP Relay Deployment Script
# Deploys the relay server to all VPN servers

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_NAME="swifttunnel-relay"
SERVICE_FILE="v3-relay.service"
REMOTE_BIN="/usr/local/bin/$BINARY_NAME"
REMOTE_SERVICE="/etc/systemd/system/$SERVICE_FILE"

# Build server (Singapore 06 Linode - has Rust toolchain)
BUILD_SERVER="root@104.64.209.241"
BUILD_DIR="/tmp/v3-relay-build"

# Passwords are NOT stored in git. Provide them via env vars:
# - SWIFTTUNNEL_SSH_PASS: generic password-auth servers + build server
# - SWIFTTUNNEL_DO_SSH_PASS: DigitalOcean password (defaults to SWIFTTUNNEL_SSH_PASS)
PASS_MD="$(cd "$SCRIPT_DIR/.." && pwd)/swifttunnel-web/pass.md"
source "$SCRIPT_DIR/deploy-utils.sh"

SSH_PASS="${SWIFTTUNNEL_SSH_PASS:-}"
DO_SSH_PASS="${SWIFTTUNNEL_DO_SSH_PASS:-}"
ROLLBACK_TUN_UDP_ONLY="${ROLLBACK_TUN_UDP_ONLY:-0}"

if [ -z "$SSH_PASS" ]; then
    SSH_PASS="$(get_generic_pass || true)"
fi
if [ -z "$SSH_PASS" ]; then
    echo "Missing SWIFTTUNNEL_SSH_PASS and couldn't infer from $PASS_MD"
    exit 1
fi
if [ -z "$DO_SSH_PASS" ]; then
    DO_SSH_PASS="$SSH_PASS"
fi

# All VPN servers
# Source of truth: swifttunnel-web/lib/constants.ts (VPN_SERVERS)
# Format: user@host
SERVERS=(
    # Linode servers (password auth)
    "root@104.64.209.241"   # singapore-06
    "root@170.187.237.235"  # mumbai-05
    "root@172.237.36.108"   # mumbai-06
    "root@172.238.14.196"   # tokyo-04
    "root@172.236.201.229"  # germany-05
    "root@172.232.44.141"   # paris-03
    "root@172.233.20.214"   # brazil-02
    "root@172.237.119.240"  # london-01
    "root@172.233.43.86"    # amsterdam-01
    "root@194.195.120.190"  # sydney-04

    # Vultr servers (password auth)
    "root@45.32.115.254"    # singapore-03
    "root@65.20.84.67"      # mumbai-03
    "root@139.180.166.16"   # sydney-03
    "root@45.32.253.124"    # tokyo-02
    "root@95.179.254.160"   # germany-03
    "root@216.238.121.139"  # brazil-03 (vultr)

    # OVH servers (password auth)
    "root@51.79.128.67"     # singapore-02
    "root@148.113.44.43"    # mumbai-02

    # Kamatera
    "root@103.125.219.188"  # tokyo-05
)

# Vultr US servers (SSH key auth)
VULTR_US_KEY_FILE="$HOME/.ssh/swifttunnel-vultr-us"
VULTR_US_SERVERS=(
    "root@45.63.55.139"     # us-west-la
    "root@108.61.7.6"       # us-east-nj
    "root@108.61.205.6"     # us-central-dallas
)

# DigitalOcean servers (different password auth)
DO_SERVERS=(
    "root@167.71.189.84"    # do-nyc3-01
    "root@164.90.185.161"   # do-fra1-01
    "root@152.42.223.13"    # do-sgp1-01
)

# AWS Lightsail servers (SSH key auth) - handled separately
AWS_SERVERS=(
    "ubuntu@54.255.205.216:swifttunnel-web/keys/LightsailDefaultKey-ap-southeast-1.pem"   # singapore
    "ubuntu@3.111.230.152:swifttunnel-web/keys/LightsailDefaultKey-ap-south-1.pem"        # mumbai
    "ubuntu@35.156.206.93:swifttunnel-web/keys/LightsailDefaultKey-eu-central-1.pem"      # germany-01
)

echo "╔════════════════════════════════════════════╗"
echo "║   SwiftTunnel V3 Relay Deployment Script   ║"
echo "╚════════════════════════════════════════════╝"
echo

# Check if sshpass is installed (for password auth)
if ! command -v sshpass &> /dev/null; then
    echo "⚠️  sshpass not found. Install with: brew install hudochenkov/sshpass/sshpass"
    echo "   Alternatively, set up SSH keys on all servers."
    exit 1
fi

# Function to run SSH command with password
ssh_pass() {
    SSHPASS="$SSH_PASS" sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=10 "$@"
}

# Function to run SCP with password
scp_pass() {
    SSHPASS="$SSH_PASS" sshpass -e scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=10 "$@"
}

if [ "$ROLLBACK_TUN_UDP_ONLY" = "1" ]; then
    echo "⚠️  Rollback-only mode: skipping build and binary copy"
else
    # Step 1: Build on remote server
    echo "📦 Step 1: Building on $BUILD_SERVER..."
    echo

    # Copy source to build server
    ssh_pass "$BUILD_SERVER" "rm -rf $BUILD_DIR && mkdir -p $BUILD_DIR/src"
    scp_pass "$SCRIPT_DIR/Cargo.lock" "$BUILD_SERVER:$BUILD_DIR/" 2>/dev/null || true
    scp_pass "$SCRIPT_DIR/Cargo.toml" "$BUILD_SERVER:$BUILD_DIR/"
    scp_pass "$SCRIPT_DIR/src/main.rs" "$BUILD_SERVER:$BUILD_DIR/src/"
    scp_pass "$SCRIPT_DIR/src/datapath_v2.rs" "$BUILD_SERVER:$BUILD_DIR/src/"
    scp_pass "$SCRIPT_DIR/src/tcp_tun.rs" "$BUILD_SERVER:$BUILD_DIR/src/"

    # Install Rust if needed and build
    ssh_pass "$BUILD_SERVER" "
        # Install Rust if not present
        if ! command -v cargo &> /dev/null; then
            echo 'Installing Rust...'
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
            source ~/.cargo/env
        fi

        # Build release
        cd $BUILD_DIR
        source ~/.cargo/env 2>/dev/null || true
        cargo build --release

        # Copy binary to known location
        cp target/release/$BINARY_NAME /tmp/$BINARY_NAME
        chmod +x /tmp/$BINARY_NAME
        echo 'Build complete!'
    "

    # Download the built binary
    echo "📥 Downloading binary from build server..."
    scp_pass "$BUILD_SERVER:/tmp/$BINARY_NAME" "/tmp/$BINARY_NAME"
fi

# Step 2: Deploy to all servers
echo
echo "🚀 Step 2: Deploying to ${#SERVERS[@]} password-auth servers..."
echo

deploy_to_server() {
    local server="$1"
    local is_aws="$2"
    local key_file="$3"
    local password="${4:-$SSH_PASS}"

    echo -n "  → $server: "

    if [ "$is_aws" = "true" ]; then
        # AWS with SSH key
        ssh_cmd="ssh -i $key_file -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=10"
        scp_cmd="scp -i $key_file -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=10"
        sudo_prefix="sudo"
    else
        # Password auth
        ssh_cmd="sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=10"
        scp_cmd="sshpass -e scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=10"
        sudo_prefix=""
    fi

    # For password-auth, set SSHPASS as an exported env var for child processes.
    if [ "$is_aws" != "true" ]; then
        export SSHPASS="$password"
    fi

    if [ "$ROLLBACK_TUN_UDP_ONLY" != "1" ]; then
        # Copy binary
        if ! $scp_cmd "/tmp/$BINARY_NAME" "$server:/tmp/$BINARY_NAME" 2>/dev/null; then
            echo "❌ Failed to copy binary"
            unset SSHPASS 2>/dev/null
            return 1
        fi

        # Copy service file
        if ! $scp_cmd "$SCRIPT_DIR/$SERVICE_FILE" "$server:/tmp/$SERVICE_FILE" 2>/dev/null; then
            echo "❌ Failed to copy service file"
            unset SSHPASS 2>/dev/null
            return 1
        fi
    fi

    # Install, configure env, and start service
    if ! $ssh_cmd "$server" "
        set -e

        if [ \"$ROLLBACK_TUN_UDP_ONLY\" != '1' ]; then
            # Stop first; atomic replace avoids ETXTBSY and cross-fs mv weirdness
            $sudo_prefix systemctl stop v3-relay >/dev/null 2>&1 || true
            $sudo_prefix mkdir -p /usr/local/bin
            $sudo_prefix mv /tmp/$BINARY_NAME ${REMOTE_BIN}.new
            $sudo_prefix chmod +x ${REMOTE_BIN}.new
            $sudo_prefix mv -f ${REMOTE_BIN}.new $REMOTE_BIN
            $sudo_prefix mv /tmp/$SERVICE_FILE $REMOTE_SERVICE
        fi

        # Ensure env + token for localhost stats exists (needed by status/observability)
        $sudo_prefix mkdir -p /etc/swifttunnel
        $sudo_prefix mkdir -p /etc/systemd/system/v3-relay.service.d
        if [ ! -f /etc/swifttunnel/relay.env ]; then
            $sudo_prefix touch /etc/swifttunnel/relay.env
        fi
        existing_token=\$(grep -E '^RELAY_STATS_TOKEN=' /etc/swifttunnel/relay.env | head -n1 | cut -d= -f2- || true)
        if [ -z \"\$existing_token\" ]; then
            token=\$(openssl rand -hex 24 2>/dev/null || (head -c 24 /dev/urandom | base64 | tr -d '=+/\\n' | head -c 48))
            if grep -q '^RELAY_STATS_TOKEN=' /etc/swifttunnel/relay.env; then
                $sudo_prefix sed -i \"s|^RELAY_STATS_TOKEN=.*|RELAY_STATS_TOKEN=\$token|\" /etc/swifttunnel/relay.env
            else
                echo \"RELAY_STATS_TOKEN=\$token\" | $sudo_prefix tee -a /etc/swifttunnel/relay.env >/dev/null
            fi
        fi
        grep -q '^RELAY_STATS_PORT=' /etc/swifttunnel/relay.env || echo 'RELAY_STATS_PORT=51822' | $sudo_prefix tee -a /etc/swifttunnel/relay.env >/dev/null
        grep -q '^RELAY_FLOW_CHANNEL_CAPACITY=' /etc/swifttunnel/relay.env || echo 'RELAY_FLOW_CHANNEL_CAPACITY=256' | $sudo_prefix tee -a /etc/swifttunnel/relay.env >/dev/null
        cat > /tmp/10-env.conf <<'EOF'
[Service]
EnvironmentFile=/etc/swifttunnel/relay.env
EOF
        $sudo_prefix mv -f /tmp/10-env.conf /etc/systemd/system/v3-relay.service.d/10-env.conf
        cat > /tmp/90-disable-tun-udp.conf <<'EOF'
[Service]
Environment=RELAY_TUN_UDP=false
EOF
        $sudo_prefix mv -f /tmp/90-disable-tun-udp.conf /etc/systemd/system/v3-relay.service.d/90-disable-tun-udp.conf
        $sudo_prefix systemctl daemon-reload
        $sudo_prefix systemctl enable v3-relay >/dev/null 2>&1 || true
        if [ \"$ROLLBACK_TUN_UDP_ONLY\" = '1' ]; then
            $sudo_prefix systemctl restart v3-relay
        else
            $sudo_prefix systemctl start v3-relay
        fi

        # Open firewall port
        if command -v ufw &> /dev/null; then
            $sudo_prefix ufw allow 51821/udp >/dev/null 2>&1 || true
        fi

        # Check if running
        sleep 1
        if $sudo_prefix systemctl is-active --quiet v3-relay; then
            echo 'OK'
        else
            echo 'Service not running'
            exit 1
        fi

        # Assign TUN IP if TCP tunneling is enabled (relay creates the device on start)
        if $sudo_prefix ip link show swifttun0 &>/dev/null; then
            $sudo_prefix ip addr add 10.200.0.1/16 dev swifttun0 2>/dev/null || true
            $sudo_prefix ip link set swifttun0 up 2>/dev/null || true
        fi

        # Verify stats JSON includes new fields (dropped_in/out/pps)
        token=\$(grep -E '^RELAY_STATS_TOKEN=' /etc/swifttunnel/relay.env | head -n1 | cut -d= -f2- || true)
        port=\$(grep -E '^RELAY_STATS_PORT=' /etc/swifttunnel/relay.env | head -n1 | cut -d= -f2- || echo 51822)
        if [ -n \"\$token\" ]; then
            curl -fsS -H \"Authorization: Bearer \$token\" http://127.0.0.1:\$port/v1/stats | grep -q 'dropped_in' || exit 1
        fi
    " 2>/dev/null; then
        echo "❌ Failed to install/start"
        unset SSHPASS 2>/dev/null
        return 1
    fi

    unset SSHPASS 2>/dev/null
    echo "✅"
    return 0
}

# Deploy to password-auth servers
SUCCESS=0
FAILED=0

for server in "${SERVERS[@]}"; do
    if deploy_to_server "$server" "false" "" "$SSH_PASS"; then
        ((++SUCCESS))
    else
        ((++FAILED))
    fi
done

# Deploy to Vultr US key-auth servers
echo
echo "🔑 Deploying to ${#VULTR_US_SERVERS[@]} Vultr US servers (SSH key auth)..."
echo
if [ -f "$VULTR_US_KEY_FILE" ]; then
    for server in "${VULTR_US_SERVERS[@]}"; do
        if deploy_to_server "$server" "true" "$VULTR_US_KEY_FILE"; then
            ((++SUCCESS))
        else
            ((++FAILED))
        fi
    done
else
    for server in "${VULTR_US_SERVERS[@]}"; do
        echo "  → $server: ⚠️  Key file not found: $VULTR_US_KEY_FILE"
        ((++FAILED))
    done
fi

# Deploy to DigitalOcean servers
echo
echo "🌊 Deploying to ${#DO_SERVERS[@]} DigitalOcean servers..."
echo

for server in "${DO_SERVERS[@]}"; do
    if deploy_to_server "$server" "false" "" "$DO_SSH_PASS"; then
        ((++SUCCESS))
    else
        ((++FAILED))
    fi
done

# Deploy to AWS servers
echo
echo "🔐 Deploying to ${#AWS_SERVERS[@]} AWS servers (SSH key auth)..."
echo

for entry in "${AWS_SERVERS[@]}"; do
    server="${entry%%:*}"
    key_file_part="${entry#*:}"
    # Repo layout: Swifttunnel/swifttunnel-relay. One level up is the repo root.
    key_file="$(cd "$SCRIPT_DIR/.." && pwd)/$key_file_part"

    if [ -f "$key_file" ]; then
        if deploy_to_server "$server" "true" "$key_file"; then
            ((++SUCCESS))
        else
            ((++FAILED))
        fi
    else
        echo "  → $server: ⚠️  Key file not found: $key_file"
        ((++FAILED))
    fi
done

# Summary
echo
echo "════════════════════════════════════════════"
echo "  Deployment Complete!"
echo "  ✅ Success: $SUCCESS servers"
echo "  ❌ Failed:  $FAILED servers"
echo "════════════════════════════════════════════"

# Cleanup
if [ "$ROLLBACK_TUN_UDP_ONLY" != "1" ]; then
    rm -f "/tmp/$BINARY_NAME"
fi

exit 0
