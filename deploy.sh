#!/bin/bash
# SwiftTunnel V3 UDP Relay Deployment Script
# Deploys the relay server to all VPN servers

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_NAME="swifttunnel-relay"
SERVICE_FILE="v3-relay.service"
REMOTE_BIN="/usr/local/bin/$BINARY_NAME"
REMOTE_SERVICE="/etc/systemd/system/$SERVICE_FILE"

# Build server (we'll use Singapore 05 Linode as build server - has Rust toolchain)
BUILD_SERVER="root@139.162.54.73"
BUILD_DIR="/tmp/v3-relay-build"

# All VPN servers (password: SwiftTunnel2026secure123)
# Format: user@host
SERVERS=(
    # Linode servers (password auth)
    "root@139.162.54.73"    # Singapore 05
    "root@104.64.209.241"   # Singapore 06
    "root@170.187.237.235"  # Mumbai 05
    "root@172.237.36.108"   # Mumbai 06
    "root@139.162.123.60"   # Tokyo 03
    "root@172.238.14.196"   # Tokyo 04
    "root@172.105.83.121"   # Germany 04
    "root@172.236.201.229"  # Germany 05
    "root@172.232.44.141"   # Paris 03
    "root@172.233.20.214"   # Brazil 02
    "root@45.79.139.183"    # America 03
    "root@45.33.11.248"     # America 04
    "root@172.237.119.240"  # London 01
    "root@172.233.43.86"    # Amsterdam 01
    "root@194.195.120.190"  # Sydney 04

    # Vultr servers (password auth)
    "root@45.32.115.254"    # Singapore 03
    "root@65.20.84.67"      # Mumbai 03
    "root@139.180.166.16"   # Sydney 03
    "root@45.32.253.124"    # Tokyo 02
    "root@95.179.254.160"   # Germany 03
    "root@158.247.215.8"    # Korea 02

    # OVH servers (password auth)
    "root@51.79.128.67"     # Singapore 02
    "root@148.113.44.43"    # Mumbai 02

    # Kamatera
    "root@103.125.219.188"  # Tokyo 05
)

# AWS Lightsail servers (SSH key auth) - handled separately
AWS_SERVERS=(
    "ubuntu@54.255.205.216:keys/LightsailDefaultKey-ap-southeast-1.pem"   # Singapore
    "ubuntu@3.111.230.152:keys/LightsailDefaultKey-ap-south-1.pem"        # Mumbai
    "ubuntu@54.153.235.165:keys/LightsailDefaultKey-ap-southeast-2.pem"   # Sydney
    "ubuntu@63.181.160.158:keys/LightsailDefaultKey-eu-central-1.pem"     # Germany 01
    "ubuntu@54.225.245.114:keys/LightsailDefaultKey-us-east-1.pem"        # America 01
    "ubuntu@3.35.251.80:keys/LightsailDefaultKey-ap-northeast-2.pem"      # Korea 01
    "ubuntu@100.21.145.132:keys/LightsailDefaultKey-us-west-2.pem"        # America 02
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

SSH_PASS="SwiftTunnel2026secure123"

# Function to run SSH command with password
ssh_pass() {
    sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$@"
}

# Function to run SCP with password
scp_pass() {
    sshpass -p "$SSH_PASS" scp -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$@"
}

# Step 1: Build on remote server
echo "📦 Step 1: Building on $BUILD_SERVER..."
echo

# Copy source to build server
ssh_pass "$BUILD_SERVER" "rm -rf $BUILD_DIR && mkdir -p $BUILD_DIR/src"
scp_pass "$SCRIPT_DIR/Cargo.toml" "$BUILD_SERVER:$BUILD_DIR/"
scp_pass "$SCRIPT_DIR/src/main.rs" "$BUILD_SERVER:$BUILD_DIR/src/"

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

# Step 2: Deploy to all servers
echo
echo "🚀 Step 2: Deploying to ${#SERVERS[@]} password-auth servers..."
echo

deploy_to_server() {
    local server="$1"
    local is_aws="$2"
    local key_file="$3"

    echo -n "  → $server: "

    if [ "$is_aws" = "true" ]; then
        # AWS with SSH key
        ssh_cmd="ssh -i $key_file -o StrictHostKeyChecking=no -o ConnectTimeout=10"
        scp_cmd="scp -i $key_file -o StrictHostKeyChecking=no -o ConnectTimeout=10"
        sudo_prefix="sudo"
    else
        # Password auth
        ssh_cmd="sshpass -p $SSH_PASS ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10"
        scp_cmd="sshpass -p $SSH_PASS scp -o StrictHostKeyChecking=no -o ConnectTimeout=10"
        sudo_prefix=""
    fi

    # Copy binary
    if ! $scp_cmd "/tmp/$BINARY_NAME" "$server:/tmp/$BINARY_NAME" 2>/dev/null; then
        echo "❌ Failed to copy binary"
        return 1
    fi

    # Copy service file
    if ! $scp_cmd "$SCRIPT_DIR/$SERVICE_FILE" "$server:/tmp/$SERVICE_FILE" 2>/dev/null; then
        echo "❌ Failed to copy service file"
        return 1
    fi

    # Install and start service
    if ! $ssh_cmd "$server" "
        $sudo_prefix mv /tmp/$BINARY_NAME $REMOTE_BIN
        $sudo_prefix chmod +x $REMOTE_BIN
        $sudo_prefix mv /tmp/$SERVICE_FILE $REMOTE_SERVICE
        $sudo_prefix systemctl daemon-reload
        $sudo_prefix systemctl enable v3-relay
        $sudo_prefix systemctl restart v3-relay

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
    " 2>/dev/null; then
        echo "❌ Failed to install/start"
        return 1
    fi

    echo "✅"
    return 0
}

# Deploy to password-auth servers
SUCCESS=0
FAILED=0

for server in "${SERVERS[@]}"; do
    if deploy_to_server "$server" "false" ""; then
        ((SUCCESS++))
    else
        ((FAILED++))
    fi
done

# Deploy to AWS servers
echo
echo "🔐 Deploying to ${#AWS_SERVERS[@]} AWS servers (SSH key auth)..."
echo

for entry in "${AWS_SERVERS[@]}"; do
    server="${entry%%:*}"
    key_file_part="${entry#*:}"
    key_file="$(cd "$SCRIPT_DIR/../.." && pwd)/$key_file_part"

    if [ -f "$key_file" ]; then
        if deploy_to_server "$server" "true" "$key_file"; then
            ((SUCCESS++))
        else
            ((FAILED++))
        fi
    else
        echo "  → $server: ⚠️  Key file not found: $key_file"
        ((FAILED++))
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
rm -f "/tmp/$BINARY_NAME"

exit 0
