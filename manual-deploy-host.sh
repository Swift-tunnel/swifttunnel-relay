#!/bin/bash
# Manual deploy helper for a single relay host.
#
# Usage:
#   SWIFTTUNNEL_SSH_PASS='...' ./manual-deploy-host.sh root@1.2.3.4
#   ./manual-deploy-host.sh ubuntu@54.255.205.216 swifttunnel-web/keys/LightsailDefaultKey-ap-southeast-1.pem
#
# Notes:
# - For password auth, set SWIFTTUNNEL_SSH_PASS (avoids putting secrets in shell history).
# - This script fetches a Linux release binary from the build server (singapore-06) and installs it.

set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 user@host [ssh-key-file]"
  exit 2
fi

SERVER="$1"
KEY_FILE="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/deploy-utils.sh"

# Build server (has Rust toolchain); uses the generic password from pass.md.
BUILD_SERVER="root@104.64.209.241"
PASS_MD="$SCRIPT_DIR/../swifttunnel-web/pass.md"

BIN_LOCAL="/tmp/swifttunnel-relay"
SVC_LOCAL="$SCRIPT_DIR/v3-relay.service"

ssh_opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=15)

fetch_linux_binary() {
  if [ -x "$BIN_LOCAL" ]; then
    return 0
  fi

  local pass
  pass="$(get_generic_pass)" || {
    echo "Missing $PASS_MD; can't fetch build binary automatically."
    return 1
  }

  if ! command -v sshpass >/dev/null 2>&1; then
    echo "sshpass is required to fetch from build server. Install: brew install hudochenkov/sshpass/sshpass"
    return 1
  fi

  # Pull from the build output directory (the /tmp/swifttunnel-relay path is moved away during deploys).
  sshpass -p "$pass" scp "${ssh_opts[@]}" \
    "$BUILD_SERVER:/tmp/v3-relay-build/target/release/swifttunnel-relay" \
    "$BIN_LOCAL"
  chmod +x "$BIN_LOCAL"
}

run_ssh() {
  if [ -n "$KEY_FILE" ]; then
    ssh -i "$KEY_FILE" "${ssh_opts[@]}" "$@"
  else
    if [ -z "${SWIFTTUNNEL_SSH_PASS:-}" ]; then
      echo "Set SWIFTTUNNEL_SSH_PASS for password auth."
      return 2
    fi
    if ! command -v sshpass >/dev/null 2>&1; then
      echo "sshpass is required for password auth. Install: brew install hudochenkov/sshpass/sshpass"
      return 2
    fi
    sshpass -p "$SWIFTTUNNEL_SSH_PASS" ssh "${ssh_opts[@]}" "$@"
  fi
}

run_scp() {
  if [ -n "$KEY_FILE" ]; then
    scp -i "$KEY_FILE" "${ssh_opts[@]}" "$@"
  else
    if [ -z "${SWIFTTUNNEL_SSH_PASS:-}" ]; then
      echo "Set SWIFTTUNNEL_SSH_PASS for password auth."
      return 2
    fi
    if ! command -v sshpass >/dev/null 2>&1; then
      echo "sshpass is required for password auth. Install: brew install hudochenkov/sshpass/sshpass"
      return 2
    fi
    sshpass -p "$SWIFTTUNNEL_SSH_PASS" scp "${ssh_opts[@]}" "$@"
  fi
}

fetch_linux_binary

echo "Deploying relay to $SERVER"
run_scp "$BIN_LOCAL" "$SERVER:/tmp/swifttunnel-relay"
run_scp "$SVC_LOCAL" "$SERVER:/tmp/v3-relay.service"

run_ssh "$SERVER" 'set -euo pipefail
systemctl stop v3-relay >/dev/null 2>&1 || true
install -m 0755 /tmp/swifttunnel-relay /usr/local/bin/swifttunnel-relay.new
mv -f /usr/local/bin/swifttunnel-relay.new /usr/local/bin/swifttunnel-relay
mv -f /tmp/v3-relay.service /etc/systemd/system/v3-relay.service

# Ensure env + token for localhost stats exists
mkdir -p /etc/swifttunnel
mkdir -p /etc/systemd/system/v3-relay.service.d
if [ ! -f /etc/swifttunnel/relay.env ]; then
  touch /etc/swifttunnel/relay.env
fi
existing_token=$(grep -E "^RELAY_STATS_TOKEN=" /etc/swifttunnel/relay.env | head -n1 | cut -d= -f2- || true)
if [ -z "$existing_token" ]; then
  token=$(openssl rand -hex 24 2>/dev/null || (head -c 24 /dev/urandom | base64 | tr -d "=/+\n" | head -c 48))
  if grep -q "^RELAY_STATS_TOKEN=" /etc/swifttunnel/relay.env; then
    sed -i "s|^RELAY_STATS_TOKEN=.*|RELAY_STATS_TOKEN=$token|" /etc/swifttunnel/relay.env
  else
    echo "RELAY_STATS_TOKEN=$token" >> /etc/swifttunnel/relay.env
  fi
fi
grep -q "^RELAY_STATS_PORT=" /etc/swifttunnel/relay.env || echo "RELAY_STATS_PORT=51822" >> /etc/swifttunnel/relay.env
grep -q "^RELAY_FLOW_CHANNEL_CAPACITY=" /etc/swifttunnel/relay.env || echo "RELAY_FLOW_CHANNEL_CAPACITY=256" >> /etc/swifttunnel/relay.env
cat > /etc/systemd/system/v3-relay.service.d/10-env.conf <<EOF
[Service]
EnvironmentFile=/etc/swifttunnel/relay.env
EOF

systemctl daemon-reload
systemctl enable v3-relay >/dev/null 2>&1 || true
systemctl start v3-relay
sleep 1
systemctl is-active --quiet v3-relay
journalctl -u v3-relay -n 15 --no-pager | tail -n 15
'

echo "OK: $SERVER"
