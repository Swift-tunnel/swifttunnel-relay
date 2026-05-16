#!/usr/bin/env bash
# setup-tun.sh — Configure TUN device and iptables for relay TUN forwarding
#
# Run once on each relay server before enabling RELAY_TCP_ENABLED=true and/or
# RELAY_TUN_UDP=true.
# Requires root privileges.

set -euo pipefail

TUN_SUBNET="10.200.0.0/16"
TUN_DEVICE="swifttun0"

echo "=== SwiftTunnel TUN Setup ==="

# 1. Load TUN kernel module
if ! lsmod | grep -q "^tun "; then
    echo "[+] Loading tun kernel module..."
    modprobe tun
else
    echo "[=] tun module already loaded"
fi

# Persist across reboots
if ! grep -q "^tun$" /etc/modules-load.d/*.conf 2>/dev/null; then
    echo "tun" > /etc/modules-load.d/swifttunnel-tun.conf
    echo "[+] Added tun to /etc/modules-load.d/swifttunnel-tun.conf"
fi

# 2. Enable IP forwarding
current_forward=$(sysctl -n net.ipv4.ip_forward)
if [ "$current_forward" != "1" ]; then
    echo "[+] Enabling net.ipv4.ip_forward..."
    sysctl -w net.ipv4.ip_forward=1
else
    echo "[=] IP forwarding already enabled"
fi

# Persist
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.d/*.conf 2>/dev/null; then
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-swifttunnel.conf
    echo "[+] Persisted IP forwarding to /etc/sysctl.d/99-swifttunnel.conf"
fi

# 3. Raise UDP socket buffer ceilings for relay burst handling
#
# The relay requests multi-megabyte SO_RCVBUF/SO_SNDBUF values. Some fresh
# Ubuntu images default net.core.rmem_max/wmem_max to 212992, silently capping
# the relay to ~416 KiB effective buffers and causing burst loss under load.
cat > /etc/sysctl.d/98-swifttunnel-relay-buffers.conf <<'EOF'
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.rmem_default=8388608
net.core.wmem_default=8388608
EOF
sysctl --system >/dev/null
echo "[+] Applied relay socket buffer sysctls"

# 4. Detect primary outbound interface
PRIMARY_IF=$(ip route show default | awk '/default/ {print $5; exit}')
if [ -z "$PRIMARY_IF" ]; then
    echo "[!] Could not detect primary interface, defaulting to eth0"
    PRIMARY_IF="eth0"
fi
echo "[*] Primary interface: $PRIMARY_IF"

# 5. NAT masquerade for TUN subnet
if ! iptables -t nat -C POSTROUTING -o "$PRIMARY_IF" -s "$TUN_SUBNET" -j MASQUERADE 2>/dev/null; then
    echo "[+] Adding MASQUERADE rule for $TUN_SUBNET..."
    iptables -t nat -A POSTROUTING -o "$PRIMARY_IF" -s "$TUN_SUBNET" -j MASQUERADE
else
    echo "[=] MASQUERADE rule already exists"
fi

# 6. TCP MSS clamping to avoid fragmentation through the tunnel
# This remains TCP-specific; UDP uses the same NAT/FORWARD path but has no MSS.
# swifttun0 runs at MTU 1400. Use a worst-case IPv4+TCP header budget (60)
# so large TCP/API asset responses do not rely on PMTU discovery or fragments.
TCP_MSS=1340

# Remove the old overly-large rule if it exists; otherwise it can match before
# the safe clamp and still advertise segments too large for swifttun0.
iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -s "$TUN_SUBNET" -j TCPMSS --set-mss 1424 2>/dev/null || true

if ! iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -s "$TUN_SUBNET" -j TCPMSS --set-mss "$TCP_MSS" 2>/dev/null; then
    echo "[+] Adding TCP MSS clamping rule ($TCP_MSS)..."
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -s "$TUN_SUBNET" -j TCPMSS --set-mss "$TCP_MSS"
else
    echo "[=] TCP MSS clamping rule already exists"
fi

# 7. FORWARD rules — needed when default FORWARD policy is DROP (e.g. UFW)
FORBIDDEN_FORWARD_DESTS=(
    "0.0.0.0/8"
    "10.0.0.0/8"
    "100.64.0.0/10"
    "127.0.0.0/8"
    "169.254.0.0/16"
    "172.16.0.0/12"
    "192.168.0.0/16"
    "224.0.0.0/4"
    "240.0.0.0/4"
)
for dst in "${FORBIDDEN_FORWARD_DESTS[@]}"; do
    if ! iptables -C FORWARD -i "$TUN_DEVICE" -d "$dst" -j DROP 2>/dev/null; then
        echo "[+] Adding FORWARD DROP rule for forbidden destination $dst..."
        iptables -I FORWARD 1 -i "$TUN_DEVICE" -d "$dst" -j DROP
    else
        echo "[=] FORWARD DROP rule for $dst already exists"
    fi
done

if ! iptables -C FORWARD -i "$TUN_DEVICE" -o "$PRIMARY_IF" -s "$TUN_SUBNET" -j ACCEPT 2>/dev/null; then
    echo "[+] Adding FORWARD ACCEPT rule for $TUN_DEVICE → $PRIMARY_IF..."
    iptables -I FORWARD 1 -i "$TUN_DEVICE" -o "$PRIMARY_IF" -s "$TUN_SUBNET" -j ACCEPT
else
    echo "[=] FORWARD outbound rule already exists"
fi

if ! iptables -C FORWARD -i "$PRIMARY_IF" -o "$TUN_DEVICE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
    echo "[+] Adding FORWARD ACCEPT rule for return traffic → $TUN_DEVICE..."
    iptables -I FORWARD 2 -i "$PRIMARY_IF" -o "$TUN_DEVICE" -m state --state RELATED,ESTABLISHED -j ACCEPT
else
    echo "[=] FORWARD return traffic rule already exists"
fi

# 8. Persist iptables rules
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save
    echo "[+] Saved iptables rules via netfilter-persistent"
elif command -v iptables-save &>/dev/null; then
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
    iptables-save > /etc/iptables.rules 2>/dev/null || \
    echo "[!] Could not auto-persist iptables rules. Save manually."
fi

echo ""
echo "=== TUN setup complete ==="
echo "Next steps:"
echo "  1. Set RELAY_TCP_ENABLED=true and/or RELAY_TUN_UDP=true in the relay service environment"
echo "  2. Restart the relay: sudo systemctl restart v3-relay"
echo "  3. Verify the relay brought swifttun0 up with 10.200.0.1/16 assigned"
