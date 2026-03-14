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

# 3. Detect primary outbound interface
PRIMARY_IF=$(ip route show default | awk '/default/ {print $5; exit}')
if [ -z "$PRIMARY_IF" ]; then
    echo "[!] Could not detect primary interface, defaulting to eth0"
    PRIMARY_IF="eth0"
fi
echo "[*] Primary interface: $PRIMARY_IF"

# 4. NAT masquerade for TUN subnet
if ! iptables -t nat -C POSTROUTING -o "$PRIMARY_IF" -s "$TUN_SUBNET" -j MASQUERADE 2>/dev/null; then
    echo "[+] Adding MASQUERADE rule for $TUN_SUBNET..."
    iptables -t nat -A POSTROUTING -o "$PRIMARY_IF" -s "$TUN_SUBNET" -j MASQUERADE
else
    echo "[=] MASQUERADE rule already exists"
fi

# 5. TCP MSS clamping to avoid fragmentation through the tunnel
# This remains TCP-specific; UDP uses the same NAT/FORWARD path but has no MSS.
# MTU: 1500 (ethernet) - 20 (outer IP) - 8 (outer UDP) - 8 (session_id) - 20 (inner IP) - 20 (TCP)
# = 1424 bytes MSS
if ! iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -s "$TUN_SUBNET" -j TCPMSS --set-mss 1424 2>/dev/null; then
    echo "[+] Adding TCP MSS clamping rule (1424)..."
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -s "$TUN_SUBNET" -j TCPMSS --set-mss 1424
else
    echo "[=] TCP MSS clamping rule already exists"
fi

# 6. FORWARD rules — needed when default FORWARD policy is DROP (e.g. UFW)
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

# 7. Persist iptables rules
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
echo "  3. After relay starts, assign TUN IP: ip addr add 10.200.0.1/16 dev swifttun0 && ip link set swifttun0 up"
