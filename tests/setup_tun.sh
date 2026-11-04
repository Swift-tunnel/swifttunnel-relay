#!/usr/bin/env bash
# No root, TUN or real firewall: setup-tun.sh runs against a fake iptables
# that keeps its rules in a file, with config written under a temp /etc.
set -euo pipefail
script="$(cd -- "$(dirname -- "$0")/.." && pwd)/setup-tun.sh"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/etc/modules-load.d" "$work/etc/sysctl.d" "$work/etc/iptables"
export SWIFTTUNNEL_ETC_DIR="$work/etc"
export RULES="$work/rules"
: > "$RULES"

# One rule per line: "<table> <chain> <spec>".
iptables() {
    local table=filter
    if [[ $1 == -t ]]; then table=$2; shift 2; fi
    local op=$1 chain=$2
    shift 2
    local prefix="$table $chain "
    case $op in
        -C) grep -qxF -- "$prefix$*" "$RULES" ;;
        -A) printf '%s\n' "$prefix$*" >> "$RULES" ;;
        -I)
            local pos=1
            if [[ ${1:-} =~ ^[0-9]+$ ]]; then pos=$1; shift; fi
            awk -v p="$prefix" -v pos="$pos" -v rule="$prefix$*" '
                index($0, p) == 1 { n++; if (n == pos && !done) { print rule; done = 1 } }
                { print }
                END { if (!done) print rule }' "$RULES" > "$RULES.new"
            command mv "$RULES.new" "$RULES"
            ;;
        -D)
            if [[ $# == 1 && $1 =~ ^[0-9]+$ ]]; then
                awk -v p="$prefix" -v pos="$1" '
                    index($0, p) == 1 { n++; if (n == pos) next }
                    { print }' "$RULES" > "$RULES.new"
            else
                grep -qxF -- "$prefix$*" "$RULES" || return 1
                awk -v rule="$prefix$*" '$0 == rule && !done { done = 1; next } { print }' \
                    "$RULES" > "$RULES.new"
            fi
            command mv "$RULES.new" "$RULES"
            ;;
        -L)
            echo "Chain $chain (policy ACCEPT)"
            echo "num  target     prot opt source               destination"
            awk -v p="$prefix" 'index($0, p) == 1 {
                    n++
                    rule = substr($0, length(p) + 1)
                    # iptables -L shows a comment match as /* name */.
                    while (match(rule, /-m comment --comment [^ ]+/)) {
                        name = substr(rule, RSTART + 21, RLENGTH - 21)
                        rule = substr(rule, 1, RSTART - 1) "/* " name " */" \
                            substr(rule, RSTART + RLENGTH)
                    }
                    print n, rule
                }' "$RULES"
            ;;
        *) echo "fake iptables: unsupported $op" >&2; return 2 ;;
    esac
}
lsmod() { echo 'tun 49152 0'; }
modprobe() { :; }
sysctl() { if [[ $1 == -n ]]; then echo 1; fi; }
ip() { echo 'default via 192.0.2.1 dev eth0 proto static'; }
netfilter-persistent() { :; }
export -f iptables lsmod modprobe sysctl ip netfilter-persistent

count() { grep -cxF -- "$1" "$RULES" || true; }
input_drop='filter INPUT -i swifttun0 -m comment --comment swifttunnel-tun-input -j DROP'
mss_out='mangle FORWARD -p tcp --tcp-flags SYN,RST SYN -s 10.200.0.0/16 -j TCPMSS --set-mss 1340'
mss_in='mangle FORWARD -o swifttun0 -p tcp --tcp-flags SYN,RST SYN -d 10.200.0.0/16 -j TCPMSS --set-mss 1340'

bash "$script" >/dev/null
# Locally addressed tunnel traffic is dropped before any other INPUT rule.
[[ $(grep -m1 '^filter INPUT ' "$RULES") == "$input_drop" ]]
[[ $(count "$mss_out") == 1 && $(count "$mss_in") == 1 ]]
grep -qx 'tun' "$work/etc/modules-load.d/swifttunnel-tun.conf"
sort "$RULES" > "$work/first"

# Rerunning changes nothing and duplicates nothing.
bash "$script" >/dev/null
sort "$RULES" | diff - "$work/first"
[[ $(count "$input_drop") == 1 ]]

# Limit modes replace each other and off removes them.
TUN_TCP_LIMIT_MODE=enforce bash "$script" >/dev/null
[[ $(grep -c 'swifttunnel-tcp-.*-j DROP$' "$RULES") == 2 ]]
TUN_TCP_LIMIT_MODE=off bash "$script" >/dev/null
[[ $(grep -c 'swifttunnel-tcp-' "$RULES") == 0 ]]
[[ $(count "$input_drop") == 1 ]]
echo 'setup-tun tests passed'
