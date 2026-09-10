#!/usr/bin/env bash
# update-dest-allowlist.sh: regenerate the relay's destination allowlist.
#
# Writes every IPv4 prefix Roblox's two networks (AS22697, AS11281) announce
# today, from RIPEstat, for UDP and TCP. Adds AWS's published CloudFront ranges
# for TCP only, because Roblox fronts part of its control plane on CloudFront
# and Route Assist carries that HTTPS through the relay.
#
# Usage: sudo ./update-dest-allowlist.sh [output-path]
#   Default output: /etc/swifttunnel/dest-allowlist.txt
#
# The relay reads the file once, at startup: set RELAY_DEST_ALLOWLIST_FILE to
# it and restart the relay to load a new one. The current file is only
# replaced when the fresh download looks complete, so a failed or partial
# fetch leaves it in place. Needs only curl and grep.

set -euo pipefail

OUT="${1:-/etc/swifttunnel/dest-allowlist.txt}"
ROBLOX_ASNS=(AS22697 AS11281)
RIPESTAT="https://stat.ripe.net/data/announced-prefixes/data.json?resource="
CLOUDFRONT="https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips"
IPV4_CIDR='[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}'

fetch() {
    curl -fsS --retry 2 --max-time 30 "$1"
}

roblox=""
for asn in "${ROBLOX_ASNS[@]}"; do
    if ! body=$(fetch "${RIPESTAT}${asn}"); then
        echo "[!] Could not fetch $asn from RIPEstat; leaving $OUT unchanged" >&2
        exit 1
    fi
    # Only the prefix fields. IPv6 prefixes do not match the IPv4 pattern.
    prefixes=$(printf '%s' "$body" \
        | grep -oE "\"prefix\": ?\"${IPV4_CIDR}\"" \
        | grep -oE "${IPV4_CIDR}" || true)
    if [ -z "$prefixes" ]; then
        echo "[!] RIPEstat returned no IPv4 prefixes for $asn; leaving $OUT unchanged" >&2
        exit 1
    fi
    roblox+="# Roblox, ${asn}, announced prefixes per RIPEstat"$'\n'"${prefixes}"$'\n'
done

if ! body=$(fetch "$CLOUDFRONT"); then
    echo "[!] Could not fetch the CloudFront list; leaving $OUT unchanged" >&2
    exit 1
fi
cloudfront=$(printf '%s' "$body" | grep -oE "${IPV4_CIDR}" || true)

roblox_count=$(printf '%s' "$roblox" | grep -cE "^${IPV4_CIDR}\$" || true)
cloudfront_count=$(printf '%s\n' "$cloudfront" | grep -cE "^${IPV4_CIDR}\$" || true)
if ! printf '%s' "$roblox" | grep -qE '^128\.116\.'; then
    echo "[!] No 128.116.x prefix among Roblox's announcements, which is where its game servers live. Not trusting this download; leaving $OUT unchanged" >&2
    exit 1
fi
if [ "$cloudfront_count" -lt 50 ]; then
    echo "[!] Only $cloudfront_count CloudFront prefixes, expected well over 100; leaving $OUT unchanged" >&2
    exit 1
fi

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
{
    echo "# SwiftTunnel relay destination allowlist"
    echo "# Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) by update-dest-allowlist.sh"
    echo "# A bare prefix applies to UDP and TCP; 'tcp <prefix>' to TCP only."
    printf '%s' "$roblox"
    echo "# CloudFront, TCP only, per AWS's published edge list"
    printf '%s\n' "$cloudfront" | sed 's/^/tcp /'
} > "$tmp"

mkdir -p "$(dirname "$OUT")"
install -m 0644 "$tmp" "$OUT"
echo "[+] Wrote $OUT: $roblox_count Roblox prefixes, $cloudfront_count CloudFront prefixes (TCP only)"
echo "    Set RELAY_DEST_ALLOWLIST_FILE=$OUT and restart the relay to load it."
