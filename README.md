# SwiftTunnel Relay

High-performance game traffic relay server (UDP + optional TUN offload for UDP/TCP). Inspired by ExitLag/WTFast architecture.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Overview

SwiftTunnel Relay provides **~0.5-1ms latency overhead** for game packet forwarding, compared to ~3-5ms with encrypted VPN solutions like WireGuard. It's designed for competitive gaming where every millisecond matters.

**Trade-off:** No encryption. Use this when latency is more important than privacy (e.g., gaming on trusted networks).

## Protocol

```
Client → Relay:  [session_id:8][IP packet with destination]
Client → Relay:  [session_id:8][0xA1][token_len:2][relay_ticket_utf8]
Client → Relay:  [session_id:8][0xA3][seq:4][client_ts_mono_ms:8]
Relay → Game:    [UDP payload only]
Game → Relay:    [UDP response]
Relay → Client:  [session_id:8][reconstructed IP packet]
Relay → Client:  [session_id:8][0xA2][status]
Relay → Client:  [session_id:8][0xA4][seq:4][client_ts_mono_ms:8][server_rx_ts_mono_ms:8]
```

The `Relay → Game` / `Game → Relay` lines above describe the default user-space UDP datapath. When `RELAY_TUN_UDP=true`, the client-facing framing stays the same, but the relay forwards the full inner IPv4 packet through the Linux TUN device instead of extracting bare UDP payloads.

The relay:
1. Receives packets prefixed with an 8-byte session ID
2. Parses the IP packet to extract destination address
3. Forwards just the UDP payload to the game server
4. Reconstructs IP packets for responses (with proper NAT address swapping)
5. Returns responses prefixed with the session ID
6. Optionally verifies signed relay tickets and binds authenticated `user_id`

Concurrency note:
- Keep the live-map lock order `sessions -> session_traffic`. RX accounting must
  drop any `session_traffic` `DashMap` guard before mutating `sessions`, or the
  cleanup/snapshot tasks can deadlock the datapath and stop draining the main
  UDP socket.

## Features

- **Ultra-low latency** - No encryption overhead
- **Selectable datapath** - `RELAY_DATAPATH=v1` (tokio per-flow tasks) or `v2` (sharded mio loop)
- **Lower p99 jitter (v2)** - buffer pool + single TX thread + sharded flow sockets
- **NAT rebinding resilience** - Handles client IP changes gracefully
- **Keepalive support** - Prevents NAT timeouts during idle periods
- **Graceful error recovery** - Transient errors don't kill flows
- **Bounded channels** - Backpressure prevents OOM (games handle packet loss)
- **Soft-delete with grace period** - Late packets can revive sessions
- **RTT/jitter ping (optional)** - ping/pong control frames for benchmarking/telemetry
- **TUN-backed IP forwarding (optional)** - Routes TCP and, optionally, UDP packets through a Linux TUN device (`RELAY_TCP_ENABLED=true`, `RELAY_TUN_UDP=true`)
- **Authenticated localhost telemetry API** - `/v1/stats` and `/v1/connections`, served from a dedicated localhost listener so relay telemetry does not depend on the Tokio worker pool

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/Swift-tunnel/swifttunnel-relay.git
cd swifttunnel-relay

# Build release binary
cargo build --release

# Binary will be at target/release/swifttunnel-relay
```

### Cross-compile for Linux (from macOS)

```bash
rustup target add x86_64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-gnu
```

## Usage

### Basic

```bash
# Run on default port 51821
./swifttunnel-relay

# Run on custom port
RELAY_PORT=9000 ./swifttunnel-relay

# Enable localhost telemetry API (recommended for server integrations)
RELAY_STATS_TOKEN=change-me RELAY_STATS_PORT=51822 ./swifttunnel-relay

# With debug logging
RUST_LOG=debug ./swifttunnel-relay
```

### Local Latency Probe

Use the bundled control-plane probe to measure relay RTT, jitter, and loss from your machine without tunneling gameplay traffic:

```bash
# Single relay
python3 probe-relay.py 45.32.115.254

# Include ICMP baseline and run 10 repeats
python3 probe-relay.py --icmp --repeat 10 45.32.115.254

# Compare multiple relays side by side
python3 probe-relay.py --icmp 45.32.115.254 54.255.205.216 45.32.253.124

# Auth-required relay
python3 probe-relay.py --ticket-file /path/to/relay-ticket.txt 45.32.115.254
```

This uses the relay's `0xA3`/`0xA4` ping/pong frames, so it measures client-to-relay control-plane RTT and loss. It does not send tunneled DNS/game packets.

### Relay Datapath Speedtest

Use the bundled relay datapath speedtest when you want to validate real tunneled
UDP forwarding instead of just relay ping/pong frames.

Run the public UDP server on the destination host:

```bash
python3 relay-speedtest.py server --bind 0.0.0.0 --port 9000
```

Or install the provided systemd unit:

```bash
sudo install -d /opt/swifttunnel
sudo install -m 0755 relay-speedtest.py /opt/swifttunnel/relay-speedtest.py
sudo install -m 0644 relay-speedtest.service /etc/systemd/system/relay-speedtest.service
sudo systemctl daemon-reload
sudo systemctl enable --now relay-speedtest
```

Run the client from a machine that can already receive UDP replies from the
relay, for example `Mac -> singapore-03 relay -> singapore-06 speedtest`:

```bash
python3 relay-speedtest.py client \
  --relay-host 45.32.115.254 \
  --target-host 104.64.209.241 \
  --target-port 9000 \
  --payload-bytes 1200 \
  --upload-packets 4000 \
  --download-packets 4000 \
  --upload-gap-us 50 \
  --download-gap-us 50 \
  --timeout-ms 5000
```

For auth-required relays, also pass `--ticket` or `--ticket-file`.

This script sends real `[session_id][IPv4 packet]` frames through the relay and
reports upload/download payload throughput plus packet loss for the actual relay
datapath. For larger WAN runs, add small pacing gaps plus a wider timeout so
the harness does not create its own burst loss and falsely implicate the relay.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_PORT` | `51821` | UDP port to listen on |
| `RELAY_STATS_PORT` | `51822` | Localhost HTTP telemetry port (`127.0.0.1` only) |
| `RELAY_STATS_TOKEN` | _(unset)_ | Enables/authenticates localhost telemetry API when set |
| `RELAY_AUTH_MODE` | `off` | Relay auth mode: `off`, `optional`, `required` |
| `RELAY_AUTH_PUBLIC_KEY_B64` | _(unset)_ | Ed25519 public key (required when auth mode is `optional`/`required`) |
| `RELAY_SERVER_ID` | _(unset)_ | Server region identifier expected in ticket `srv` claim |
| `RELAY_DATAPATH` | `v2` | Datapath: `v1` (tokio per-flow tasks) or `v2` (sharded mio loop) |
| `RELAY_SHARDS` | _(physical CPU count)_ | Shard count for `v2` (1..256) |
| `RELAY_V2_POOL_SLOTS` | `8192` | Fixed buffer pool slots for `v2` (512..262144) |
| `RELAY_V2_SHARD_QUEUE` | `4096` | Per-shard inbound queue depth for `v2` (256..262144) |
| `RELAY_V2_TX_QUEUE` | `8192` | TX queue depth for `v2` control/data (256..262144) |
| `RELAY_SOCKET_RCVBUF_BYTES` | `4194304` | `v2` main socket SO_RCVBUF size |
| `RELAY_SOCKET_SNDBUF_BYTES` | `4194304` | `v2` main socket SO_SNDBUF size |
| `RELAY_FLOW_RCVBUF_BYTES` | `2097152` | `v2` per-flow socket SO_RCVBUF size |
| `RELAY_FLOW_SNDBUF_BYTES` | `2097152` | `v2` per-flow socket SO_SNDBUF size |
| `RELAY_FLOW_CHANNEL_CAPACITY` | `256` | `v1` only: bounded channel size per flow (clamped to 8..4096) |
| `RELAY_TCP_ENABLED` | `false` | Enable TCP tunneling via TUN device (Linux only, requires `setup-tun.sh`) |
| `RELAY_TUN_UDP` | `false` | Forward UDP IPv4 packets through the Linux TUN device instead of per-flow sockets (Linux only, requires `setup-tun.sh`) |
| `RUST_LOG` | `info` | Log level (trace, debug, info, warn, error) |

### systemd Service

```ini
# /etc/systemd/system/swifttunnel-relay.service
[Unit]
Description=SwiftTunnel UDP Relay
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/swifttunnel-relay
Environment=RUST_LOG=info
Environment=RELAY_PORT=51821
Environment=RELAY_DATAPATH=v2
Environment=RELAY_STATS_PORT=51822
Environment=RELAY_STATS_TOKEN=replace-with-long-random-token
Environment=RELAY_AUTH_MODE=optional
Environment=RELAY_AUTH_PUBLIC_KEY_B64=replace-with-ed25519-public-key
Environment=RELAY_SERVER_ID=us-east-nj
Environment=RELAY_TUN_UDP=false
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable swifttunnel-relay
sudo systemctl start swifttunnel-relay
```

## Architecture

### Datapath v1 (tokio per-flow tasks)

```
┌────────────────────────────────────────────────┐
│                  Main Task                      │
│  - Receives from clients on configured port     │
│  - Parses [session_id][IP packet]               │
│  - Routes to flow tasks via channels            │
└───────────────────────┬────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│   Flow Task   │ │   Flow Task   │ │   Flow Task   │
│ session+game1 │ │ session+game2 │ │ session+game3 │
│  - Connected  │ │  - Connected  │ │  - Connected  │
│    socket to  │ │    socket to  │ │    socket to  │
│    game       │ │    game       │ │    game       │
└───────────────┘ └───────────────┘ └───────────────┘
        │               │               │
        └───────────────┼───────────────┘
                        ▼
                ┌───────────────┐
                │ Response Task │
                │ Sends back to │
                │    clients    │
                └───────────────┘
```

### Datapath v2 (sharded mio loop)

```
┌────────────────────────────────────────────────┐
│                  RX Thread                      │
│  - Receives from clients on configured port     │
│  - Parses control + data frames                 │
│  - Dispatches by session_id -> shard inbox      │
└───────────────────────┬────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│    Shard 0    │ │    Shard 1    │ │    Shard N    │
│  - mio poll   │ │  - mio poll   │ │  - mio poll   │
│  - flow map   │ │  - flow map   │ │  - flow map   │
└───────────────┴───────────────┴───────────────┘
                        │
                        ▼
                ┌───────────────┐
                │   TX Thread   │
                │ Single sender │
                │  to clients   │
                └───────────────┘
```

### TUN-backed UDP offload (optional)

When `RELAY_TUN_UDP=true`, the relay creates a TUN device (`swifttun0`) and forwards full UDP IPv4 packets through the Linux kernel instead of maintaining per-flow UDP sockets in user-space. The client framing stays the same (`[session_id][ip packet]`), but the relay rewrites the inner source IP to a per-session TUN IP and lets the kernel handle routing/NAT on the server side.

This path is currently not recommended for production rollout. Keep
`RELAY_TUN_UDP=false` unless you are doing a short-lived canary while actively
measuring latency and jitter.

Fragmented IPv4 packets stay fragment-safe on this path: after the relay rewrites
the inner source/destination IP, it refreshes the IPv4 header checksum on every
fragment, updates the transport checksum pseudo-header only on fragment `0`, and
leaves later fragment payload bytes untouched until the far endpoint reassembles
the full datagram.

This removes the relay's hottest user-space work:
- per-flow socket creation and mio registration
- UDP payload extraction
- reconstructed response IP packet building
- repeated checksum rebuilds on the user-space return path

**Setup (run once per server):**
```bash
sudo ./setup-tun.sh
```

This enables IP forwarding, configures NAT masquerade for the `10.200.0.0/16` TUN subnet, and adds the FORWARD rules needed for return traffic. The relay now brings `swifttun0` up and reapplies `10.200.0.1/16` on every start, so you no longer need a separate manual `ip addr add ... && ip link set ... up` step after restarts.

**Experimental enablement only:**
```bash
# Via systemd drop-in
sudo mkdir -p /etc/systemd/system/v3-relay.service.d
echo -e '[Service]\nEnvironment=RELAY_TUN_UDP=true' | sudo tee /etc/systemd/system/v3-relay.service.d/20-tun-udp.conf
sudo systemctl daemon-reload
sudo systemctl restart v3-relay
```

**Rollback / production override:**
```bash
sudo mkdir -p /etc/systemd/system/v3-relay.service.d
echo -e '[Service]\nEnvironment=RELAY_TUN_UDP=false' | sudo tee /etc/systemd/system/v3-relay.service.d/90-disable-tun-udp.conf
sudo systemctl daemon-reload
sudo systemctl restart v3-relay
```

### TUN-based TCP forwarding (optional)

When `RELAY_TCP_ENABLED=true`, the relay uses the same TUN device (`swifttun0`) to route TCP packets from clients through the Linux kernel's TCP stack. This allows game API calls (HTTPS) to be tunneled alongside UDP gameplay traffic when needed.

**Setup (run once per server):**
```bash
sudo ./setup-tun.sh
```

This enables IP forwarding, configures NAT masquerade for the `10.200.0.0/16` TUN subnet, and adds TCP MSS clamping. The relay handles the runtime `swifttun0` address/link setup itself on each start.

**Enable:**
```bash
# Via systemd drop-in
sudo mkdir -p /etc/systemd/system/v3-relay.service.d
echo -e '[Service]\nEnvironment=RELAY_TCP_ENABLED=true' | sudo tee /etc/systemd/system/v3-relay.service.d/20-tcp.conf
sudo systemctl daemon-reload
sudo systemctl restart v3-relay
```

**How it works:**
1. Client sends `[session_id:8][TCP IPv4 packet]` (same framing as UDP)
2. Relay assigns each session a unique IP in `10.200.0.0/16`
3. Rewrites source IP and writes raw packet to TUN device
4. Linux kernel handles TCP handshake, retransmission, etc.
5. Response packets read from TUN, source IP restored, sent back to client

**Requirements:** Linux, `/dev/net/tun`, `CAP_NET_ADMIN`

## Client Implementation

To connect to this relay, your client needs to:

1. **Generate a random 8-byte session ID**
2. **Fetch a short-lived relay ticket** from your control-plane/web API
3. **Send auth hello**: `[session_id:8][0xA1][token_len:2][ticket_utf8]`
4. **Wait for auth ack**: `[session_id:8][0xA2][status]`
5. **(Optional) RTT/jitter ping**: `[session_id:8][0xA3][seq:4][client_ts_mono_ms:8]` → `[session_id:8][0xA4]...`
6. **Intercept game UDP packets** (e.g., using NDIS, WFP, or iptables)
7. **Wrap packets**: `[session_id:8][original IP packet]`
8. **Send to relay server** on configured port
9. **Receive responses**: `[session_id:8][response IP packet]`
10. **Inject responses** back to the game

Auth ack status codes:
- `0` ok
- `1` bad_format
- `2` bad_signature
- `3` expired
- `4` sid_mismatch
- `5` server_mismatch
- `6` auth_disabled

**Keepalive:** Send just the session ID (8 bytes, no payload) every 15-20 seconds to maintain NAT bindings.

See the [SwiftTunnel App](https://github.com/Swift-tunnel/swifttunnel-app) for a reference client implementation.

## Firewall

```bash
# Open the relay port
sudo ufw allow 51821/udp

# Speedtest server port
sudo ufw allow 9000/udp
```

## Monitoring

Stats are logged every 60 seconds:

```
Stats: in=1234 out=1230 (1.5/1.4 MB), 40 pkt/s, sessions=5, flows=8, dropped=0+0
```

View logs:
```bash
journalctl -u swifttunnel-relay -f
```

Quick local probe:
```bash
python3 probe-relay.py --icmp 45.32.115.254
```

### Localhost Telemetry API

When `RELAY_STATS_TOKEN` is configured, relay exposes authenticated HTTP telemetry endpoints on:

`http://127.0.0.1:${RELAY_STATS_PORT}`

Authentication header (required):

`Authorization: Bearer ${RELAY_STATS_TOKEN}`

Available endpoints:
- `GET /v1/stats` - relay-level counters and rates (card-safe, does not scan live session maps)
- `GET /v1/connections` - live session rows (`user_id`, `session_id`, `auth_state`, activity, bytes, endpoint)

Current `user_id` behavior:
- uses authenticated identity when available
- otherwise falls back to tunnel source IP/session-derived identity

Example:
```bash
curl -s \
  -H "Authorization: Bearer $RELAY_STATS_TOKEN" \
  http://127.0.0.1:51822/v1/stats

curl -s \
  -H "Authorization: Bearer $RELAY_STATS_TOKEN" \
  http://127.0.0.1:51822/v1/connections
```

`/v1/stats` response fields:
- `version`
- `timestamp`
- `active_users` - card-safe approximation that mirrors active session count
- `active_sessions`
- `throttled_users`
- `inbound_bps` - rolling `client -> relay` bytes/sec sampled from recent traffic
- `outbound_bps` - rolling `relay -> client` bytes/sec sampled from recent traffic
- `dropped_in`
- `dropped_out`
- `dropped_pps`
- `pool_exhausted` - datapath v2 buffer-pool acquire failures; a non-zero rate
  means `RELAY_V2_POOL_SLOTS` needs to be raised. Also contributes to
  `dropped_out`, so the two counters together let you split "queue full" from
  "pool empty" drops.
- `tcp_forwarded`
- `tun_udp_forwarded`

Use `/v1/connections` when you need exact per-session identity details. The stats endpoint intentionally avoids walking the live session map so heartbeat/admin counters stay responsive under load even if detailed connection scans get stuck. `/v1/connections` itself is served from a cached snapshot refreshed once per second, and the localhost HTTP listener now runs on dedicated blocking threads so local observability polling cannot pile up on the Tokio runtime.

## Performance Tuning

For optimal performance on Linux:

```bash
# Increase UDP buffer sizes
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216

# Enable BBR congestion control
sysctl -w net.ipv4.tcp_congestion_control=bbr

# Reduce conntrack timeouts for gaming
sysctl -w net.netfilter.nf_conntrack_udp_timeout=30
sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=60
```

## Self-Hosting with SwiftTunnel Client

The [SwiftTunnel desktop app](https://github.com/Swift-tunnel/swifttunnel-app) can be configured to use your own relay:

```bash
# Set environment variables before launching
set SWIFTTUNNEL_RELAY_HOST=your-relay-server.com
set SWIFTTUNNEL_RELAY_PORT=51821
swifttunnel.exe
```

*Note: This requires building the client from source with the environment variable support patch.*

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please open an issue or PR on [GitHub](https://github.com/Swift-tunnel/swifttunnel-relay).

## Related Projects

- [SwiftTunnel App](https://github.com/Swift-tunnel/swifttunnel-app) - Desktop VPN client with split tunneling
- [SwiftTunnel Web](https://github.com/evelynwantscookies-ship-it/swifttunnel-web) - Website and dashboard
