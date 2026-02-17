# SwiftTunnel Relay

High-performance UDP relay server for low-latency game traffic. Inspired by ExitLag/WTFast architecture.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Overview

SwiftTunnel Relay provides **~0.5-1ms latency overhead** for game packet forwarding, compared to ~3-5ms with encrypted VPN solutions like WireGuard. It's designed for competitive gaming where every millisecond matters.

**Trade-off:** No encryption. Use this when latency is more important than privacy (e.g., gaming on trusted networks).

## Protocol

```
Client → Relay:  [session_id:8][IP packet with destination]
Relay → Game:    [UDP payload only]
Game → Relay:    [UDP response]
Relay → Client:  [session_id:8][reconstructed IP packet]
```

The relay:
1. Receives packets prefixed with an 8-byte session ID
2. Parses the IP packet to extract destination address
3. Forwards just the UDP payload to the game server
4. Reconstructs IP packets for responses (with proper NAT address swapping)
5. Returns responses prefixed with the session ID

## Features

- **Ultra-low latency** - No encryption overhead
- **Per-flow async tasks** - Efficient handling of multiple game connections
- **NAT rebinding resilience** - Handles client IP changes gracefully
- **Keepalive support** - Prevents NAT timeouts during idle periods
- **Graceful error recovery** - Transient errors don't kill flows
- **Bounded channels** - Backpressure prevents OOM (games handle packet loss)
- **Soft-delete with grace period** - Late packets can revive sessions

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

# With debug logging
RUST_LOG=debug ./swifttunnel-relay
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_PORT` | `51821` | UDP port to listen on |
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

## Client Implementation

To connect to this relay, your client needs to:

1. **Generate a random 8-byte session ID**
2. **Intercept game UDP packets** (e.g., using NDIS, WFP, or iptables)
3. **Wrap packets**: `[session_id:8][original IP packet]`
4. **Send to relay server** on configured port
5. **Receive responses**: `[session_id:8][response IP packet]`
6. **Inject responses** back to the game

**Keepalive:** Send just the session ID (8 bytes, no payload) every 15-20 seconds to maintain NAT bindings.

See the [SwiftTunnel App](https://github.com/Swift-tunnel/swifttunnel-app) for a reference client implementation.

## Firewall

```bash
# Open the relay port
sudo ufw allow 51821/udp

# Or with custom port
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
