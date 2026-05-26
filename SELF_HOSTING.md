# Self-Hosting SwiftTunnel Relay

A complete guide to running your own SwiftTunnel relay and pointing the desktop
app at it. Written for the post-shutdown world where the hosted SwiftTunnel
service is going away and you want to keep the gaming-VPN latency benefit on
infrastructure you control.

> **Heads up:** the relay itself self-hosts cleanly with one binary and no
> external dependencies. The desktop app is more entangled — it expects the
> hosted swifttunnel.net web API (server list, login, profile) to be alive.
> The [Hosted-service dependencies](#hosted-service-dependencies) section at
> the end covers how to handle that.

## Table of Contents

1. [Architecture in one minute](#architecture-in-one-minute)
2. [Prerequisites](#prerequisites)
3. [Step 1 — Provision a server](#step-1--provision-a-server)
4. [Step 2 — Build the relay](#step-2--build-the-relay)
5. [Step 3 — Deploy the binary](#step-3--deploy-the-binary)
6. [Step 4 — Network setup (TUN + firewall + sysctls)](#step-4--network-setup-tun--firewall--sysctls)
7. [Step 5 — systemd unit (open relay)](#step-5--systemd-unit-open-relay)
8. [Step 6 — Verify the relay](#step-6--verify-the-relay)
9. [Step 7 — Point the SwiftTunnel app at your relay](#step-7--point-the-swifttunnel-app-at-your-relay)
10. [Multi-region setup](#multi-region-setup)
11. [Performance tuning](#performance-tuning)
12. [Hardening](#hardening)
13. [Troubleshooting](#troubleshooting)
14. [Hosted-service dependencies](#hosted-service-dependencies)
15. [Writing your own client](#writing-your-own-client)

---

## Architecture in one minute

```
   Roblox.exe                Desktop app                    Your relay
       │                          │                              │
       ├── UDP packet ──────────► │ NDIS intercept               │
       │                          ├── Process is Roblox?         │
       │                          │   yes → [sid][packet] ──────►│ → game server
       │                          │   no  → passthrough          │
       │ ◄────────────────────────┼──────────────────────────────┤ response
```

The relay is a stateless UDP forwarder. It:

- Listens on `RELAY_PORT/UDP` (default `51821`).
- Receives `[session_id:8][full IPv4 packet]` frames from the client.
- Strips the IP header, opens an outbound socket toward the destination, and
  forwards the UDP payload (or, with `RELAY_TUN_UDP=true`, hands the whole
  packet to the Linux kernel via a TUN device).
- Reconstructs response IP packets and ships them back to the client.

No encryption. No login. No persistent state. Latency overhead is ~0.5–1 ms
versus 3–5 ms for an encrypted VPN.

## Prerequisites

**On your server:**
- A Linux box with root access (Ubuntu 22.04+ or Debian 12 recommended).
- Kernel with `/dev/net/tun` (every mainstream distro since forever).
- A public IPv4 address.
- An open UDP port (`51821` by default — change as you like).
- ~50 MB disk, 256 MB RAM minimum. The binary itself is a single ~5 MB
  executable.

**On your local machine:**
- Rust toolchain (`rustup`) if you're building from source.
- SSH access to the server.
- The SwiftTunnel desktop app installed (Windows).

**You do _not_ need:**
- A SwiftTunnel account.
- A Supabase project or web deployment.
- Ed25519 ticket signing keys.
- The hosted `swifttunnel.net` infrastructure (but see
  [Hosted-service dependencies](#hosted-service-dependencies) — the app still
  reaches out for a few things).

## Step 1 — Provision a server

Pick a region with the lowest latency to your **target game backbone**, not
to your home. For Roblox, the major Roblox datacenters are in:

- US East (Ashburn, VA) and US West (San Jose, CA)
- Frankfurt and London
- Tokyo
- Sydney
- Singapore

A relay in the same region as the game server reduces overall trip time the
most.

Tested cheap options (no endorsement, just shapes that work):

- **Vultr / Linode / DigitalOcean** — $5–6/mo VMs, global regions.
- **Hetzner Cloud** — extremely cheap EU/US, 1 Gbps shared.
- **OVH VPS** — cheap European/Canadian boxes, 250 Mbps–1 Gbps.
- **AWS Lightsail** — predictable pricing, broad region map.

For personal use, a single 1 vCPU / 1 GB box handles 50+ concurrent gaming
sessions comfortably.

## Step 2 — Build the relay

Clone the repository and produce a release binary.

### Native build on Linux

```bash
git clone https://github.com/Swift-tunnel/swifttunnel-relay.git
cd swifttunnel-relay

cargo build --release
ls -lh target/release/swifttunnel-relay
```

### Cross-compile from macOS / Windows

You don't need to install Rust on the server itself. Cross-compile to
`x86_64-unknown-linux-gnu` and copy the binary.

```bash
rustup target add x86_64-unknown-linux-gnu

# Apple Silicon hosts need a GNU linker:
brew install messense/macos-cross-toolchains/x86_64-unknown-linux-gnu

# Tell cargo about the linker:
mkdir -p ~/.cargo
cat >> ~/.cargo/config.toml <<'EOF'
[target.x86_64-unknown-linux-gnu]
linker = "x86_64-unknown-linux-gnu-gcc"
EOF

cargo build --release --target x86_64-unknown-linux-gnu
ls -lh target/x86_64-unknown-linux-gnu/release/swifttunnel-relay
```

### Sanity check

```bash
./target/release/swifttunnel-relay --version
# expected: swifttunnel-relay 1.5.0
```

## Step 3 — Deploy the binary

```bash
# Copy the relay binary, the TUN setup script, and the systemd unit template
scp target/release/swifttunnel-relay         root@SERVER:/usr/local/bin/
scp setup-tun.sh                             root@SERVER:/root/
scp v3-relay.service                         root@SERVER:/tmp/

ssh root@SERVER 'chmod +x /usr/local/bin/swifttunnel-relay /root/setup-tun.sh'
```

> The repo's `deploy.sh` and `deploy-single.sh` scripts are intended for the
> hosted multi-server fleet rollout — they hardcode the auth-enabled config.
> For self-hosting, the manual `scp` + `systemctl` flow below is simpler and
> easier to audit.

## Step 4 — Network setup (TUN + firewall + sysctls)

SSH into the server and run the setup script. It's idempotent — re-running it
won't break anything.

```bash
ssh root@SERVER

sudo /root/setup-tun.sh
```

The script:

- Enables IPv4 forwarding (`net.ipv4.ip_forward=1`, persisted to
  `/etc/sysctl.d/99-swifttunnel.conf`).
- Raises UDP socket buffers (`net.core.rmem_max`/`wmem_max` to 16 MiB,
  defaults 8 MiB).
- Creates a `swifttun0` TUN device and assigns `10.200.0.1/16`.
- Configures NAT masquerade for the `10.200.0.0/16` subnet.
- Installs FORWARD drops for private (RFC1918) / link-local / loopback /
  multicast / reserved / CGNAT (100.64.0.0/10) destinations **before** the
  managed outbound ACCEPT rule. This prevents the relay from being used as a
  pivot into internal networks.
- MSS-clamps TCP at 1340 bytes so large API/asset responses fit the 1400-byte
  `swifttun0` MTU without relying on PMTU discovery.

If the script fails, check `/tmp/swifttunnel-setup-tun.log`.

Verify:

```bash
ip addr show swifttun0
# expected: inet 10.200.0.1/16 ... scope global swifttun0

sysctl net.ipv4.ip_forward
# expected: net.ipv4.ip_forward = 1
```

Open the relay port in the host firewall:

```bash
# UFW
sudo ufw allow 51821/udp

# or iptables directly
sudo iptables -A INPUT -p udp --dport 51821 -j ACCEPT
sudo iptables-save | sudo tee /etc/iptables/rules.v4 >/dev/null
```

Also open UDP/51821 in your cloud provider's security group (AWS, OVH,
DigitalOcean panel).

## Step 5 — systemd unit (open relay)

This is the **self-host** systemd unit. It runs the relay with auth disabled,
which is the mode the desktop app's "Custom relay server" path expects.

```bash
sudo tee /etc/systemd/system/swifttunnel-relay.service >/dev/null <<'EOF'
[Unit]
Description=SwiftTunnel UDP Relay (self-hosted)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/swifttunnel-relay
Restart=always
RestartSec=5
LimitNOFILE=65535

# --- Core relay config ---
Environment=RUST_LOG=info
Environment=RELAY_PORT=51821
Environment=RELAY_DATAPATH=v2

# --- Auth: OFF ---
# The desktop app's custom-relay path does NOT fetch or send relay tickets,
# so this relay has to be in `off` mode. The relay refuses to start in `off`
# mode unless RELAY_ALLOW_INSECURE=1 is also set — that's a safety interlock
# to prevent accidental open-relay deployments.
Environment=RELAY_AUTH_MODE=off
Environment=RELAY_ALLOW_INSECURE=1

# --- TCP forwarding ---
# Enables tunneling of TCP (e.g. Roblox login/HTTPS) alongside UDP gameplay.
# Required if you want the app's `enable_api_tunneling` feature to work.
Environment=RELAY_TCP_ENABLED=true

# --- Telemetry (optional but recommended) ---
# Binds 127.0.0.1:51822 only. Generate a long random token:
#   openssl rand -hex 32
Environment=RELAY_STATS_PORT=51822
Environment=RELAY_STATS_TOKEN=REPLACE_WITH_LONG_RANDOM_TOKEN

# --- Optional kernel-TUN UDP offload ---
# Off by default. Only turn on for a short canary while measuring
# latency/jitter — it's experimental and not recommended for steady-state use.
# Environment=RELAY_TUN_UDP=false

[Install]
WantedBy=multi-user.target
EOF

# Replace the token placeholder
sudo sed -i "s/REPLACE_WITH_LONG_RANDOM_TOKEN/$(openssl rand -hex 32)/" \
  /etc/systemd/system/swifttunnel-relay.service

sudo systemctl daemon-reload
sudo systemctl enable --now swifttunnel-relay
sudo systemctl status swifttunnel-relay --no-pager
```

Watch the boot logs:

```bash
sudo journalctl -u swifttunnel-relay -f
```

You should see something like:

```
SwiftTunnel relay starting (v1.5.0, datapath=v2, auth=off)
Listening for client UDP on 0.0.0.0:51821
Localhost telemetry on 127.0.0.1:51822 (token auth)
```

If you see:

```
RELAY_AUTH_MODE=off requires RELAY_ALLOW_INSECURE=1; refusing to start open relay
```

…you forgot `Environment=RELAY_ALLOW_INSECURE=1` in the unit file. Add it,
`daemon-reload`, restart.

## Step 6 — Verify the relay

### From the server

```bash
# Process is alive
sudo systemctl is-active swifttunnel-relay        # → active

# Listening
sudo ss -ulnp | grep 51821                        # → 0.0.0.0:51821

# Telemetry returns config
TOKEN=$(grep RELAY_STATS_TOKEN= /etc/systemd/system/swifttunnel-relay.service | cut -d= -f3)
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:51822/v1/config | jq
# expected: { "auth_mode": "off", "datapath": "v2", "version": "1.5.0", ... }

curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:51822/v1/stats | jq
# expected: zeroed counters until clients connect
```

### From your local machine

The repo ships a control-plane probe that uses the relay's `0xA3`/`0xA4`
ping/pong frames:

```bash
cd swifttunnel-relay
python3 probe-relay.py --icmp <server-ip>
python3 probe-relay.py --icmp --repeat 10 <server-ip>
```

Expected output: ICMP and pong RTTs that are close to each other (the relay
adds <1 ms of pong overhead).

For a real datapath test, run a UDP echo server somewhere reachable and
benchmark through the relay:

```bash
# On the destination box
python3 relay-speedtest.py server --bind 0.0.0.0 --port 9000

# From your local machine
python3 relay-speedtest.py client \
  --relay-host <server-ip> \
  --target-host <destination-ip> \
  --target-port 9000 \
  --payload-bytes 1200 \
  --upload-packets 4000 \
  --download-packets 4000 \
  --upload-gap-us 50 \
  --download-gap-us 50 \
  --timeout-ms 5000
```

The script reports upload/download throughput and loss for the actual relay
datapath, not just the ping/pong frames.

## Step 7 — Point the SwiftTunnel app at your relay

The desktop app has a "Custom relay server" setting that overrides the relay
endpoint. When set, the app skips the hosted ticket-auth bootstrap entirely
and connects directly to your server.

### Option A — settings.json (always works)

This is the reliable path, especially once swifttunnel.net is gone.

1. Quit SwiftTunnel completely (right-click tray icon → Quit).
2. Open `%APPDATA%\SwiftTunnel\settings.json` in a text editor.
3. Find (or add) the `custom_relay_server` field. Format is `host:port`:

   ```json
   {
     "custom_relay_server": "relay.example.com:51821",
     "auto_routing_enabled": false,
     ...
   }
   ```

   IPv4 addresses work too: `"203.0.113.10:51821"`.

4. Save the file and start SwiftTunnel.
5. Connect. The log at `%APPDATA%\SwiftTunnel\logs\swifttunnel.log` should
   show:

   ```
   V3: Using CUSTOM relay server: relay.example.com:51821
   V3: Resolved custom relay to <ip>:51821
   V3: Custom relay enabled, skipping authenticated relay ticket bootstrap
   V3: Creating UDP relay to <ip>:51821
   V3 split tunnel setup succeeded
   V3 connected successfully (no encryption, lowest latency)
   ```

### Option B — UI (only if your account has `is_tester=true`)

If you still have a working SwiftTunnel account flagged as a tester, the UI
exposes the same setting:

1. Open SwiftTunnel → Settings.
2. Scroll to the **Experimental** section (only visible to testers).
3. Set "Custom relay server" to `relay.example.com:51821`.
4. Disconnect/reconnect.

When swifttunnel.net is gone, profile lookup fails and `isTester` falls back
to `false`, so the UI section disappears. Edit `settings.json` directly
(Option A) — the backend reads the field regardless of UI state.

### Behavior changes when `custom_relay_server` is set

- **Auto-routing is force-disabled** for that session. The app logs
  `Auto-routing disabled for this session because custom_relay_server is set`.
  The IPinfo-backed game-server region resolver is not invoked.
- **Forced server pins are ignored** — the relay address comes from your
  setting, not the per-region pin map.
- **Relay ticket fetch is skipped entirely.** The relay must be in
  `RELAY_AUTH_MODE=off`. If you accidentally launch the relay with
  `optional`/`required` and no key, the app will time out the data path
  silently because the relay drops unauth'd frames.
- The displayed connection state shows `relay_auth_mode: "custom_legacy"`.

### Behavior that is _not_ overridden

- The app still fetches the **server list** from
  `https://swifttunnel.net/api/vpn/servers` before connecting and refuses to
  connect if the configured `selected_region` isn't in the list. See
  [Hosted-service dependencies](#hosted-service-dependencies) for how to
  handle this once the hosted service is gone.
- The app still calls `/api/user/profile` on startup for ban/tester status.
  When that fails, the app continues but you lose the tester UI gate.

## Multi-region setup

If you want the same multi-region experience the hosted service offered:

1. Spin up a relay in each region you care about. The binary, systemd unit,
   and `setup-tun.sh` are identical on every host — only the public IP
   changes.
2. The app's `custom_relay_server` setting is a single host:port string.
   Switching regions means editing `settings.json` and reconnecting. A small
   PowerShell helper makes this painless:

   ```powershell
   # ~\swap-relay.ps1
   param([Parameter(Mandatory)][string]$Relay)
   $path = Join-Path $env:APPDATA 'SwiftTunnel\settings.json'
   $json = Get-Content $path -Raw | ConvertFrom-Json
   $json.custom_relay_server = $Relay
   $json | ConvertTo-Json -Depth 32 | Set-Content $path -Encoding UTF8
   Write-Host "custom_relay_server -> $Relay"
   ```

   Usage: `.\swap-relay.ps1 relay-us-east.example.com:51821`

3. If you fork the app, restoring the multi-region picker is a small change
   in `commands/vpn.rs` — make `custom_relay_server` a map keyed by region
   instead of a single string, and pick the entry matching `selected_region`.

## Performance tuning

The defaults are tuned for low-jitter gaming on a 1 vCPU host. For higher
concurrency or large per-session bursts, bump the v2 datapath knobs.

```ini
# In /etc/systemd/system/swifttunnel-relay.service
Environment=RELAY_V2_POOL_SLOTS=32768          # buffer pool, default 8192
Environment=RELAY_V2_SHARD_QUEUE=16384         # per-shard inbox, default 4096
Environment=RELAY_V2_TX_QUEUE=32768            # tx queue, default 8192
Environment=RELAY_SOCKET_RCVBUF_BYTES=16777216 # default 4 MiB
Environment=RELAY_SOCKET_SNDBUF_BYTES=16777216 # default 4 MiB
Environment=RELAY_FLOW_RCVBUF_BYTES=8388608    # per-flow rcv, default 2 MiB
Environment=RELAY_FLOW_SNDBUF_BYTES=8388608    # per-flow snd, default 2 MiB
# RELAY_SHARDS defaults to your physical CPU count; override if needed.
```

Sysctl tuning (the setup script already does the basics):

```bash
sudo sysctl -w net.core.rmem_max=33554432
sudo sysctl -w net.core.wmem_max=33554432
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
sudo sysctl -w net.netfilter.nf_conntrack_udp_timeout=30
sudo sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=60
```

Persist with `/etc/sysctl.d/99-swifttunnel-tuning.conf`.

### What to watch

Pull `/v1/stats` periodically:

- `pool_exhausted` — should stay flat. Growing means raise
  `RELAY_V2_POOL_SLOTS`.
- `dropped_in` / `dropped_out` — should stay near zero. Persistent drops mean
  undersized buffers or sysctl `rmem_max` still at the default 212 KiB.
- `drops.*` — per-reason counters (auth, parse, queue, pool, TUN, flow, …).
  `tcp_disabled` only matters if you set `RELAY_TCP_ENABLED=false`.
  `forbidden_dst` counts blocked attempts to forward to RFC1918/CGNAT/etc.
- `inbound_bps` / `outbound_bps` are **directional from the relay's
  perspective**: `inbound = Client → Relay`, `outbound = Relay → Client`.

## Hardening

Running an open relay means anyone who knows the host:port can forward UDP
through it. To reduce exposure:

- **Don't publish the host publicly.** No DNS A record on a known name, no
  posts on forums. Treat the IP like a SSH bastion.
- **Pick a non-default port.** `RELAY_PORT=49152` is just as functional and
  defeats casual scanners.
- **Source-IP allowlist at the firewall** if you have a static home IP:

  ```bash
  sudo ufw delete allow 51821/udp
  sudo ufw allow from <your-home-ip> to any port 51821 proto udp
  ```

  For dynamic home IPs, a tiny cron job that reads your DDNS hostname and
  rewrites the ufw rule works fine.

- **Keep `RELAY_TCP_ENABLED=false`** if you don't need API tunneling. TCP
  forwarding through the TUN device opens a bigger attack surface than
  UDP-only forwarding.
- **Leave the `setup-tun.sh` forbidden-destination drops in place.** They are
  the only thing preventing the relay from being used as a pivot into
  RFC1918/link-local/CGNAT.
- **Rate limiting is already on by default** — the datapath enforces
  per-source-IP buckets on new sessions/new flows/total packets before
  allocating state. Drops surface under `/v1/stats` `drops.rate_limit`.
- **Telemetry is localhost-only.** Don't expose `RELAY_STATS_PORT` to the
  public internet under any circumstances. SSH-tunnel into it if you need
  remote access:

  ```bash
  ssh -L 51822:127.0.0.1:51822 root@SERVER
  # then on your local machine:
  curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:51822/v1/stats
  ```

## Troubleshooting

### Relay refuses to start

```
RELAY_AUTH_MODE=off requires RELAY_ALLOW_INSECURE=1; refusing to start open relay
```
→ Add `Environment=RELAY_ALLOW_INSECURE=1` to the unit. This is an
intentional interlock, not a bug.

```
RELAY_AUTH_PUBLIC_KEY_B64 is required when RELAY_AUTH_MODE != off
```
→ You set `RELAY_AUTH_MODE=optional` or `required` without a key. Either set
the key (for the hosted-style deployment) or switch the mode to `off`.

### `swifttun0` device missing after restart

The relay re-applies the address and link-up on every start, so a plain
`systemctl restart swifttunnel-relay` should be enough. If `ip link show
swifttun0` errors out, re-run `setup-tun.sh`.

### App connects but no traffic flows

1. Confirm the app log shows
   `V3: Custom relay enabled, skipping authenticated relay ticket bootstrap`.
   If it doesn't, the custom-relay path isn't being taken — verify
   `custom_relay_server` is set in `settings.json` and the app was restarted
   after the edit.
2. Check UDP reachability: `nc -uvz <server> 51821` from your local machine
   (Linux/macOS) or `Test-NetConnection -ComputerName <server> -Port 51821`
   from PowerShell (TCP-only on Windows, but errors fast if the host is
   unreachable at all).
3. On the relay, watch `/v1/stats` — `active_sessions` should increment when
   the app connects. If not, your firewall is blocking inbound UDP.

### App reports "Selected region '…' is unavailable in server list"

The app's cached server list is empty or stale and the hosted
`/api/vpn/servers` endpoint is unreachable. See
[Hosted-service dependencies](#hosted-service-dependencies). Workaround:
serve a static replacement JSON at the same URL via a DNS override.

### High loss / jitter

- `/v1/stats` `pool_exhausted` growing → raise `RELAY_V2_POOL_SLOTS`.
- `/v1/stats` `dropped_in` / `dropped_out` growing → raise socket buffers and
  confirm `sysctl net.core.rmem_max` is at least 16 MiB.
- Server CPU saturated → bump to a larger instance, or enable
  `RELAY_TUN_UDP=true` as a (still experimental) offload. Measure carefully.

### App's UI doesn't show the Experimental section

That UI is gated behind `isTester` (from `/api/user/profile`). When the
hosted profile endpoint is down or your account isn't flagged, the section
disappears. Edit `settings.json` directly — the backend reads
`custom_relay_server` regardless of UI state.

## Hosted-service dependencies

The relay self-hosts cleanly. The desktop app, in its shipped form, still
expects the hosted swifttunnel.net surface to be alive for a few things. None
of these are fatal individually, but knowing about them lets you plan.

| Endpoint | What the app uses it for | Behavior when down |
|---|---|---|
| `GET /api/vpn/servers` | Cached server list (TTL 1h, hard max 24h stale) | After cache expires, connect fails with "Selected region '…' is unavailable in server list" |
| `POST /api/auth/desktop/exchange` | OAuth code → access token exchange after login | Login flow breaks. Existing refresh tokens may still work. |
| `GET /api/user/profile` | Tester / ban / username refresh on startup | Tester UI section hides; ban detection no-ops. App still runs. |
| `POST /api/vpn/relay-ticket` | Hosted ticket fetch (auth-enabled relay) | Not used on custom-relay path — irrelevant here. |
| `POST /api/vpn/game-server-region` | Auto-routing's IPinfo-backed resolver | Not used on custom-relay path — auto-routing is force-disabled. |
| `https://auth.swifttunnel.net` | Supabase auth (login refresh) | Login breaks. |

The **only** one that breaks the custom-relay flow at connect time is
`/api/vpn/servers`. There are three ways to handle it:

1. **DNS override + static JSON (recommended).** Run a tiny nginx/Caddy/Worker
   serving the relay's expected JSON shape, then point `swifttunnel.net` at
   that host. Either edit `C:\Windows\System32\drivers\etc\hosts` per machine,
   or run your own DNS resolver pointing the name at your stub.

   Minimum viable response shape — adjust to your relay's region and IP:

   ```json
   {
     "servers": [
       {
         "region": "self-hosted",
         "name": "My Relay",
         "country_code": "us",
         "ip": "203.0.113.10",
         "port": 51820,
         "phantun_available": false,
         "relay_available": true,
         "relay_port": 51821
       }
     ],
     "version": "1.0.0"
   }
   ```

   The desktop app caches this list at `%APPDATA%\SwiftTunnel\servers.json`.
   Set `selected_region` and `last_connected_region` in `settings.json` to
   `"self-hosted"` so it picks your entry.

2. **Fork the app** and short-circuit `vpn/servers.rs` to return a hardcoded
   list when `custom_relay_server` is set. ~20 lines of Rust; the simplest
   structural fix.

3. **Build the app from source** with `API_BASE_URL` pointed at your own
   replacement web service (a small Next.js / Worker / FastAPI app that
   serves the four endpoints above with minimal stubs). Most invasive,
   cleanest long-term.

For an unattended self-host with no SwiftTunnel infrastructure left, option
2 (fork + patch) is the least fragile.

## Writing your own client

The shipped desktop app is Windows-only and depends on NDIS-level packet
interception (WinpkFilter). If you want a client on Linux/macOS, you'll have
to write one. The wire protocol is small.

Against a `RELAY_AUTH_MODE=off` relay, the minimal flow is:

1. Generate a random 8-byte session ID.
2. Intercept the UDP packets you want to tunnel (raw socket, TUN, NFQUEUE,
   eBPF, etc.).
3. Wrap each packet as `[session_id:8][full IPv4 packet]` and send to the
   relay's `RELAY_PORT/UDP`.
4. Receive `[session_id:8][full IPv4 packet]` from the relay and inject it
   back into the local network stack.
5. Send a bare `[session_id:8]` keepalive (8 bytes, no payload) every
   15–20 s to keep NAT bindings alive.

In `off` mode you do not need to send the `0xA1` auth hello — the relay will
respond with `0xA2` status `6` (`auth_disabled`) if you try, which you can
safely ignore. See the main [README's protocol section](README.md#protocol)
for the full frame set and the optional `0xA3`/`0xA4` ping/pong control
frames.

## Quick reference card

```bash
# Build + deploy
cargo build --release
scp target/release/swifttunnel-relay setup-tun.sh root@SERVER:/usr/local/bin/

# Setup
ssh root@SERVER 'sudo /usr/local/bin/setup-tun.sh'
ssh root@SERVER 'sudo systemctl enable --now swifttunnel-relay'

# Verify
ssh root@SERVER 'curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:51822/v1/config | jq .auth_mode'
python3 probe-relay.py --icmp SERVER

# App config — %APPDATA%\SwiftTunnel\settings.json
#   "custom_relay_server": "SERVER:51821"
```

That's it. Open an issue at
[github.com/Swift-tunnel/swifttunnel-relay](https://github.com/Swift-tunnel/swifttunnel-relay)
if anything in this guide is wrong or unclear.
