# Claude Deployment Runbook (Relay)

This file is for a Claude Code agent performing **manual production deployments** of `swifttunnel-relay`.

Use this runbook for the authenticated relay rollout (ticket handshake + auth modes), including optional TUN-backed UDP/TCP forwarding.

## Scope

- Repo: `/Users/Evelyn/Swifttunnel/swifttunnel-relay`
- Service name on servers: `v3-relay`
- Binary path on servers: `/usr/local/bin/swifttunnel-relay`
- systemd unit path on servers: `/etc/systemd/system/v3-relay.service`

## Non-Negotiables

1. Roll out canary first, then fleet.
2. Relays fail closed: deploy with `RELAY_AUTH_MODE=required` unless an incident explicitly sets `RELAY_AUTH_MODE=off` together with `RELAY_ALLOW_INSECURE=1`.
3. Every server must have the correct `RELAY_SERVER_ID` for that host/region.
4. Validate each canary before touching more servers.
5. Keep rollback steps ready before each deployment wave.

## Required Inputs Before Starting

1. Target relay commit to deploy (should include auth fixes from PR #2).
2. `RELAY_AUTH_PUBLIC_KEY_B64` (Ed25519 public key used by web-signed tickets).
3. `RELAY_STATS_TOKEN` (used by localhost telemetry auth).
4. Server inventory with SSH access.
5. Host -> relay server ID mapping.

Notes:
- Source of truth for current server region IDs is `swifttunnel-web/lib/constants.ts` (`VPN_SERVERS` keys).
- Do not assume `deploy.sh` inventory comments are always current; verify against current infra inventory.

## Preflight (Local)

From `/Users/Evelyn/Swifttunnel/swifttunnel-relay`:

```bash
git status
git log --oneline -n 5
cargo test
python3 probe-relay.py --icmp 45.32.115.254
```

If tests fail, stop and fix before any deployment.

## Canary Rollout (Manual, One Server at a Time)

Prefer `deploy-single.sh` for controlled rollout:

```bash
# Password-auth server
./deploy-single.sh root@<server_ip>

# SSH-key server
./deploy-single.sh ubuntu@<server_ip> /absolute/path/to/key.pem
```

After binary+unit deployment, set auth/stats envs with a systemd drop-in on that server:

```bash
sudo mkdir -p /etc/systemd/system/v3-relay.service.d
sudo tee /etc/systemd/system/v3-relay.service.d/10-auth.conf >/dev/null <<'EOF'
[Service]
Environment=RELAY_STATS_PORT=51822
Environment=RELAY_STATS_TOKEN=__RELAY_STATS_TOKEN__
Environment=RELAY_AUTH_MODE=required
Environment=RELAY_AUTH_PUBLIC_KEY_B64=__RELAY_AUTH_PUBLIC_KEY_B64__
Environment=RELAY_SERVER_ID=__RELAY_SERVER_ID__
Environment=RELAY_TUN_UDP=false
EOF

sudo systemctl daemon-reload
sudo systemctl restart v3-relay
sudo systemctl is-active v3-relay
sudo systemctl status v3-relay --no-pager
```

Replace:
- `__RELAY_STATS_TOKEN__`
- `__RELAY_AUTH_PUBLIC_KEY_B64__`
- `__RELAY_SERVER_ID__`

If you are canarying the kernel-backed UDP path, also:

```bash
sudo /absolute/path/to/setup-tun.sh
sudo mkdir -p /etc/systemd/system/v3-relay.service.d
sudo tee /etc/systemd/system/v3-relay.service.d/20-tun-udp.conf >/dev/null <<'EOF'
[Service]
Environment=RELAY_TUN_UDP=true
EOF

sudo systemctl daemon-reload
sudo systemctl restart v3-relay
```

For production rollback or to force UDP back onto the direct relay path, pin a
high-precedence override instead of trusting earlier drop-ins to be removed:

```bash
sudo mkdir -p /etc/systemd/system/v3-relay.service.d
sudo tee /etc/systemd/system/v3-relay.service.d/90-disable-tun-udp.conf >/dev/null <<'EOF'
[Service]
Environment=RELAY_TUN_UDP=false
EOF

sudo systemctl daemon-reload
sudo systemctl restart v3-relay
```

`setup-tun.sh` installs the NAT/FORWARD prerequisites, forbidden-destination drops for private/link-local/loopback/multicast/CGNAT ranges, and persists the relay socket-buffer sysctls (`rmem_max`/`wmem_max` 16 MiB, defaults 8 MiB). The relay itself now re-applies `swifttun0` link-up state and `10.200.0.1/16` on every start, so a plain service restart should not leave the TUN device down/unaddressed anymore.

## Canary Verification Checklist

Run on the canary server:

```bash
sudo journalctl -u v3-relay -n 80 --no-pager
curl -sS -H "Authorization: Bearer __RELAY_STATS_TOKEN__" http://127.0.0.1:51822/v1/stats
curl -sS -H "Authorization: Bearer __RELAY_STATS_TOKEN__" http://127.0.0.1:51822/v1/connections
```

Run from your local machine against the canary:

```bash
python3 probe-relay.py --icmp <canary_ip>
python3 probe-relay.py --icmp --repeat 10 <canary_ip>
python3 relay-speedtest.py client --relay-host <canary_ip> --target-host 104.64.209.241 --target-port 9000 --payload-bytes 1200 --upload-packets 4000 --download-packets 4000 --upload-gap-us 50 --download-gap-us 50 --timeout-ms 5000
```

Expected:

1. `v3-relay` is active.
2. `/v1/stats` returns JSON quickly; it is intentionally card-safe and should keep responding even if detailed connection scans are degraded.
   Traffic rates are rolling `client -> relay` / `relay -> client` bytes-per-second, not lifetime averages.
3. `/v1/connections` returns JSON (may be empty when idle). It is served from a cached per-second snapshot so repeated admin polling does not walk the live session map on every request.
4. No crash loop or auth config errors in logs.
5. During a live app connection to this canary, connection rows should show `auth_state: "authenticated"` for updated app clients.
6. If `RELAY_TUN_UDP=true`, confirm `swifttun0` exists and has `10.200.0.1/16` assigned.
7. `probe-relay.py` returns pong RTT/loss numbers instead of timing out.
8. `ss -tanp | grep 51822` should show short-lived `TIME-WAIT` sockets, not growing `CLOSE-WAIT` piles on the relay stats port.
9. `relay-speedtest.py client ...` completes an upload/download run against the destination host and reports non-zero throughput instead of timing out.
   For larger sweeps, keep the pacing flags in the command above so the harness
   does not manufacture burst loss on its own.
10. `/v1/stats` `pool_exhausted` counter should stay flat during normal load. If
    it grows steadily on a canary, raise `RELAY_V2_POOL_SLOTS` before widening
    the rollout — a rising `pool_exhausted` rate means datapath v2 is dropping
    response packets because the buffer pool is under-sized for this host.

If any check fails, stop rollout and rollback that server.

## Fleet Rollout

After canaries are healthy:

1. Continue sequential `deploy-single.sh` across all remaining servers.
2. Apply/update the `10-auth.conf` drop-in on each server with the correct `RELAY_SERVER_ID`.
3. Restart and verify each server (`systemctl is-active`, quick `/v1/stats` check).

You may use `deploy.sh` only as a binary distribution helper, but still apply per-server auth env overrides manually because `RELAY_SERVER_ID` differs per host.

Operational note:
- Desktop API tunneling depends on relay TCP forwarding. Keep `RELAY_TCP_ENABLED=true` on production relays; if it is off, TCP packets are counted under the structured `tcp_disabled` drop reason instead of being silently consumed. Forbidden relay destinations are counted under `forbidden_dst`.
- Public relay datapaths apply per-source packet/new-session/new-flow buckets before state allocation and emit structured `rate_limit`/`capacity` drops. Auth tickets are single-use per `jti`, and authenticated sessions do not rebind to a different source IP from bare data/keepalive frames.
- Treat `RELAY_STATS_TOKEN=` with an empty value as broken config, not as "already set". The current `deploy.sh` and `manual-deploy-host.sh` helpers regenerate empty tokens and keep `RELAY_STATS_PORT=51822` plus `RELAY_FLOW_CHANNEL_CAPACITY=256` present in `/etc/swifttunnel/relay.env`.
- Preserve the lock order `sessions -> session_traffic` in relay code. If RX
  keeps a `session_traffic` `DashMap` guard alive while later mutating
  `sessions`, the cleanup/snapshot tasks can deadlock the datapath and the main
  UDP socket will stop draining.

## Rollback

Emergency rollback on a host (keep new binary, explicitly disable auth enforcement path):

1. Edit drop-in to set `RELAY_AUTH_MODE=off` and `RELAY_ALLOW_INSECURE=1`.
2. `sudo systemctl daemon-reload && sudo systemctl restart v3-relay`.

If service/binary regression exists:

1. Redeploy previous known-good commit with `deploy-single.sh`.
2. Keep `RELAY_AUTH_MODE=off` with `RELAY_ALLOW_INSECURE=1` only until the issue is resolved.

## Post-Deployment Migration Steps

1. Keep relay and web auth policy in `required` mode.
2. Release updated app and observe adoption (`auth_state` in relay connections).
3. If an incident requires insecure fallback, document the host, reason, and cleanup time before setting `RELAY_ALLOW_INSECURE=1`.
