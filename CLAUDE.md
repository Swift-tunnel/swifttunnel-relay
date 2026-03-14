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
2. First rollout mode is always `RELAY_AUTH_MODE=optional` (not `required`).
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
Environment=RELAY_AUTH_MODE=optional
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

## Canary Verification Checklist

Run on the canary server:

```bash
sudo journalctl -u v3-relay -n 80 --no-pager
curl -sS -H "Authorization: Bearer __RELAY_STATS_TOKEN__" http://127.0.0.1:51822/v1/stats
curl -sS -H "Authorization: Bearer __RELAY_STATS_TOKEN__" http://127.0.0.1:51822/v1/connections
```

Expected:

1. `v3-relay` is active.
2. `/v1/stats` returns JSON.
3. `/v1/connections` returns JSON (may be empty when idle).
4. No crash loop or auth config errors in logs.
5. During a live app connection to this canary, connection rows should show `auth_state: "authenticated"` for updated app clients.
6. If `RELAY_TUN_UDP=true`, confirm `swifttun0` exists and has `10.200.0.1/16` assigned.

If any check fails, stop rollout and rollback that server.

## Fleet Rollout

After canaries are healthy:

1. Continue sequential `deploy-single.sh` across all remaining servers.
2. Apply/update the `10-auth.conf` drop-in on each server with the correct `RELAY_SERVER_ID`.
3. Restart and verify each server (`systemctl is-active`, quick `/v1/stats` check).

You may use `deploy.sh` only as a binary distribution helper, but still apply per-server auth env overrides manually because `RELAY_SERVER_ID` differs per host.

## Rollback

Fast rollback on a host (keep new binary, disable auth enforcement path):

1. Edit drop-in to set `RELAY_AUTH_MODE=off`.
2. `sudo systemctl daemon-reload && sudo systemctl restart v3-relay`.

If service/binary regression exists:

1. Redeploy previous known-good commit with `deploy-single.sh`.
2. Keep `RELAY_AUTH_MODE=off` until issue is resolved.

## Post-Deployment Migration Steps

1. Keep relay in `optional` mode during migration window.
2. Release updated app and observe adoption (`auth_state` in relay connections).
3. After adoption is stable, coordinate:
   - web `RELAY_AUTH_MODE=required`
   - relay `RELAY_AUTH_MODE=required`

Do not switch to `required` until app adoption and canary/fleet telemetry are healthy.
