#!/usr/bin/env python3
"""
Relay control-plane latency probe.

This script does not tunnel gameplay traffic. It uses the relay's optional
ping/pong control frames:

  Client -> Relay: [session_id:8][0xA3][seq:4][client_ts_mono_ms:8]
  Relay  -> Client: [session_id:8][0xA4][seq:4][client_ts_mono_ms:8][server_rx_ts_mono_ms:8]

Use it to measure:
  - control-plane RTT
  - packet loss
  - jitter (stdev)
  - optional ICMP baseline to the same host

If the relay requires authentication for pings, pass a relay ticket with
--ticket or --ticket-file.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import socket
import statistics
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Iterable, Optional


SESSION_ID_LEN = 8

AUTH_HELLO_FRAME_TYPE = 0xA1
AUTH_ACK_FRAME_TYPE = 0xA2
PING_FRAME_TYPE = 0xA3
PONG_FRAME_TYPE = 0xA4

AUTH_ACK_OK = 0

AUTH_ACK_LABELS = {
    0: "ok",
    1: "bad_format",
    2: "bad_signature",
    3: "expired",
    4: "sid_mismatch",
    5: "server_mismatch",
    6: "auth_disabled",
}

DEFAULT_RELAY_PORT = 51821
DEFAULT_TIMEOUT_MS = 1500
DEFAULT_INTERVAL_MS = 100
DEFAULT_COUNT = 30
DEFAULT_REPEAT = 1


@dataclass
class ProbeConfig:
    hosts: list[str]
    relay_port: int
    count: int
    repeat: int
    interval_ms: int
    timeout_ms: int
    do_icmp: bool
    json_output: bool
    ticket: Optional[str]


def monotonic_ms() -> int:
    return time.monotonic_ns() // 1_000_000


def percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return float("nan")
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    pct = max(0.0, min(100.0, pct))
    idx = (len(sorted_values) - 1) * (pct / 100.0)
    low = math.floor(idx)
    high = math.ceil(idx)
    if low == high:
        return float(sorted_values[low])
    left = sorted_values[low] * (high - idx)
    right = sorted_values[high] * (idx - low)
    return float(left + right)


def summarize_samples(samples: Iterable[float]) -> dict:
    values = sorted(float(v) for v in samples)
    if not values:
        return {
            "min_ms": float("nan"),
            "avg_ms": float("nan"),
            "p50_ms": float("nan"),
            "p90_ms": float("nan"),
            "p99_ms": float("nan"),
            "max_ms": float("nan"),
            "jitter_stdev_ms": float("nan"),
        }

    return {
        "min_ms": values[0],
        "avg_ms": sum(values) / len(values),
        "p50_ms": percentile(values, 50.0),
        "p90_ms": percentile(values, 90.0),
        "p99_ms": percentile(values, 99.0),
        "max_ms": values[-1],
        "jitter_stdev_ms": statistics.pstdev(values) if len(values) > 1 else 0.0,
    }


def parse_ping_summary(stdout: str) -> Optional[dict]:
    for line in stdout.splitlines():
        line = line.strip()
        if ("round-trip" in line or line.startswith("rtt ")) and "=" in line and "/" in line:
            try:
                rhs = line.split("=", 1)[1].strip()
                values = rhs.split(" ", 1)[0]
                min_ms, avg_ms, max_ms, stddev_ms = [float(v) for v in values.split("/")]
                return {
                    "min_ms": min_ms,
                    "avg_ms": avg_ms,
                    "max_ms": max_ms,
                    "stddev_ms": stddev_ms,
                }
            except (IndexError, ValueError):
                return None
    return None


def try_icmp_ping(host: str, count: int) -> Optional[dict]:
    try:
        proc = subprocess.run(
            ["ping", "-c", str(count), "-n", host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=max(5, count * 2),
        )
    except (OSError, subprocess.SubprocessError):
        return None

    if proc.returncode != 0:
        return None
    return parse_ping_summary(proc.stdout)


def recv_matching_frame(
    sock: socket.socket,
    session_id: bytes,
    frame_type: int,
    timeout_ms: int,
) -> Optional[bytes]:
    deadline = time.monotonic() + (timeout_ms / 1000.0)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        try:
            data = sock.recv(2048)
        except socket.timeout:
            return None
        except OSError:
            return None

        if len(data) < SESSION_ID_LEN + 1:
            continue
        if data[:SESSION_ID_LEN] != session_id:
            continue
        if data[SESSION_ID_LEN] != frame_type:
            continue
        return data


def authenticate_if_requested(sock: socket.socket, session_id: bytes, ticket: Optional[str], timeout_ms: int) -> dict:
    if not ticket:
        return {"attempted": False, "ok": None, "status": None, "status_label": None}

    ticket_bytes = ticket.encode("utf-8")
    if len(ticket_bytes) > 0xFFFF:
        raise ValueError("relay ticket is too long")

    packet = (
        session_id
        + bytes([AUTH_HELLO_FRAME_TYPE])
        + struct.pack("!H", len(ticket_bytes))
        + ticket_bytes
    )
    sock.send(packet)
    response = recv_matching_frame(sock, session_id, AUTH_ACK_FRAME_TYPE, timeout_ms)
    if response is None or len(response) < SESSION_ID_LEN + 2:
        return {"attempted": True, "ok": False, "status": None, "status_label": "timeout"}

    status = response[SESSION_ID_LEN + 1]
    return {
        "attempted": True,
        "ok": status == AUTH_ACK_OK,
        "status": status,
        "status_label": AUTH_ACK_LABELS.get(status, f"unknown_{status}"),
    }


def run_single_probe(host: str, cfg: ProbeConfig) -> dict:
    session_id = os.urandom(SESSION_ID_LEN)
    samples: list[float] = []
    lost = 0
    consecutive_loss = 0
    max_consecutive_loss = 0

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((host, cfg.relay_port))
        auth = authenticate_if_requested(sock, session_id, cfg.ticket, cfg.timeout_ms)

        start = time.monotonic()
        next_send = start
        for seq in range(1, cfg.count + 1):
            now = time.monotonic()
            sleep_s = next_send - now
            if sleep_s > 0:
                time.sleep(sleep_s)

            client_ts_ms = monotonic_ms()
            packet = session_id + bytes([PING_FRAME_TYPE]) + struct.pack("!IQ", seq, client_ts_ms)
            sent_at = time.monotonic()
            sock.send(packet)

            response = recv_matching_frame(sock, session_id, PONG_FRAME_TYPE, cfg.timeout_ms)
            if response is None or len(response) < SESSION_ID_LEN + 21:
                lost += 1
                consecutive_loss += 1
                max_consecutive_loss = max(max_consecutive_loss, consecutive_loss)
            else:
                returned_seq = struct.unpack("!I", response[SESSION_ID_LEN + 1 : SESSION_ID_LEN + 5])[0]
                echoed_client_ts = struct.unpack(
                    "!Q", response[SESSION_ID_LEN + 5 : SESSION_ID_LEN + 13]
                )[0]
                if returned_seq != seq or echoed_client_ts != client_ts_ms:
                    lost += 1
                    consecutive_loss += 1
                    max_consecutive_loss = max(max_consecutive_loss, consecutive_loss)
                else:
                    samples.append((time.monotonic() - sent_at) * 1000.0)
                    consecutive_loss = 0

            next_send += cfg.interval_ms / 1000.0

    stats = summarize_samples(samples)
    recv = len(samples)
    sent = cfg.count
    loss_pct = (lost / sent * 100.0) if sent else 0.0
    ok_pct = (recv / sent * 100.0) if sent else 0.0

    return {
        "relay": f"{host}:{cfg.relay_port}",
        "sent": sent,
        "recv": recv,
        "lost": lost,
        "ok_pct": ok_pct,
        "loss_pct": loss_pct,
        "max_consecutive_loss": max_consecutive_loss,
        "auth": auth,
        "_samples": samples,
        **stats,
    }


def aggregate_runs(host: str, cfg: ProbeConfig, runs: list[dict], icmp: Optional[dict]) -> dict:
    all_samples = []
    for run in runs:
        if not math.isnan(run["min_ms"]):
            all_samples.extend(run["_samples"])

    aggregate_stats = summarize_samples(all_samples)
    sent = sum(run["sent"] for run in runs)
    recv = sum(run["recv"] for run in runs)
    lost = sum(run["lost"] for run in runs)
    loss_pct = (lost / sent * 100.0) if sent else 0.0
    ok_pct = (recv / sent * 100.0) if sent else 0.0
    auth = runs[0]["auth"] if runs else {"attempted": False, "ok": None, "status": None, "status_label": None}

    return {
        "relay": f"{host}:{cfg.relay_port}",
        "repeat": cfg.repeat,
        "count_per_run": cfg.count,
        "interval_ms": cfg.interval_ms,
        "timeout_ms": cfg.timeout_ms,
        "sent": sent,
        "recv": recv,
        "lost": lost,
        "ok_pct": ok_pct,
        "loss_pct": loss_pct,
        "max_consecutive_loss": max((run["max_consecutive_loss"] for run in runs), default=0),
        "auth": auth,
        "icmp": icmp,
        "runs": [
            {
                "index": idx + 1,
                "sent": run["sent"],
                "recv": run["recv"],
                "lost": run["lost"],
                "loss_pct": run["loss_pct"],
                "min_ms": run["min_ms"],
                "avg_ms": run["avg_ms"],
                "p50_ms": run["p50_ms"],
                "p90_ms": run["p90_ms"],
                "p99_ms": run["p99_ms"],
                "max_ms": run["max_ms"],
                "jitter_stdev_ms": run["jitter_stdev_ms"],
            }
            for idx, run in enumerate(runs)
        ],
        **aggregate_stats,
    }


def print_summary(summary: dict) -> None:
    print(f"relay={summary['relay']}")
    print(
        f"repeat={summary['repeat']} count_per_run={summary['count_per_run']} "
        f"interval={summary['interval_ms']}ms timeout={summary['timeout_ms']}ms"
    )

    auth = summary["auth"]
    if auth["attempted"]:
        print(
            f"auth: attempted=yes ok={'yes' if auth['ok'] else 'no'} "
            f"status={auth['status_label']}"
        )
    else:
        print("auth: attempted=no")

    if summary.get("icmp"):
        icmp = summary["icmp"]
        print(
            "icmp: "
            f"min/avg/max/stddev={icmp['min_ms']:.2f}/{icmp['avg_ms']:.2f}/"
            f"{icmp['max_ms']:.2f}/{icmp['stddev_ms']:.2f} ms"
        )

    print(
        f"summary: sent={summary['sent']} recv={summary['recv']} lost={summary['lost']} "
        f"ok={summary['ok_pct']:.2f}% loss={summary['loss_pct']:.2f}% "
        f"max_consecutive_loss={summary['max_consecutive_loss']}"
    )
    print(
        "rtt_ms: "
        f"min={summary['min_ms']:.2f} avg={summary['avg_ms']:.2f} "
        f"p50={summary['p50_ms']:.2f} p90={summary['p90_ms']:.2f} "
        f"p99={summary['p99_ms']:.2f} max={summary['max_ms']:.2f} "
        f"jitter_stdev={summary['jitter_stdev_ms']:.2f}"
    )

    if summary["repeat"] > 1:
        print("runs:")
        for run in summary["runs"]:
            print(
                f"  #{run['index']}: loss={run['loss_pct']:.2f}% "
                f"avg={run['avg_ms']:.2f}ms p50={run['p50_ms']:.2f}ms "
                f"p90={run['p90_ms']:.2f}ms p99={run['p99_ms']:.2f}ms"
            )


def load_ticket(args: argparse.Namespace) -> Optional[str]:
    if args.ticket and args.ticket_file:
        raise ValueError("use either --ticket or --ticket-file, not both")
    if args.ticket_file:
        with open(args.ticket_file, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    if args.ticket:
        return args.ticket.strip()
    return None


def parse_args(argv: list[str]) -> ProbeConfig:
    parser = argparse.ArgumentParser(
        description="Probe relay control-plane RTT/loss using A3/A4 ping frames."
    )
    parser.add_argument(
        "hosts",
        nargs="+",
        help="Relay hostnames or IPs. Pass multiple to compare them in one run.",
    )
    parser.add_argument("--relay-port", type=int, default=DEFAULT_RELAY_PORT)
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT, help="Pings per run.")
    parser.add_argument("--repeat", type=int, default=DEFAULT_REPEAT, help="Number of runs per host.")
    parser.add_argument("--interval-ms", type=int, default=DEFAULT_INTERVAL_MS)
    parser.add_argument("--timeout-ms", type=int, default=DEFAULT_TIMEOUT_MS)
    parser.add_argument("--icmp", action="store_true", help="Also run a local ICMP ping baseline.")
    parser.add_argument("--ticket", default=None, help="Relay ticket for auth-required relays.")
    parser.add_argument("--ticket-file", default=None, help="Read relay ticket from a file.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    args = parser.parse_args(argv)

    return ProbeConfig(
        hosts=args.hosts,
        relay_port=max(1, min(65535, args.relay_port)),
        count=max(1, args.count),
        repeat=max(1, args.repeat),
        interval_ms=max(1, args.interval_ms),
        timeout_ms=max(50, args.timeout_ms),
        do_icmp=bool(args.icmp),
        json_output=bool(args.json),
        ticket=load_ticket(args),
    )


def main(argv: list[str]) -> int:
    cfg = parse_args(argv)
    summaries = []

    for host in cfg.hosts:
        icmp = try_icmp_ping(host, min(10, cfg.count)) if cfg.do_icmp else None
        runs = []
        for _ in range(cfg.repeat):
            runs.append(run_single_probe(host, cfg))

        summary = aggregate_runs(host, cfg, runs, icmp)
        summaries.append(summary)

        if cfg.json_output:
            print(json.dumps(summary, sort_keys=True))
        else:
            print_summary(summary)
            print("")

    if len(summaries) > 1 and not cfg.json_output:
        print("comparison:")
        for summary in summaries:
            print(
                f"{summary['relay']}: loss={summary['loss_pct']:.2f}% "
                f"avg={summary['avg_ms']:.2f}ms p50={summary['p50_ms']:.2f}ms "
                f"p90={summary['p90_ms']:.2f}ms p99={summary['p99_ms']:.2f}ms"
            )

    if any(summary["recv"] == 0 for summary in summaries):
        if not cfg.json_output:
            print("")
            print("warning: at least one relay returned no pong frames.")
            if not cfg.ticket:
                print("warning: if that relay requires auth, rerun with --ticket or --ticket-file.")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
