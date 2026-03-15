#!/usr/bin/env python3
"""
UDP speedtest over the SwiftTunnel relay datapath.

Server mode runs a public UDP listener on the target host.
Client mode sends real `[session_id][IPv4 packet]` frames to a relay and measures
payload throughput for the path:

  local client -> relay -> target server
  target server -> relay -> local client

This validates the actual relay forwarding path, unlike `probe-relay.py`, which
only measures relay control-plane ping/pong frames.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Optional


SESSION_ID_LEN = 8

AUTH_HELLO_FRAME_TYPE = 0xA1
AUTH_ACK_FRAME_TYPE = 0xA2

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

MAGIC = b"SWST"
PROTO_VERSION = 1

MSG_HELLO_REQ = 0x01
MSG_HELLO_RESP = 0x02
MSG_UPLOAD_PREP = 0x10
MSG_UPLOAD_READY = 0x11
MSG_UPLOAD_DATA = 0x12
MSG_UPLOAD_FINISH = 0x13
MSG_UPLOAD_RESULT = 0x14
MSG_DOWNLOAD_REQUEST = 0x20
MSG_DOWNLOAD_DATA = 0x21
MSG_DOWNLOAD_RESULT = 0x22

DEFAULT_RELAY_PORT = 51821
DEFAULT_SERVER_PORT = 9000
DEFAULT_TIMEOUT_MS = 2000
DEFAULT_PAYLOAD_BYTES = 1200
DEFAULT_UPLOAD_PACKETS = 4000
DEFAULT_DOWNLOAD_PACKETS = 4000
DEFAULT_UPLOAD_GAP_US = 0
DEFAULT_DOWNLOAD_GAP_US = 0
DEFAULT_INNER_SRC_IP = "10.0.0.2"
SOCKET_BUFFER_BYTES = 4 * 1024 * 1024


@dataclass
class UploadState:
    expected_packets: int
    payload_bytes: int
    recv_packets: int = 0
    recv_bytes: int = 0
    first_recv_ns: int = 0
    last_recv_ns: int = 0


def monotonic_ns() -> int:
    return time.monotonic_ns()


def random_session_id() -> bytes:
    return os.urandom(SESSION_ID_LEN)


def checksum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"

    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_ipv4_udp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
    *,
    identification: Optional[int] = None,
) -> bytes:
    src_ip_bytes = socket.inet_aton(src_ip)
    dst_ip_bytes = socket.inet_aton(dst_ip)

    udp_len = 8 + len(payload)
    total_len = 20 + udp_len
    identification = identification if identification is not None else random.randint(0, 0xFFFF)

    ip_header = bytearray(
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            total_len,
            identification,
            0x4000,  # DF
            64,
            17,  # UDP
            0,
            src_ip_bytes,
            dst_ip_bytes,
        )
    )
    ip_checksum = checksum16(bytes(ip_header))
    ip_header[10:12] = struct.pack("!H", ip_checksum)

    # IPv4 allows UDP checksum 0 ("omitted"). That matches the relay's own
    # response packets and avoids checksum mismatches on the TUN path while the
    # relay is rewriting the inner source IP per session.
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)

    return bytes(ip_header) + udp_header + payload


def parse_ipv4_udp_packet(packet: bytes) -> Optional[dict]:
    if len(packet) < 28:
        return None
    if packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 0x0F) * 4
    if ihl < 20 or len(packet) < ihl + 8:
        return None
    total_len = struct.unpack("!H", packet[2:4])[0]
    if total_len < ihl + 8 or len(packet) < total_len:
        return None
    if packet[9] != 17:
        return None

    udp_start = ihl
    src_port, dst_port, udp_len, _ = struct.unpack("!HHHH", packet[udp_start : udp_start + 8])
    payload_start = udp_start + 8
    if udp_len < 8 or payload_start + udp_len - 8 > total_len:
        return None

    return {
        "src_ip": socket.inet_ntoa(packet[12:16]),
        "dst_ip": socket.inet_ntoa(packet[16:20]),
        "src_port": src_port,
        "dst_port": dst_port,
        "payload": packet[payload_start : payload_start + udp_len - 8],
    }


def build_message(msg_type: int, body: bytes = b"") -> bytes:
    return MAGIC + bytes([PROTO_VERSION, msg_type]) + body


def parse_message(payload: bytes) -> Optional[tuple[int, bytes]]:
    if len(payload) < 6:
        return None
    if payload[:4] != MAGIC:
        return None
    if payload[4] != PROTO_VERSION:
        return None
    return payload[5], payload[6:]


def build_hello_req(nonce: int) -> bytes:
    return build_message(MSG_HELLO_REQ, struct.pack("!Q", nonce))


def parse_hello_req(body: bytes) -> Optional[int]:
    if len(body) != 8:
        return None
    return struct.unpack("!Q", body)[0]


def build_hello_resp(nonce: int) -> bytes:
    return build_message(MSG_HELLO_RESP, struct.pack("!Q", nonce))


def build_upload_prep(test_id: int, packet_count: int, payload_bytes: int) -> bytes:
    return build_message(MSG_UPLOAD_PREP, struct.pack("!QIH", test_id, packet_count, payload_bytes))


def parse_upload_prep(body: bytes) -> Optional[tuple[int, int, int]]:
    if len(body) != 14:
        return None
    return struct.unpack("!QIH", body)


def build_upload_ready(test_id: int) -> bytes:
    return build_message(MSG_UPLOAD_READY, struct.pack("!Q", test_id))


def build_upload_data(test_id: int, seq: int, payload_bytes: int) -> bytes:
    header = build_message(MSG_UPLOAD_DATA, struct.pack("!QI", test_id, seq))
    if payload_bytes < len(header):
        raise ValueError(f"payload_bytes must be at least {len(header)}")
    return header + bytes(payload_bytes - len(header))


def parse_upload_data(body: bytes) -> Optional[tuple[int, int]]:
    if len(body) < 12:
        return None
    return struct.unpack("!QI", body[:12])


def build_upload_finish(test_id: int) -> bytes:
    return build_message(MSG_UPLOAD_FINISH, struct.pack("!Q", test_id))


def build_upload_result(
    test_id: int,
    recv_packets: int,
    recv_bytes: int,
    first_recv_ns: int,
    last_recv_ns: int,
) -> bytes:
    return build_message(
        MSG_UPLOAD_RESULT,
        struct.pack("!QIQQQ", test_id, recv_packets, recv_bytes, first_recv_ns, last_recv_ns),
    )


def parse_upload_result(body: bytes) -> Optional[tuple[int, int, int, int, int]]:
    if len(body) != 36:
        return None
    return struct.unpack("!QIQQQ", body[:36])


def build_download_request(test_id: int, packet_count: int, payload_bytes: int, gap_us: int) -> bytes:
    return build_message(
        MSG_DOWNLOAD_REQUEST,
        struct.pack("!QIHI", test_id, packet_count, payload_bytes, gap_us),
    )


def parse_download_request(body: bytes) -> Optional[tuple[int, int, int, int]]:
    if len(body) != 18:
        return None
    return struct.unpack("!QIHI", body)


def build_download_data(test_id: int, seq: int, payload_bytes: int) -> bytes:
    header = build_message(MSG_DOWNLOAD_DATA, struct.pack("!QI", test_id, seq))
    if payload_bytes < len(header):
        raise ValueError(f"payload_bytes must be at least {len(header)}")
    fill = bytes([seq & 0xFF]) * (payload_bytes - len(header))
    return header + fill


def parse_download_data(body: bytes) -> Optional[tuple[int, int]]:
    if len(body) < 12:
        return None
    return struct.unpack("!QI", body[:12])


def build_download_result(
    test_id: int,
    sent_packets: int,
    sent_bytes: int,
    first_send_ns: int,
    last_send_ns: int,
) -> bytes:
    return build_message(
        MSG_DOWNLOAD_RESULT,
        struct.pack("!QIQQQ", test_id, sent_packets, sent_bytes, first_send_ns, last_send_ns),
    )


def parse_download_result(body: bytes) -> Optional[tuple[int, int, int, int, int]]:
    if len(body) != 36:
        return None
    return struct.unpack("!QIQQQ", body[:36])


def make_relay_socket() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_BUFFER_BYTES)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUFFER_BYTES)
    return sock


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
            data = sock.recv(65535)
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


def authenticate_if_requested(
    sock: socket.socket,
    session_id: bytes,
    ticket: Optional[str],
    timeout_ms: int,
) -> dict:
    if not ticket:
        return {"attempted": False, "ok": None, "status": None, "status_label": None}

    ticket_bytes = ticket.encode("utf-8")
    if len(ticket_bytes) > 0xFFFF:
        raise ValueError("relay ticket is too long")

    packet = session_id + bytes([AUTH_HELLO_FRAME_TYPE]) + struct.pack("!H", len(ticket_bytes)) + ticket_bytes
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


class RelaySpeedtestClient:
    def __init__(
        self,
        relay_host: str,
        relay_port: int,
        target_host: str,
        target_port: int,
        inner_src_ip: str,
        inner_src_port: int,
        timeout_ms: int,
        ticket: Optional[str],
    ) -> None:
        self.relay_host = relay_host
        self.relay_port = relay_port
        self.target_host = target_host
        self.target_port = target_port
        self.target_ip = socket.gethostbyname(target_host)
        self.inner_src_ip = inner_src_ip
        self.inner_src_port = inner_src_port
        self.timeout_ms = timeout_ms
        self.session_id = random_session_id()
        self.sock = make_relay_socket()
        self.sock.connect((relay_host, relay_port))
        self.sock.send(self.session_id)
        self.auth = authenticate_if_requested(self.sock, self.session_id, ticket, timeout_ms)
        if self.auth["attempted"] and not self.auth["ok"]:
            raise RuntimeError(f"relay auth failed: {self.auth['status_label']}")

    def close(self) -> None:
        self.sock.close()

    def send_speedtest_payload(self, payload: bytes) -> None:
        packet = build_ipv4_udp_packet(
            self.inner_src_ip,
            self.target_ip,
            self.inner_src_port,
            self.target_port,
            payload,
        )
        self.sock.send(self.session_id + packet)

    def recv_speedtest_message(
        self,
        *,
        expected_types: set[int],
        expected_test_id: Optional[int],
        timeout_ms: int,
    ) -> Optional[tuple[int, bytes]]:
        deadline = time.monotonic() + (timeout_ms / 1000.0)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self.sock.settimeout(remaining)
            try:
                frame = self.sock.recv(65535)
            except socket.timeout:
                return None

            if len(frame) < SESSION_ID_LEN + 20:
                continue
            if frame[:SESSION_ID_LEN] != self.session_id:
                continue
            if frame[SESSION_ID_LEN] in (AUTH_ACK_FRAME_TYPE,):
                continue

            parsed_packet = parse_ipv4_udp_packet(frame[SESSION_ID_LEN:])
            if parsed_packet is None:
                continue
            if parsed_packet["src_port"] != self.target_port:
                continue
            if parsed_packet["dst_port"] != self.inner_src_port:
                continue

            parsed_message = parse_message(parsed_packet["payload"])
            if parsed_message is None:
                continue

            msg_type, body = parsed_message
            if msg_type not in expected_types:
                continue

            if expected_test_id is not None:
                test_id = struct.unpack("!Q", body[:8])[0] if len(body) >= 8 else None
                if test_id != expected_test_id:
                    continue

            return msg_type, body

    def handshake(self) -> None:
        nonce = random.getrandbits(64)
        for _ in range(3):
            self.send_speedtest_payload(build_hello_req(nonce))
            response = self.recv_speedtest_message(
                expected_types={MSG_HELLO_RESP},
                expected_test_id=None,
                timeout_ms=self.timeout_ms,
            )
            if response is None:
                continue
            _, body = response
            returned = parse_hello_req(body)
            if returned == nonce:
                return
        raise RuntimeError("speedtest server handshake timed out")

    def run_upload(self, packet_count: int, payload_bytes: int, gap_us: int) -> dict:
        test_id = random.getrandbits(64)

        ready = None
        for _ in range(3):
            self.send_speedtest_payload(build_upload_prep(test_id, packet_count, payload_bytes))
            ready = self.recv_speedtest_message(
                expected_types={MSG_UPLOAD_READY},
                expected_test_id=test_id,
                timeout_ms=self.timeout_ms,
            )
            if ready is not None:
                break
        if ready is None:
            raise RuntimeError("upload prep timed out")

        total_payload_bytes = 0
        send_started_ns = monotonic_ns()
        for seq in range(packet_count):
            payload = build_upload_data(test_id, seq, payload_bytes)
            total_payload_bytes += len(payload)
            self.send_speedtest_payload(payload)
            if gap_us:
                time.sleep(gap_us / 1_000_000.0)
        send_finished_ns = monotonic_ns()

        result = None
        for _ in range(4):
            self.send_speedtest_payload(build_upload_finish(test_id))
            result = self.recv_speedtest_message(
                expected_types={MSG_UPLOAD_RESULT},
                expected_test_id=test_id,
                timeout_ms=self.timeout_ms,
            )
            if result is not None:
                break
        if result is None:
            raise RuntimeError("upload result timed out")

        _, body = result
        result_test_id, recv_packets, recv_bytes, first_recv_ns, last_recv_ns = parse_upload_result(body) or (
            None,
            0,
            0,
            0,
            0,
        )
        if result_test_id != test_id:
            raise RuntimeError("upload result test id mismatch")

        server_duration_ns = max(last_recv_ns - first_recv_ns, 1) if recv_packets > 1 else 1
        client_duration_ns = max(send_finished_ns - send_started_ns, 1)

        return {
            "direction": "upload",
            "packet_count": packet_count,
            "payload_bytes": payload_bytes,
            "sent_packets": packet_count,
            "sent_bytes": total_payload_bytes,
            "recv_packets": recv_packets,
            "recv_bytes": recv_bytes,
            "loss_pct": (100.0 * (packet_count - recv_packets) / packet_count) if packet_count else 0.0,
            "client_mbps": (total_payload_bytes * 8.0) / (client_duration_ns / 1_000_000_000.0) / 1_000_000.0,
            "server_mbps": (recv_bytes * 8.0) / (server_duration_ns / 1_000_000_000.0) / 1_000_000.0,
            "client_duration_ms": client_duration_ns / 1_000_000.0,
            "server_duration_ms": server_duration_ns / 1_000_000.0,
        }

    def run_download(self, packet_count: int, payload_bytes: int, gap_us: int) -> dict:
        test_id = random.getrandbits(64)
        self.send_speedtest_payload(build_download_request(test_id, packet_count, payload_bytes, gap_us))

        recv_packets = 0
        recv_bytes = 0
        first_recv_ns = 0
        last_recv_ns = 0
        result: Optional[tuple[int, int, int, int, int]] = None
        trailing_deadline: Optional[float] = None

        while True:
            timeout_ms = self.timeout_ms if trailing_deadline is None else max(
                int((trailing_deadline - time.monotonic()) * 1000),
                1,
            )
            response = self.recv_speedtest_message(
                expected_types={MSG_DOWNLOAD_DATA, MSG_DOWNLOAD_RESULT},
                expected_test_id=test_id,
                timeout_ms=timeout_ms,
            )
            if response is None:
                if trailing_deadline is not None and time.monotonic() >= trailing_deadline:
                    break
                raise RuntimeError("download timed out")

            msg_type, body = response
            now_ns = monotonic_ns()
            if msg_type == MSG_DOWNLOAD_DATA:
                recv_packets += 1
                recv_bytes += len(build_message(MSG_DOWNLOAD_DATA, body))
                if first_recv_ns == 0:
                    first_recv_ns = now_ns
                last_recv_ns = now_ns
                continue

            parsed = parse_download_result(body)
            if parsed is None:
                continue
            result = parsed
            sent_packets = result[1]
            if recv_packets >= sent_packets:
                break
            trailing_deadline = time.monotonic() + 0.3

        if result is None:
            raise RuntimeError("download result missing")

        result_test_id, sent_packets, sent_bytes, first_send_ns, last_send_ns = result
        if result_test_id != test_id:
            raise RuntimeError("download result test id mismatch")

        client_duration_ns = max(last_recv_ns - first_recv_ns, 1) if recv_packets > 1 else 1
        server_duration_ns = max(last_send_ns - first_send_ns, 1) if sent_packets > 1 else 1

        return {
            "direction": "download",
            "packet_count": packet_count,
            "payload_bytes": payload_bytes,
            "sent_packets": sent_packets,
            "sent_bytes": sent_bytes,
            "recv_packets": recv_packets,
            "recv_bytes": recv_bytes,
            "loss_pct": (100.0 * (sent_packets - recv_packets) / sent_packets) if sent_packets else 0.0,
            "client_mbps": (recv_bytes * 8.0) / (client_duration_ns / 1_000_000_000.0) / 1_000_000.0,
            "server_mbps": (sent_bytes * 8.0) / (server_duration_ns / 1_000_000_000.0) / 1_000_000.0,
            "client_duration_ms": client_duration_ns / 1_000_000.0,
            "server_duration_ms": server_duration_ns / 1_000_000.0,
        }


def run_server(bind_host: str, port: int) -> int:
    states: dict[tuple[tuple[str, int], int], UploadState] = {}

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_BUFFER_BYTES)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUFFER_BYTES)
        sock.bind((bind_host, port))
        print(f"relay-speedtest server listening on {bind_host}:{port}", flush=True)

        while True:
            payload, addr = sock.recvfrom(65535)
            parsed = parse_message(payload)
            if parsed is None:
                continue

            msg_type, body = parsed

            if msg_type == MSG_HELLO_REQ:
                nonce = parse_hello_req(body)
                if nonce is not None:
                    sock.sendto(build_hello_resp(nonce), addr)
                continue

            if msg_type == MSG_UPLOAD_PREP:
                parsed_prep = parse_upload_prep(body)
                if parsed_prep is None:
                    continue
                test_id, packet_count, payload_bytes = parsed_prep
                states[(addr, test_id)] = UploadState(packet_count, payload_bytes)
                sock.sendto(build_upload_ready(test_id), addr)
                continue

            if msg_type == MSG_UPLOAD_DATA:
                parsed_data = parse_upload_data(body)
                if parsed_data is None:
                    continue
                test_id, _ = parsed_data
                state = states.get((addr, test_id))
                if state is None:
                    continue
                now_ns = monotonic_ns()
                state.recv_packets += 1
                state.recv_bytes += len(payload)
                if state.first_recv_ns == 0:
                    state.first_recv_ns = now_ns
                state.last_recv_ns = now_ns
                continue

            if msg_type == MSG_UPLOAD_FINISH:
                if len(body) != 8:
                    continue
                test_id = struct.unpack("!Q", body)[0]
                state = states.pop((addr, test_id), None)
                if state is None:
                    continue
                sock.sendto(
                    build_upload_result(
                        test_id,
                        state.recv_packets,
                        state.recv_bytes,
                        state.first_recv_ns,
                        state.last_recv_ns,
                    ),
                    addr,
                )
                continue

            if msg_type == MSG_DOWNLOAD_REQUEST:
                parsed_request = parse_download_request(body)
                if parsed_request is None:
                    continue
                test_id, packet_count, payload_bytes, gap_us = parsed_request

                first_send_ns = 0
                last_send_ns = 0
                sent_bytes = 0
                for seq in range(packet_count):
                    packet = build_download_data(test_id, seq, payload_bytes)
                    now_ns = monotonic_ns()
                    if first_send_ns == 0:
                        first_send_ns = now_ns
                    last_send_ns = now_ns
                    sock.sendto(packet, addr)
                    sent_bytes += len(packet)
                    if gap_us:
                        time.sleep(gap_us / 1_000_000.0)

                sock.sendto(
                    build_download_result(
                        test_id,
                        packet_count,
                        sent_bytes,
                        first_send_ns,
                        last_send_ns,
                    ),
                    addr,
                )


def format_result(result: dict) -> str:
    return (
        f"{result['direction']}: "
        f"sent={result['sent_packets']}pkts/{result['sent_bytes']}B "
        f"recv={result['recv_packets']}pkts/{result['recv_bytes']}B "
        f"loss={result['loss_pct']:.2f}% "
        f"client={result['client_mbps']:.2f} Mbps "
        f"server={result['server_mbps']:.2f} Mbps"
    )


def read_ticket(args: argparse.Namespace) -> Optional[str]:
    if args.ticket:
        return args.ticket.strip()
    if args.ticket_file:
        with open(args.ticket_file, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    return None


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="UDP speedtest over the SwiftTunnel relay datapath.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    server_parser = subparsers.add_parser("server", help="Run the public UDP speedtest server")
    server_parser.add_argument("--bind", default="0.0.0.0")
    server_parser.add_argument("--port", type=int, default=DEFAULT_SERVER_PORT)

    client_parser = subparsers.add_parser("client", help="Run the relay-path speedtest client")
    client_parser.add_argument("--relay-host", required=True)
    client_parser.add_argument("--relay-port", type=int, default=DEFAULT_RELAY_PORT)
    client_parser.add_argument("--target-host", required=True)
    client_parser.add_argument("--target-port", type=int, default=DEFAULT_SERVER_PORT)
    client_parser.add_argument("--inner-src-ip", default=DEFAULT_INNER_SRC_IP)
    client_parser.add_argument("--inner-src-port", type=int, default=random.randint(20000, 60000))
    client_parser.add_argument("--payload-bytes", type=int, default=DEFAULT_PAYLOAD_BYTES)
    client_parser.add_argument("--upload-packets", type=int, default=DEFAULT_UPLOAD_PACKETS)
    client_parser.add_argument("--download-packets", type=int, default=DEFAULT_DOWNLOAD_PACKETS)
    client_parser.add_argument("--upload-gap-us", type=int, default=DEFAULT_UPLOAD_GAP_US)
    client_parser.add_argument("--download-gap-us", type=int, default=DEFAULT_DOWNLOAD_GAP_US)
    client_parser.add_argument("--timeout-ms", type=int, default=DEFAULT_TIMEOUT_MS)
    client_parser.add_argument("--skip-upload", action="store_true")
    client_parser.add_argument("--skip-download", action="store_true")
    client_parser.add_argument("--ticket")
    client_parser.add_argument("--ticket-file")
    client_parser.add_argument("--json", action="store_true")

    return parser.parse_args(argv)


def run_client(args: argparse.Namespace) -> int:
    ticket = read_ticket(args)
    client = RelaySpeedtestClient(
        relay_host=args.relay_host,
        relay_port=args.relay_port,
        target_host=args.target_host,
        target_port=args.target_port,
        inner_src_ip=args.inner_src_ip,
        inner_src_port=args.inner_src_port,
        timeout_ms=args.timeout_ms,
        ticket=ticket,
    )

    try:
        client.handshake()

        results = {
            "relay_host": args.relay_host,
            "relay_port": args.relay_port,
            "target_host": args.target_host,
            "target_ip": client.target_ip,
            "target_port": args.target_port,
            "inner_src_ip": args.inner_src_ip,
            "inner_src_port": args.inner_src_port,
            "session_id": client.session_id.hex(),
            "auth": client.auth,
            "results": [],
        }

        if not args.skip_upload:
            results["results"].append(
                client.run_upload(args.upload_packets, args.payload_bytes, args.upload_gap_us)
            )
        if not args.skip_download:
            results["results"].append(
                client.run_download(args.download_packets, args.payload_bytes, args.download_gap_us)
            )

        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print(
                f"relay={args.relay_host}:{args.relay_port} "
                f"target={args.target_host}:{args.target_port} "
                f"session={results['session_id']}"
            )
            for result in results["results"]:
                print(format_result(result))
        return 0
    finally:
        client.close()


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.command == "server":
        return run_server(args.bind, args.port)
    return run_client(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
