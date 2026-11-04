#!/usr/bin/env python3
"""Local-only checks for the relay-speedtest.py server. Run: python3 THIS_FILE.

The server answers whoever a datagram claims to come from, so it must not send
a large reply to an address that has not shown it can receive.
"""
import importlib.util
import os
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("speedtest", os.path.join(ROOT, "relay-speedtest.py"))
st = importlib.util.module_from_spec(spec)
sys.modules["speedtest"] = st
spec.loader.exec_module(st)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def drain(sock: socket.socket, quiet_s: float = 0.3) -> list[bytes]:
    got = []
    sock.settimeout(quiet_s)
    while True:
        try:
            got.append(sock.recv(65535))
        except socket.timeout:
            return got


def hello(sock: socket.socket, addr, padded: bool = True) -> tuple[int, bytes]:
    nonce = 1234
    body = st.struct.pack("!Q", nonce) + (bytes(st.HELLO_PADDING) if padded else b"")
    request = st.build_message(st.MSG_HELLO_REQ, body)
    sock.sendto(request, addr)
    reply = drain(sock)[0]
    assert len(reply) <= len(request), "HELLO reply larger than the request"
    parsed = st.parse_hello_resp(st.parse_message(reply)[1])
    assert parsed is not None and parsed[0] == nonce
    return parsed


def main() -> int:
    port = free_port()
    server = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "relay-speedtest.py"), "server",
         "--bind", "127.0.0.1", "--port", str(port), "--max-download-packets", "10"],
        stdout=subprocess.DEVNULL,
    )
    addr = ("127.0.0.1", port)
    try:
        time.sleep(0.5)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("127.0.0.1", 0))

        # An old-style request with no cookie, as a spoofer would send.
        client.sendto(st.build_download_request(1, 1000, 1200, 0), addr)
        assert drain(client) == [], "download sent without proof of address"

        # A legacy unpadded HELLO still works but earns no cookie.
        assert hello(client, addr, padded=False)[1] == b""

        _, cookie = hello(client, addr)
        assert len(cookie) == st.COOKIE_LEN

        # Somebody else's cookie does not work from another address.
        other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        other.bind(("127.0.0.1", 0))
        other.sendto(st.build_download_request(2, 5, 200, 0, cookie), addr)
        assert drain(other) == [], "cookie accepted from a different address"

        # With its own cookie: oversized requests are clamped.
        client.sendto(st.build_download_request(3, 1_000_000, 60000, 0, cookie), addr)
        got = drain(client)
        data = [m for m in got if st.parse_message(m)[0] == st.MSG_DOWNLOAD_DATA]
        assert len(data) == 10, f"expected 10 clamped packets, got {len(data)}"
        assert max(len(m) for m in data) <= st.MAX_PAYLOAD_BYTES
        assert any(st.parse_message(m)[0] == st.MSG_DOWNLOAD_RESULT for m in got)
    finally:
        server.kill()
        server.wait()
    print("relay-speedtest server tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
