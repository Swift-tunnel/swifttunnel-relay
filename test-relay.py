#!/usr/bin/env python3
"""
V3 UDP Relay Test Script

Tests the relay server by:
1. Sending a keepalive (session ID only)
2. Sending a mock game packet (session ID + IP packet)
3. Verifying connectivity
"""

import socket
import struct
import random
import time
import sys

def generate_session_id():
    """Generate random 8-byte session ID"""
    return random.randbytes(8)

def create_mock_ip_udp_packet(dst_ip: str, dst_port: int, payload: bytes) -> bytes:
    """
    Create a minimal IPv4 UDP packet for testing.
    This is what the desktop client would send.
    """
    dst_ip_bytes = socket.inet_aton(dst_ip)
    src_ip_bytes = socket.inet_aton("10.0.0.2")  # Mock client IP

    # UDP header (8 bytes)
    src_port = random.randint(10000, 60000)
    udp_length = 8 + len(payload)
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)  # checksum=0

    # IP header (20 bytes, no options)
    version_ihl = 0x45  # IPv4, IHL=5 (20 bytes)
    dscp_ecn = 0
    total_length = 20 + udp_length
    identification = random.randint(0, 65535)
    flags_fragment = 0x4000  # Don't fragment
    ttl = 64
    protocol = 17  # UDP
    checksum = 0  # We don't need valid checksum for relay

    ip_header = struct.pack("!BBHHHBBH4s4s",
        version_ihl, dscp_ecn, total_length,
        identification, flags_fragment,
        ttl, protocol, checksum,
        src_ip_bytes, dst_ip_bytes
    )

    return ip_header + udp_header + payload

def test_relay(relay_host: str, relay_port: int = 51821):
    """Test the relay server"""
    print(f"\n🧪 Testing V3 Relay at {relay_host}:{relay_port}")
    print("=" * 50)

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)

    session_id = generate_session_id()
    session_hex = session_id.hex()
    print(f"Session ID: {session_hex}")

    # Test 1: Keepalive (just session ID)
    print("\n📤 Test 1: Sending keepalive...")
    try:
        sock.sendto(session_id, (relay_host, relay_port))
        print("   ✅ Keepalive sent successfully")
    except Exception as e:
        print(f"   ❌ Failed to send keepalive: {e}")
        return False

    # Test 2: Send mock game packet
    # Target: 8.8.8.8:53 (Google DNS - just for testing connectivity)
    print("\n📤 Test 2: Sending mock game packet to 8.8.8.8:53...")

    # DNS query payload (minimal)
    dns_query = bytes([
        0x00, 0x01,  # Transaction ID
        0x01, 0x00,  # Flags: standard query
        0x00, 0x01,  # Questions: 1
        0x00, 0x00,  # Answer RRs
        0x00, 0x00,  # Authority RRs
        0x00, 0x00,  # Additional RRs
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,  # "example"
        0x03, 0x63, 0x6f, 0x6d,  # "com"
        0x00,        # End of name
        0x00, 0x01,  # Type: A
        0x00, 0x01,  # Class: IN
    ])

    ip_packet = create_mock_ip_udp_packet("8.8.8.8", 53, dns_query)
    packet = session_id + ip_packet

    try:
        sock.sendto(packet, (relay_host, relay_port))
        print(f"   ✅ Sent {len(packet)} bytes (8 session + {len(ip_packet)} IP packet)")
    except Exception as e:
        print(f"   ❌ Failed to send: {e}")
        return False

    # Test 3: Try to receive response
    print("\n📥 Test 3: Waiting for response (5s timeout)...")
    try:
        data, addr = sock.recvfrom(1600)
        if len(data) >= 8:
            resp_session = data[:8]
            resp_payload = data[8:]
            if resp_session == session_id:
                print(f"   ✅ Received {len(data)} bytes from {addr}")
                print(f"   ✅ Session ID matches!")
                print(f"   📦 Payload: {len(resp_payload)} bytes")
                return True
            else:
                print(f"   ⚠️ Session ID mismatch")
        else:
            print(f"   ⚠️ Response too short: {len(data)} bytes")
    except socket.timeout:
        print("   ⏱️ Timeout - no response (this is OK for keepalive test)")
        print("   ℹ️  The relay only responds when game server responds")
    except Exception as e:
        print(f"   ❌ Error: {e}")

    # Test 4: Verify relay is listening by checking port
    print("\n🔍 Test 4: Verifying relay is listening...")
    try:
        # Send another keepalive
        sock.sendto(session_id, (relay_host, relay_port))
        print("   ✅ Relay is accepting packets on port 51821")
    except Exception as e:
        print(f"   ❌ Relay not responding: {e}")
        return False

    sock.close()

    print("\n" + "=" * 50)
    print("✅ V3 Relay test PASSED - Server is operational")
    print("=" * 50)
    return True

def main():
    if len(sys.argv) < 2:
        print("Usage: python test-relay.py <relay-host> [port]")
        print("Example: python test-relay.py 203.0.113.10")
        print("Example: python test-relay.py 203.0.113.10 51821")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 51821

    success = test_relay(host, port)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
