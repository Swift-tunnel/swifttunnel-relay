//! Helpers for the local-only relay tests: start the real binary, sign a
//! ticket, build frames. No TUN, external relay, or production keys.
#![allow(dead_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub struct LocalRelay(Child);

impl Drop for LocalRelay {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// GET a local stats API path as JSON.
pub fn api(port: u16, path: &str) -> Option<serde_json::Value> {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().ok()?,
        Duration::from_millis(100),
    )
    .ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nAuthorization: Bearer local-regression\r\n\r\n")
                .as_bytes(),
        )
        .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    serde_json::from_str(response.split_once("\r\n\r\n")?.1).ok()
}

/// Start the relay on free local ports, requiring tickets signed by `key`.
/// Returns the relay, its UDP port and its stats API port.
pub fn start(
    datapath: &str,
    key: &Ed25519KeyPair,
    extra_env: &[(&str, &str)],
) -> (LocalRelay, u16, u16) {
    let port = UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let stats_port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut command = Command::new(env!("CARGO_BIN_EXE_swifttunnel-relay"));
    command
        .env("RELAY_PORT", port.to_string())
        .env("RELAY_STATS_PORT", stats_port.to_string())
        .env("RELAY_STATS_TOKEN", "local-regression")
        .env("RELAY_HEALTH_PORT", "0")
        .env("RELAY_AUTH_MODE", "required")
        .env(
            "RELAY_AUTH_PUBLIC_KEY_B64",
            URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
        )
        .env("RELAY_SERVER_ID", "local-test")
        .env("RELAY_DATAPATH", datapath)
        .env("RELAY_TCP_ENABLED", "false")
        .env("RELAY_TUN_UDP", "false")
        .env("RELAY_SHARDS", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (name, value) in extra_env {
        command.env(name, value);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW, so no console flashes up while the suite runs.
        command.creation_flags(0x0800_0000);
    }
    let relay = LocalRelay(command.spawn().unwrap());
    for _ in 0..50 {
        if api(stats_port, "/v1/stats").is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        api(stats_port, "/v1/stats").is_some(),
        "{datapath} relay did not start"
    );
    (relay, port, stats_port)
}

/// An auth hello for session 1, signed by `key`.
pub fn hello(key: &Ed25519KeyPair) -> Vec<u8> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let payload = serde_json::to_vec(&serde_json::json!({
        "v": 1, "iss": "swifttunnel-web", "aud": "swifttunnel-relay",
        "sub": "owner", "sid": "0000000000000001", "srv": "local-test",
        "iat": now, "exp": now + 300, "jti": "local-test-ticket", "lease": true,
    }))
    .unwrap();
    let token = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&payload),
        URL_SAFE_NO_PAD.encode(key.sign(&payload).as_ref())
    );
    let mut frame = 1u64.to_be_bytes().to_vec();
    frame.push(0xa1);
    frame.extend_from_slice(&(token.len() as u16).to_be_bytes());
    frame.extend_from_slice(token.as_bytes());
    frame
}

/// Authenticate session 1 from a fresh local socket, and return the socket.
pub fn authenticated_client(port: u16, key: &Ed25519KeyPair) -> UdpSocket {
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client.send_to(&hello(key), ("127.0.0.1", port)).unwrap();
    let mut ack = [0u8; 64];
    let len = client.recv(&mut ack).expect("no answer to the auth hello");
    assert!(len > 9 && ack[9] == 0, "the relay refused a valid ticket");
    client
}

/// One UDP packet for session 1, from the client's tunnel address.
pub fn udp_frame(dst: [u8; 4], dst_port: u16) -> Vec<u8> {
    let mut ip = [0u8; 32];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&32u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
    ip[16..20].copy_from_slice(&dst);
    ip[20..22].copy_from_slice(&40000u16.to_be_bytes());
    ip[22..24].copy_from_slice(&dst_port.to_be_bytes());
    ip[24..26].copy_from_slice(&12u16.to_be_bytes());
    ip[28..32].copy_from_slice(b"ping");
    let mut frame = 1u64.to_be_bytes().to_vec();
    frame.extend_from_slice(&ip);
    frame
}

/// An RTT ping for session 1. The relay answers with a pong, type 0xa4.
pub fn ping() -> Vec<u8> {
    let mut frame = 1u64.to_be_bytes().to_vec();
    frame.push(0xa3);
    frame.extend_from_slice(&[0; 12]);
    frame
}
