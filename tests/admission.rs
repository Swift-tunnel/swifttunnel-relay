//! Local-only protocol regression. No TUN, external relay, or production keys.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    process::{Child, Command, Stdio},
    time::Duration,
};

struct LocalRelay(Child);
impl Drop for LocalRelay {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn stats(port: u16) -> Option<serde_json::Value> {
    let mut s = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().ok()?,
        Duration::from_millis(100),
    )
    .ok()?;
    s.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
    s.write_all(b"GET /v1/stats HTTP/1.1\r\nAuthorization: Bearer local-regression\r\n\r\n")
        .ok()?;
    let mut response = String::new();
    s.read_to_string(&mut response).ok()?;
    serde_json::from_str(response.split_once("\r\n\r\n")?.1).ok()
}
fn hello(key: &Ed25519KeyPair, owner: &str, jti: &str) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let payload=serde_json::to_vec(&serde_json::json!({"v":1,"iss":"swifttunnel-web","aud":"swifttunnel-relay",
        "sub":owner,"sid":"0000000000000001","srv":"local-test","iat":now,"exp":now+300,"jti":jti,"lease":true})).unwrap();
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
fn ping() -> Vec<u8> {
    let mut frame = 1u64.to_be_bytes().to_vec();
    frame.push(0xa3);
    frame.extend_from_slice(&[0; 12]);
    frame
}
fn exchange(socket: &UdpSocket, port: u16, frame: &[u8]) -> Vec<u8> {
    socket.send_to(frame, ("127.0.0.1", port)).unwrap();
    let mut b = [0u8; 1600];
    let n = socket.recv(&mut b).unwrap();
    b[..n].to_vec()
}

#[test]
fn both_datapaths_require_the_owner_before_changing_the_endpoint() {
    let key = Ed25519KeyPair::from_seed_unchecked(&[42; 32]).unwrap();
    for datapath in ["v1", "v2"] {
        let reserved = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
        let api = reserved.local_addr().unwrap().port();
        drop(reserved);
        let mut command = Command::new(env!("CARGO_BIN_EXE_swifttunnel-relay"));
        command
            .env("RELAY_PORT", port.to_string())
            .env("RELAY_STATS_PORT", api.to_string())
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
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let _child = LocalRelay(command.spawn().unwrap());
        for _ in 0..50 {
            if stats(api).is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(stats(api).is_some(), "{datapath} did not start");
        let original = UdpSocket::bind("127.0.0.1:0").unwrap();
        let changed = UdpSocket::bind("127.0.0.1:0").unwrap();
        for socket in [&original, &changed] {
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
        }
        for sid in 2..100u64 {
            original
                .send_to(&sid.to_be_bytes(), ("127.0.0.1", port))
                .unwrap();
        }
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(
            stats(api).unwrap()["active_sessions"],
            0,
            "unsigned traffic allocated sessions"
        );
        assert_eq!(
            exchange(&original, port, &hello(&key, "owner", "first"))[9],
            0
        );
        assert_eq!(
            exchange(&changed, port, &ping())[9],
            9,
            "NAT change must request proof"
        );
        assert_eq!(
            exchange(&changed, port, &hello(&key, "other", "wrong-owner"))[9],
            8
        );
        assert_ne!(
            exchange(&original, port, &ping()).get(9),
            Some(&9),
            "rejected ticket changed endpoint"
        );
        assert_eq!(
            exchange(&changed, port, &hello(&key, "owner", "fresh"))[9],
            0
        );
        assert_eq!(
            exchange(&original, port, &ping())[9],
            9,
            "old endpoint still owns session"
        );
        assert_ne!(exchange(&changed, port, &ping()).get(9), Some(&9));
    }
}
