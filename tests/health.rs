//! Local-only regression: idle connections to the public health endpoint
//! cannot make the relay spawn threads without limit. Linux only, since it
//! counts the relay's threads in /proc.
#![cfg(target_os = "linux")]
mod common;

use common::start;
use ring::signature::Ed25519KeyPair;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    time::Duration,
};

fn threads(pid: u32) -> usize {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("Threads:"))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn health(port: u16) -> Option<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    stream.write_all(b"GET /health HTTP/1.1\r\n\r\n").ok()?;
    let mut body = String::new();
    stream.read_to_string(&mut body).ok()?;
    Some(body)
}

#[test]
fn idle_health_connections_do_not_spawn_unbounded_threads() {
    let key = Ed25519KeyPair::from_seed_unchecked(&[12; 32]).unwrap();
    let health_port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let port_text = health_port.to_string();
    let (relay, _, _) = start("v2", &key, &[("RELAY_HEALTH_PORT", &port_text)]);
    assert!(health(health_port).is_some_and(|body| body.contains("\"status\":\"ok\"")));
    std::thread::sleep(Duration::from_millis(100));
    let before = threads(relay.pid());

    let idle: Vec<_> = (0..300)
        .filter_map(|_| TcpStream::connect(("127.0.0.1", health_port)).ok())
        .collect();
    assert!(idle.len() >= 250, "could not open the idle connections");
    std::thread::sleep(Duration::from_millis(300));
    let during = threads(relay.pid());
    assert!(
        during <= before + 40,
        "{} idle connections grew the relay from {before} to {during} threads",
        idle.len()
    );

    drop(idle);
    std::thread::sleep(Duration::from_millis(300));
    assert!(health(health_port).is_some_and(|body| body.contains("\"status\":\"ok\"")));
}
