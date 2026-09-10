//! Local-only regression: the v1 receive loop keeps going after it opens a
//! UDP flow.
//!
//! It deadlocked on the first one. Admitting a new flow read the whole flow
//! map with `flows.len()` while that flow's own entry held one of the map's
//! shard locks, and DashMap's locks are not reentrant. In v1 that loop is the
//! only reader of the relay socket, so everything behind it stopped too: data,
//! pings, authentication. Destinations are documentation ranges (RFC 5737), so
//! nothing real is contacted.
mod common;

use common::{api, authenticated_client, ping, start, udp_frame};
use ring::signature::Ed25519KeyPair;

#[test]
fn v1_keeps_receiving_after_opening_udp_flows() {
    let key = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
    let (_relay, port, stats_port) = start("v1", &key, &[]);
    let client = authenticated_client(port, &key);

    // Two new flows, so the loop has to come back for a second one as well.
    for dst in [[198, 51, 100, 20], [203, 0, 113, 20]] {
        client
            .send_to(&udp_frame(dst, 50000), ("127.0.0.1", port))
            .unwrap();
    }
    client.send_to(&ping(), ("127.0.0.1", port)).unwrap();
    let mut pong = [0u8; 64];
    let len = client
        .recv(&mut pong)
        .expect("v1 stopped answering after opening a UDP flow");
    assert_eq!(
        pong[8], 0xa4,
        "expected a pong, got frame type {:#x} ({len} bytes)",
        pong[8]
    );

    // The session saw every frame: the hello, both packets and the ping. The
    // stats server refreshes its connection snapshot once a second, so wait
    // for it rather than read it immediately.
    let mut seen = serde_json::Value::Null;
    for _ in 0..150 {
        seen = api(stats_port, "/v1/connections").unwrap()["connections"][0]["packets_in"].clone();
        if seen == 4 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(seen, 4, "packets the session recorded");
}
