//! Local-only: the destination policy runs in the real binary, on both
//! datapaths. No TUN, external relay, or production keys. The destinations
//! are documentation ranges (RFC 5737), so nothing real is ever contacted:
//! 198.51.100.0/24 stands in for Roblox and 203.0.113.0/24 for everyone else.
mod common;

use common::{api, authenticated_client, ping, start, udp_frame};
use ring::signature::Ed25519KeyPair;
use std::{net::UdpSocket, path::PathBuf};

struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Wait for the pong to a ping sent after the data.
///
/// The relay judges and counts each packet in its receive loop, in order,
/// before reading the next one, so once the pong is back every counter for
/// the data is final. Reading them any earlier races the relay: a packet's
/// counter and its tally entry are updated one after the other, and a
/// snapshot can land in between.
fn wait_for_pong(client: &UdpSocket, port: u16, context: &str) {
    client.send_to(&ping(), ("127.0.0.1", port)).unwrap();
    let mut frame = [0u8; 64];
    loop {
        let len = client
            .recv(&mut frame)
            .unwrap_or_else(|error| panic!("{context}: no pong: {error}"));
        if len > 8 && frame[8] == 0xa4 {
            return;
        }
    }
}

#[test]
fn both_datapaths_refuse_unlisted_destinations_only_when_enforcing() {
    let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let allowlist = std::env::temp_dir().join(format!(
        "swifttunnel-dest-policy-{}.txt",
        std::process::id()
    ));
    std::fs::write(&allowlist, "198.51.100.0/24\n").unwrap();
    let _remove = RemoveOnDrop(allowlist.clone());
    let allowlist = allowlist.to_str().unwrap();

    for datapath in ["v1", "v2"] {
        for mode in ["observe", "enforce"] {
            let context = format!("{datapath}/{mode}");
            let (_relay, port, stats_port) = start(
                datapath,
                &key,
                &[
                    ("RELAY_DEST_POLICY_MODE", mode),
                    ("RELAY_DEST_ALLOWLIST_FILE", allowlist),
                ],
            );
            let client = authenticated_client(port, &key);
            for dst in [[198, 51, 100, 10], [203, 0, 113, 10]] {
                client
                    .send_to(&udp_frame(dst, 50000), ("127.0.0.1", port))
                    .unwrap();
            }
            wait_for_pong(&client, port, &context);

            let policy = api(stats_port, "/v1/dest-policy").unwrap();
            assert_eq!(policy["mode"], mode, "{context}");
            // Exactly one: the listed packet was judged too, and not counted.
            assert_eq!(policy["unlisted_packets"]["udp"], 1, "{context}");
            assert_eq!(
                policy["unlisted_sample"]["networks"][0]["network"], "203.0.113.0/24",
                "{context}"
            );

            // The datapath's own drop counter: refused, not merely counted.
            let expected = u64::from(mode == "enforce");
            let refused = api(stats_port, "/v1/stats").unwrap()["drops"]["forbidden_dst"].clone();
            assert_eq!(policy["dropped_packets"], expected, "{context}");
            assert_eq!(refused, expected, "{context}");

            // First fragments still contain the destination port. Fragmenting
            // TCP must not evade port observation/enforcement, and fragmenting
            // UDP must not bypass the existing forbidden-port rule.
            for (protocol, dst_port) in [(6, 22), (17, 53)] {
                let mut frame = udp_frame([198, 51, 100, 10], dst_port);
                frame.truncate(8 + 28);
                frame[8 + 2..8 + 4].copy_from_slice(&28u16.to_be_bytes());
                frame[8 + 6] = 0x20;
                frame[8 + 9] = protocol;
                client.send_to(&frame, ("127.0.0.1", port)).unwrap();
            }
            wait_for_pong(&client, port, &context);
            let policy = api(stats_port, "/v1/dest-policy").unwrap();
            assert_eq!(policy["unlisted_packets"]["tcp_port"], 1, "{context}");
            let refused = api(stats_port, "/v1/stats").unwrap()["drops"]["forbidden_dst"].clone();
            assert_eq!(refused, 1 + 2 * expected, "{context}");
        }
    }
}
