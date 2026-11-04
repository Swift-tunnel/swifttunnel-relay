//! Local-only regression: a retransmitted auth hello is acknowledged, not
//! refused as a replay.
//!
//! The ack is a UDP datagram. When it is lost the client sends the same hello
//! again, with the same ticket id, and the relay answered that with
//! `AUTH_ACK_REPLAY` even though the session was already authenticated by
//! it. The same ticket from any other endpoint must still be refused.
mod common;

use common::{authenticated_client, hello, ping, start};
use ring::signature::Ed25519KeyPair;
use std::{net::UdpSocket, time::Duration};

fn exchange(socket: &UdpSocket, port: u16, frame: &[u8]) -> Vec<u8> {
    socket.send_to(frame, ("127.0.0.1", port)).unwrap();
    let mut buf = [0u8; 64];
    let len = socket.recv(&mut buf).expect("no answer from the relay");
    buf[..len].to_vec()
}

#[test]
fn both_datapaths_acknowledge_a_retransmitted_hello_only_from_its_endpoint() {
    let key = Ed25519KeyPair::from_seed_unchecked(&[11; 32]).unwrap();
    for datapath in ["v1", "v2"] {
        let (_relay, port, _) = start(datapath, &key, &[]);
        let client = authenticated_client(port, &key);

        let again = exchange(&client, port, &hello(&key));
        assert_eq!((again[8], again[9]), (0xa2, 0), "{datapath}: retransmit");

        let other = UdpSocket::bind("127.0.0.1:0").unwrap();
        other
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let replay = exchange(&other, port, &hello(&key));
        assert_eq!((replay[8], replay[9]), (0xa2, 7), "{datapath}: replay");

        let pong = exchange(&client, port, &ping());
        assert_eq!(pong[8], 0xa4, "{datapath}: endpoint moved");
    }
}
