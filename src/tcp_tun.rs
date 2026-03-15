//! TUN-based IPv4 tunneling for SwiftTunnel relay.
//!
//! The relay can forward full IPv4 packets through a Linux TUN device instead
//! of handling per-flow UDP sockets and response packet reconstruction in
//! user-space. TCP requires this path because the kernel owns handshake,
//! retransmit, and congestion control. UDP can also use this path when
//! `RELAY_TUN_UDP=true`, which removes the relay's hottest user-space work.
//!
//! Flow:
//!   Client -> relay (UDP tunnel) -> rewrite src IP -> TUN fd -> kernel TCP -> game server
//!   Game server -> kernel TCP -> TUN fd -> rewrite dst IP -> relay (UDP tunnel) -> client
//!
//! Each session gets a deterministic IP in `10.200.0.0/16` derived from its session_id.
//! The module is gated on `RELAY_TCP_ENABLED=true` from main.rs; this file provides
//! the implementation only.

#[cfg(target_os = "linux")]
use crossbeam_channel::Receiver;
use crossbeam_channel::Sender;
use dashmap::DashMap;
use std::net::{Ipv4Addr, SocketAddr};
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::sync::Arc;

/// Maximum packet size for TUN reads (matches MAX_PACKET_SIZE in main.rs).
const TUN_BUF_SIZE: usize = 1600;

/// Reuse the relay's canonical IP header minimum length.
use super::IP_HEADER_MIN as MIN_IPV4_HEADER_LEN;

/// IPv4 protocol number for TCP.
const IPPROTO_TCP: u8 = 6;
/// IPv4 protocol number for UDP.
const IPPROTO_UDP: u8 = 17;
#[cfg(target_os = "linux")]
const TUN_DEVICE_NAME: &str = "swifttun0";
#[cfg(target_os = "linux")]
const TUN_INTERFACE_CIDR: &str = "10.200.0.1/16";

/// Packet to transmit back to a client via the relay's UDP socket.
pub struct TxPacket {
    pub session_id: [u8; 8],
    pub client_addr: SocketAddr,
    pub ip_packet: Vec<u8>,
}

/// Handle for cleaning up expired TUN sessions from outside the TUN handler.
///
/// Returned by `TunHandler::new` so the relay's existing cleanup task can
/// remove stale entries and reclaim TUN IP space.
pub struct TunSessionCleanup {
    ip_to_session: std::sync::Arc<DashMap<Ipv4Addr, SessionMapping>>,
    session_to_ip: std::sync::Arc<DashMap<[u8; 8], Ipv4Addr>>,
}

impl TunSessionCleanup {
    /// Remove TCP session state for sessions that no longer exist in the
    /// relay's main session map.
    pub fn remove_expired<F>(&self, session_alive: F)
    where
        F: Fn(&[u8; 8]) -> bool,
    {
        self.session_to_ip.retain(|sid, ip| {
            let alive = session_alive(sid);
            if !alive {
                self.ip_to_session.remove(ip);
            }
            alive
        });
    }
}

/// Inbound IPv4 packet received from a client via the UDP tunnel.
pub struct InboundTunPacket {
    pub session_id: [u8; 8],
    pub client_addr: SocketAddr,
    pub raw_ip_packet: Vec<u8>,
}

/// Mapping info for a session, stored by its assigned TUN IP.
struct SessionMapping {
    session_id: [u8; 8],
    client_addr: SocketAddr,
    original_src_ip: Ipv4Addr,
}

// ---------------------------------------------------------------------------
// Linux TUN implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::os::unix::io::RawFd;

    // ioctl constants for TUN/TAP on Linux.
    const TUNSETIFF: libc::c_ulong = 0x400454ca;
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;

    /// ifr_name length (IFNAMSIZ).
    const IFNAMSIZ: usize = 16;

    /// Minimal `struct ifreq` layout for TUNSETIFF.
    #[repr(C)]
    struct Ifreq {
        ifr_name: [u8; IFNAMSIZ],
        ifr_flags: libc::c_short,
        _pad: [u8; 22], // remainder of union (ifr_ifru)
    }

    /// Create a TUN device with the given name.
    ///
    /// Returns the file descriptor for the TUN device. The fd uses blocking I/O.
    pub fn create_tun_device(name: &str) -> Result<RawFd, std::io::Error> {
        let dev_path = b"/dev/net/tun\0";
        let fd = unsafe { libc::open(dev_path.as_ptr() as *const libc::c_char, libc::O_RDWR) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut ifr = Ifreq {
            ifr_name: [0u8; IFNAMSIZ],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _pad: [0u8; 22],
        };

        // Copy device name into ifr_name (must be NUL-terminated, max IFNAMSIZ-1 chars).
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(IFNAMSIZ - 1);
        ifr.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let ret = unsafe { libc::ioctl(fd, TUNSETIFF as libc::c_ulong, &ifr as *const Ifreq) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }

        log::info!("TUN device '{}' created (fd={})", name, fd);
        Ok(fd)
    }

    pub struct TunHandler {
        tun_fd: RawFd,
        /// Maps rewritten src IP -> session mapping.
        ip_to_session: Arc<DashMap<Ipv4Addr, SessionMapping>>,
        /// Maps session_id -> assigned TUN subnet IP.
        session_to_ip: Arc<DashMap<[u8; 8], Ipv4Addr>>,
        /// Channel to receive IPv4 packets from the RX side.
        rx_receiver: Receiver<InboundTunPacket>,
        /// Channel to send responses back to clients.
        tx_sender: Sender<TxPacket>,
    }

    impl TunHandler {
        fn run_ip_command(args: &[&str]) -> Result<(), std::io::Error> {
            let status = Command::new("ip").args(args).status()?;
            if status.success() {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("ip {} failed with {}", args.join(" "), status),
                ))
            }
        }

        /// TUN MTU sized to avoid IP fragmentation after relay encapsulation.
        ///
        /// Relay frame adds 8 bytes (session_id) and the outer UDP/IP adds 28
        /// bytes, totalling 36 bytes of overhead.  1500 − 36 = 1464, but we
        /// use 1400 for extra headroom against tunnelled-in-tunnel or
        /// non-standard path-MTU scenarios.
        const TUN_MTU: &str = "1400";

        fn configure_tun_interface(name: &str) -> Result<(), std::io::Error> {
            // The relay recreates swifttun0 on every restart, so the address,
            // MTU, and link state need to be re-applied every time instead of
            // relying on a one-time server bootstrap step.
            Self::run_ip_command(&["link", "set", "dev", name, "mtu", Self::TUN_MTU])?;
            Self::run_ip_command(&["link", "set", "dev", name, "up"])?;
            Self::run_ip_command(&["addr", "replace", TUN_INTERFACE_CIDR, "dev", name])?;
            Ok(())
        }

        /// Create a new TunHandler.
        ///
        /// Opens a TUN device named "swifttun0" and returns the handler, a
        /// [`Sender`] for inbound IPv4 packets, and a [`TunSessionCleanup`] handle
        /// for the relay's cleanup task to remove expired sessions.
        pub fn new(
            tx_sender: Sender<TxPacket>,
        ) -> Result<(Self, Sender<InboundTunPacket>, TunSessionCleanup), std::io::Error> {
            let tun_fd = create_tun_device(TUN_DEVICE_NAME)?;
            Self::configure_tun_interface(TUN_DEVICE_NAME)?;

            // Bounded to apply backpressure — tunneled packets are dropped when full,
            // same as the UDP datapath's bounded channel design.
            let (inbound_tx, inbound_rx) = crossbeam_channel::bounded::<InboundTunPacket>(4096);

            let ip_to_session = Arc::new(DashMap::new());
            let session_to_ip = Arc::new(DashMap::new());

            let cleanup = TunSessionCleanup {
                ip_to_session: Arc::clone(&ip_to_session),
                session_to_ip: Arc::clone(&session_to_ip),
            };

            let handler = TunHandler {
                tun_fd,
                ip_to_session,
                session_to_ip,
                rx_receiver: inbound_rx,
                tx_sender,
            };

            Ok((handler, inbound_tx, cleanup))
        }

        /// Run the TUN handler.
        ///
        /// Spawns two OS threads:
        /// - **tun-writer**: reads from `rx_receiver`, rewrites src IP, writes to TUN fd.
        /// - **tun-reader**: reads from TUN fd, rewrites dst IP, sends via `tx_sender`.
        ///
        /// This method consumes `self` and blocks the calling thread only to join the
        /// spawned threads if they exit (they shouldn't under normal operation).
        pub fn run(self) {
            let ip_to_session_w = Arc::clone(&self.ip_to_session);
            let session_to_ip_w = Arc::clone(&self.session_to_ip);
            let rx_receiver = self.rx_receiver.clone();
            let tun_fd_w = self.tun_fd;

            let ip_to_session_r = Arc::clone(&self.ip_to_session);
            let tx_sender = self.tx_sender.clone();
            let tun_fd_r = self.tun_fd;

            // tun-writer thread: client packets -> TUN device
            let writer = std::thread::Builder::new()
                .name("tun-writer".into())
                .spawn(move || {
                    Self::tun_writer_loop(tun_fd_w, rx_receiver, ip_to_session_w, session_to_ip_w);
                })
                .expect("failed to spawn tun-writer thread");

            // tun-reader thread: TUN device -> client responses
            let reader = std::thread::Builder::new()
                .name("tun-reader".into())
                .spawn(move || {
                    Self::tun_reader_loop(tun_fd_r, ip_to_session_r, tx_sender);
                })
                .expect("failed to spawn tun-reader thread");

            // Both threads run indefinitely; join so caller can detect exit.
            if let Err(e) = writer.join() {
                log::warn!("tun-writer thread panicked: {:?}", e);
            }
            if let Err(e) = reader.join() {
                log::warn!("tun-reader thread panicked: {:?}", e);
            }
        }

        /// Writer loop: receive inbound IPv4 packets and write to TUN.
        fn tun_writer_loop(
            tun_fd: RawFd,
            rx_receiver: Receiver<InboundTunPacket>,
            ip_to_session: Arc<DashMap<Ipv4Addr, SessionMapping>>,
            session_to_ip: Arc<DashMap<[u8; 8], Ipv4Addr>>,
        ) {
            loop {
                let pkt = match rx_receiver.recv() {
                    Ok(p) => p,
                    Err(_) => {
                        log::info!("tun-writer: inbound channel closed, exiting");
                        return;
                    }
                };

                let mut ip_packet = pkt.raw_ip_packet;
                if ip_packet.len() < MIN_IPV4_HEADER_LEN {
                    log::debug!(
                        "tun-writer: dropping runt packet ({} bytes)",
                        ip_packet.len()
                    );
                    continue;
                }

                // Verify it is IPv4.
                let version = ip_packet[0] >> 4;
                if version != 4 {
                    log::debug!("tun-writer: dropping non-IPv4 packet (version={})", version);
                    continue;
                }

                // Only tunnel TCP/UDP IPv4 packets.
                if !matches!(ip_packet[9], IPPROTO_TCP | IPPROTO_UDP) {
                    log::debug!("tun-writer: dropping unsupported proto {}", ip_packet[9]);
                    continue;
                }

                // Read the original source IP from the packet.
                let original_src_ip =
                    Ipv4Addr::new(ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]);

                // Get or assign a TUN IP for this session.
                let tun_ip = *session_to_ip.entry(pkt.session_id).or_insert_with(|| {
                    let ip = assign_session_ip(&pkt.session_id, &ip_to_session);
                    log::info!(
                        "TUN session {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x} \
                             assigned TUN IP {}",
                        pkt.session_id[0],
                        pkt.session_id[1],
                        pkt.session_id[2],
                        pkt.session_id[3],
                        pkt.session_id[4],
                        pkt.session_id[5],
                        pkt.session_id[6],
                        pkt.session_id[7],
                        ip,
                    );
                    ip
                });

                // Update reverse mapping. Use entry API to avoid write-lock on
                // the common case where only client_addr may change (NAT rebind).
                ip_to_session
                    .entry(tun_ip)
                    .and_modify(|m| {
                        m.client_addr = pkt.client_addr;
                        m.original_src_ip = original_src_ip;
                    })
                    .or_insert_with(|| SessionMapping {
                        session_id: pkt.session_id,
                        client_addr: pkt.client_addr,
                        original_src_ip,
                    });

                // Rewrite source IP to the assigned TUN IP.
                rewrite_src_ip(&mut ip_packet, tun_ip);

                log::debug!(
                    "tun-writer: {} -> {} ({} bytes) -> TUN",
                    original_src_ip,
                    tun_ip,
                    ip_packet.len(),
                );

                // Write to TUN fd.
                let written = unsafe {
                    libc::write(
                        tun_fd,
                        ip_packet.as_ptr() as *const libc::c_void,
                        ip_packet.len(),
                    )
                };
                if written < 0 {
                    log::warn!(
                        "tun-writer: write failed: {}",
                        std::io::Error::last_os_error()
                    );
                }
            }
        }

        /// Reader loop: read from TUN and send responses back to clients.
        fn tun_reader_loop(
            tun_fd: RawFd,
            ip_to_session: Arc<DashMap<Ipv4Addr, SessionMapping>>,
            tx_sender: Sender<TxPacket>,
        ) {
            let mut buf = [0u8; TUN_BUF_SIZE];

            loop {
                let n =
                    unsafe { libc::read(tun_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    log::warn!("tun-reader: read failed: {}", err);
                    // Brief pause before retrying to avoid a tight error loop.
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                let n = n as usize;
                if n < MIN_IPV4_HEADER_LEN {
                    continue;
                }

                let packet = &buf[..n];

                // Parse destination IP from the packet (bytes 16-19).
                let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

                // Look up the session for this destination IP.
                let mapping = match ip_to_session.get(&dst_ip) {
                    Some(m) => m,
                    None => {
                        log::debug!(
                            "tun-reader: no session for dst IP {} ({} bytes), dropping",
                            dst_ip,
                            n,
                        );
                        continue;
                    }
                };

                let session_id = mapping.session_id;
                let client_addr = mapping.client_addr;
                let original_src_ip = mapping.original_src_ip;
                drop(mapping); // release DashMap ref before mutable borrow

                // Clone the packet and rewrite the destination IP back to the
                // client's original source IP.
                let mut ip_packet = buf[..n].to_vec();
                rewrite_dst_ip(&mut ip_packet, original_src_ip);

                log::debug!(
                    "tun-reader: TUN -> {} (rewritten dst {} -> {}, {} bytes)",
                    client_addr,
                    dst_ip,
                    original_src_ip,
                    n,
                );

                if let Err(e) = tx_sender.send(TxPacket {
                    session_id,
                    client_addr,
                    ip_packet,
                }) {
                    log::warn!("tun-reader: tx channel send failed: {}", e);
                    return;
                }
            }
        }
    }

    impl Drop for TunHandler {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.tun_fd);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Non-Linux stub
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::*;

    pub struct TunHandler {
        _tx_sender: Sender<TxPacket>,
    }

    impl TunHandler {
        pub fn new(
            _tx_sender: Sender<TxPacket>,
        ) -> Result<(Self, Sender<InboundTunPacket>, TunSessionCleanup), std::io::Error> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "TUN-based TCP tunneling is only supported on Linux",
            ))
        }

        pub fn run(self) {
            unreachable!("TunHandler::new always fails on non-Linux");
        }
    }
}

// Re-export the platform-specific handler at module level.
#[allow(unused_imports)]
pub use platform::TunHandler;

// ---------------------------------------------------------------------------
// IP assignment
// ---------------------------------------------------------------------------

/// Deterministically assign a TUN IP in `10.200.0.0/16` from a session_id.
///
/// Primary choice: `10.200.{session_id[0]}.{session_id[1]}`.
/// On collision, fall back to successive byte pairs (2,3), (4,5), (6,7).
/// If all valid candidates collide (astronomically unlikely with 8-byte random
/// IDs), the last valid pair wins and overwrites. If every pair is reserved
/// (`0.0` or `255.255`), fall back to `10.200.0.1`.
fn assign_session_ip(
    session_id: &[u8; 8],
    ip_to_session: &DashMap<Ipv4Addr, SessionMapping>,
) -> Ipv4Addr {
    let mut fallback = None;

    // Byte-pair candidates: (0,1), (2,3), (4,5), (6,7).
    for pair_idx in 0..4 {
        let a = session_id[pair_idx * 2];
        let b = session_id[pair_idx * 2 + 1];

        // Skip 0.0 and 255.255 (network/broadcast-ish in the /16).
        if (a == 0 && b == 0) || (a == 255 && b == 255) {
            continue;
        }

        let candidate = Ipv4Addr::new(10, 200, a, b);
        fallback = Some(candidate);

        // O(1) collision check via the reverse map instead of scanning session_to_ip.
        let collision = ip_to_session
            .get(&candidate)
            .map_or(false, |m| m.session_id != *session_id);

        if !collision {
            return candidate;
        }
    }

    fallback.unwrap_or(Ipv4Addr::new(10, 200, 0, 1))
}

// ---------------------------------------------------------------------------
// Packet rewriting helpers
// ---------------------------------------------------------------------------

/// Byte offset of the source IP field in an IPv4 header.
const IP_SRC_OFFSET: usize = 12;
/// Byte offset of the destination IP field in an IPv4 header.
const IP_DST_OFFSET: usize = 16;

/// Rewrite an IPv4 address field at the given byte offset and fix checksums.
fn rewrite_ip_field(packet: &mut [u8], offset: usize, new_ip: Ipv4Addr) {
    if packet.len() < MIN_IPV4_HEADER_LEN || packet.len() < offset + 4 {
        return;
    }
    let old_ip = Ipv4Addr::new(
        packet[offset],
        packet[offset + 1],
        packet[offset + 2],
        packet[offset + 3],
    );
    packet[offset..offset + 4].copy_from_slice(&new_ip.octets());

    recalculate_ip_checksum(packet);

    // Fragmented IPv4 packets do not carry a complete transport segment in
    // every fragment. Recomputing UDP/TCP checksums over partial fragments
    // corrupts payload bytes and breaks reassembly on the far side. Only
    // fragment 0 carries the transport checksum field, so update the
    // pseudo-header there incrementally and leave later fragments untouched.
    if ipv4_is_fragment(packet) {
        if ipv4_fragment_offset(packet) == Some(0) {
            match packet[9] {
                IPPROTO_TCP => update_fragment_tcp_checksum(packet, old_ip, new_ip),
                IPPROTO_UDP => update_fragment_udp_checksum(packet, old_ip, new_ip),
                _ => {}
            }
        }
        return;
    }

    match packet[9] {
        // TCP/UDP checksums both include the IPv4 pseudo-header.
        IPPROTO_TCP => recalculate_tcp_checksum(packet),
        IPPROTO_UDP => recalculate_udp_checksum(packet),
        _ => {}
    }
}

/// Rewrite the source IP address (bytes 12-15) in an IPv4 packet and fix checksums.
fn rewrite_src_ip(packet: &mut [u8], new_src: Ipv4Addr) {
    rewrite_ip_field(packet, IP_SRC_OFFSET, new_src);
}

/// Rewrite the destination IP address (bytes 16-19) in an IPv4 packet and fix checksums.
fn rewrite_dst_ip(packet: &mut [u8], new_dst: Ipv4Addr) {
    rewrite_ip_field(packet, IP_DST_OFFSET, new_dst);
}

fn ipv4_is_fragment(packet: &[u8]) -> bool {
    ipv4_fragment_offset(packet).is_some_and(|offset| {
        let fragment_bits = u16::from_be_bytes([packet[6], packet[7]]);
        (fragment_bits & 0x2000) != 0 || offset != 0
    })
}

fn ipv4_fragment_offset(packet: &[u8]) -> Option<u16> {
    if packet.len() < MIN_IPV4_HEADER_LEN {
        return None;
    }

    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if ihl < MIN_IPV4_HEADER_LEN || packet.len() < ihl {
        return None;
    }

    let fragment_bits = u16::from_be_bytes([packet[6], packet[7]]);
    Some(fragment_bits & 0x1FFF)
}

fn update_fragment_tcp_checksum(packet: &mut [u8], old_ip: Ipv4Addr, new_ip: Ipv4Addr) {
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if ihl < MIN_IPV4_HEADER_LEN || packet.len() < ihl + 18 {
        return;
    }

    let checksum_offset = ihl + 16;
    let checksum = u16::from_be_bytes([packet[checksum_offset], packet[checksum_offset + 1]]);
    let adjusted = adjust_checksum_for_ipv4_addr_change(checksum, old_ip, new_ip);
    packet[checksum_offset..checksum_offset + 2].copy_from_slice(&adjusted.to_be_bytes());
}

fn update_fragment_udp_checksum(packet: &mut [u8], old_ip: Ipv4Addr, new_ip: Ipv4Addr) {
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if ihl < MIN_IPV4_HEADER_LEN || packet.len() < ihl + 8 {
        return;
    }

    let checksum_offset = ihl + 6;
    let checksum = u16::from_be_bytes([packet[checksum_offset], packet[checksum_offset + 1]]);
    if checksum == 0 {
        return;
    }

    let adjusted = adjust_checksum_for_ipv4_addr_change(checksum, old_ip, new_ip);
    let adjusted = if adjusted == 0 { 0xFFFF } else { adjusted };
    packet[checksum_offset..checksum_offset + 2].copy_from_slice(&adjusted.to_be_bytes());
}

fn adjust_checksum_for_ipv4_addr_change(checksum: u16, old_ip: Ipv4Addr, new_ip: Ipv4Addr) -> u16 {
    let old = old_ip.octets();
    let new = new_ip.octets();

    let old_hi = u16::from_be_bytes([old[0], old[1]]);
    let old_lo = u16::from_be_bytes([old[2], old[3]]);
    let new_hi = u16::from_be_bytes([new[0], new[1]]);
    let new_lo = u16::from_be_bytes([new[2], new[3]]);

    let mut sum = (!checksum as u32)
        + (!old_hi as u32 & 0xFFFF)
        + new_hi as u32
        + (!old_lo as u32 & 0xFFFF)
        + new_lo as u32;

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Recalculate the IPv4 header checksum (RFC 1071).
///
/// Zeros the checksum field (bytes 10-11), computes over the header, and writes back.
fn recalculate_ip_checksum(packet: &mut [u8]) {
    if packet.len() < MIN_IPV4_HEADER_LEN {
        return;
    }

    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if ihl < MIN_IPV4_HEADER_LEN || packet.len() < ihl {
        return;
    }

    // Zero the checksum field before computing.
    packet[10] = 0;
    packet[11] = 0;

    let checksum = super::calculate_ip_checksum(&packet[..ihl]);
    packet[10] = (checksum >> 8) as u8;
    packet[11] = (checksum & 0xFF) as u8;
}

/// Recalculate the TCP checksum over the pseudo-header + TCP segment.
///
/// The TCP pseudo-header contains: src IP (4), dst IP (4), zero (1), protocol (1),
/// TCP length (2). We zero the TCP checksum field, compute, and write back.
fn recalculate_tcp_checksum(packet: &mut [u8]) {
    if packet.len() < MIN_IPV4_HEADER_LEN {
        return;
    }

    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if packet.len() < ihl {
        return;
    }

    // IP total length (bytes 2-3).
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < ihl || packet.len() < total_len {
        return;
    }

    let tcp_offset = ihl;
    let tcp_len = total_len - ihl;

    // TCP header is at least 20 bytes; checksum is at offset 16-17 within TCP.
    if tcp_len < 20 {
        return;
    }

    // Zero the TCP checksum field (offset 16-17 within the TCP segment).
    packet[tcp_offset + 16] = 0;
    packet[tcp_offset + 17] = 0;

    // Build pseudo-header: src_ip(4) + dst_ip(4) + zero(1) + proto(1) + tcp_len(2) = 12 bytes.
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&packet[12..16]); // src IP
    pseudo[4..8].copy_from_slice(&packet[16..20]); // dst IP
    pseudo[8] = 0;
    pseudo[9] = IPPROTO_TCP;
    pseudo[10] = (tcp_len >> 8) as u8;
    pseudo[11] = (tcp_len & 0xFF) as u8;

    // Accumulate checksum over pseudo-header + TCP segment.
    let mut sum: u32 = 0;

    // Pseudo-header.
    for i in (0..12).step_by(2) {
        sum += u16::from_be_bytes([pseudo[i], pseudo[i + 1]]) as u32;
    }

    // TCP segment.
    let tcp_segment = &packet[tcp_offset..tcp_offset + tcp_len];
    let mut i = 0;
    while i + 1 < tcp_len {
        sum += u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
        i += 2;
    }
    // If TCP segment length is odd, pad with a zero byte.
    if tcp_len % 2 == 1 {
        sum += (tcp_segment[tcp_len - 1] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits.
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let checksum = !sum as u16;

    packet[tcp_offset + 16] = (checksum >> 8) as u8;
    packet[tcp_offset + 17] = (checksum & 0xFF) as u8;
}

/// Recalculate the UDP checksum over the pseudo-header + UDP datagram.
///
/// IPv4 allows UDP checksum 0 to mean "checksum omitted". Preserve that mode
/// instead of forcing a non-zero checksum after IP rewriting.
fn recalculate_udp_checksum(packet: &mut [u8]) {
    if packet.len() < MIN_IPV4_HEADER_LEN {
        return;
    }

    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if packet.len() < ihl {
        return;
    }

    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < ihl + 8 || packet.len() < total_len {
        return;
    }

    let udp_offset = ihl;
    let udp_len = total_len - ihl;
    if udp_len < 8 {
        return;
    }

    let existing = u16::from_be_bytes([packet[udp_offset + 6], packet[udp_offset + 7]]);
    if existing == 0 {
        return;
    }

    packet[udp_offset + 6] = 0;
    packet[udp_offset + 7] = 0;

    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&packet[12..16]);
    pseudo[4..8].copy_from_slice(&packet[16..20]);
    pseudo[8] = 0;
    pseudo[9] = IPPROTO_UDP;
    pseudo[10] = (udp_len >> 8) as u8;
    pseudo[11] = (udp_len & 0xFF) as u8;

    let mut sum: u32 = 0;
    for i in (0..12).step_by(2) {
        sum += u16::from_be_bytes([pseudo[i], pseudo[i + 1]]) as u32;
    }

    let udp_datagram = &packet[udp_offset..udp_offset + udp_len];
    let mut i = 0;
    while i + 1 < udp_len {
        sum += u16::from_be_bytes([udp_datagram[i], udp_datagram[i + 1]]) as u32;
        i += 2;
    }
    if udp_len % 2 == 1 {
        sum += (udp_datagram[udp_len - 1] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let checksum = !sum as u16;
    let checksum = if checksum == 0 { 0xFFFF } else { checksum };

    packet[udp_offset + 6] = (checksum >> 8) as u8;
    packet[udp_offset + 7] = (checksum & 0xFF) as u8;
}

pub type InboundTcpPacket = InboundTunPacket;
pub type TcpSessionCleanup = TunSessionCleanup;
pub type TcpTunHandler = TunHandler;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid IPv4+TCP packet for testing.
    fn make_tcp_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        // IPv4 header (20 bytes) + TCP header (20 bytes) + 4 bytes payload = 44 bytes.
        let total_len: u16 = 44;
        let mut pkt = vec![0u8; total_len as usize];

        // Version (4) + IHL (5 = 20 bytes).
        pkt[0] = 0x45;
        // Total length.
        pkt[2] = (total_len >> 8) as u8;
        pkt[3] = (total_len & 0xFF) as u8;
        // TTL.
        pkt[8] = 64;
        // Protocol = TCP.
        pkt[9] = IPPROTO_TCP;
        // Source IP.
        let s = src.octets();
        pkt[12..16].copy_from_slice(&s);
        // Destination IP.
        let d = dst.octets();
        pkt[16..20].copy_from_slice(&d);

        // TCP header starts at offset 20.
        // Source port = 12345 (0x3039).
        pkt[20] = 0x30;
        pkt[21] = 0x39;
        // Dest port = 80 (0x0050).
        pkt[22] = 0x00;
        pkt[23] = 0x50;
        // Data offset: 5 (20 bytes) in upper nibble of byte 32.
        pkt[32] = 0x50;
        // Payload bytes (arbitrary).
        pkt[40] = 0xDE;
        pkt[41] = 0xAD;
        pkt[42] = 0xBE;
        pkt[43] = 0xEF;

        // Compute checksums.
        recalculate_ip_checksum(&mut pkt);
        recalculate_tcp_checksum(&mut pkt);

        pkt
    }

    fn make_udp_packet(src: Ipv4Addr, dst: Ipv4Addr, checksum: u16) -> Vec<u8> {
        let payload = [0xAA, 0xBB, 0xCC, 0xDD];
        let total_len: u16 = 20 + 8 + payload.len() as u16;
        let mut pkt = vec![0u8; total_len as usize];

        pkt[0] = 0x45;
        pkt[2] = (total_len >> 8) as u8;
        pkt[3] = (total_len & 0xFF) as u8;
        pkt[8] = 64;
        pkt[9] = IPPROTO_UDP;
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&dst.octets());

        let udp_len = 8 + payload.len() as u16;
        pkt[20] = 0x30;
        pkt[21] = 0x39;
        pkt[22] = 0x00;
        pkt[23] = 0x35;
        pkt[24] = (udp_len >> 8) as u8;
        pkt[25] = (udp_len & 0xFF) as u8;
        pkt[26] = (checksum >> 8) as u8;
        pkt[27] = (checksum & 0xFF) as u8;
        pkt[28..32].copy_from_slice(&payload);

        recalculate_ip_checksum(&mut pkt);
        if checksum != 0 {
            recalculate_udp_checksum(&mut pkt);
        }

        pkt
    }

    fn make_udp_fragment_pair(src: Ipv4Addr, dst: Ipv4Addr) -> (Vec<u8>, Vec<u8>) {
        let payload = b"fragmented-udp-checksum-path".to_vec();
        let udp_len = 8 + payload.len();

        let mut udp_datagram = Vec::with_capacity(udp_len);
        udp_datagram.extend_from_slice(&0x3039u16.to_be_bytes());
        udp_datagram.extend_from_slice(&0x0035u16.to_be_bytes());
        udp_datagram.extend_from_slice(&(udp_len as u16).to_be_bytes());
        udp_datagram.extend_from_slice(&0u16.to_be_bytes());
        udp_datagram.extend_from_slice(&payload);

        let mut pseudo = [0u8; 12];
        pseudo[0..4].copy_from_slice(&src.octets());
        pseudo[4..8].copy_from_slice(&dst.octets());
        pseudo[8] = 0;
        pseudo[9] = IPPROTO_UDP;
        pseudo[10..12].copy_from_slice(&(udp_len as u16).to_be_bytes());

        let mut checksum_input = pseudo.to_vec();
        checksum_input.extend_from_slice(&udp_datagram);
        let checksum = super::super::calculate_ip_checksum(&checksum_input);
        let checksum = if checksum == 0 { 0xFFFF } else { checksum };
        udp_datagram[6..8].copy_from_slice(&checksum.to_be_bytes());

        let first_payload = udp_datagram[..24].to_vec();
        let second_payload = udp_datagram[24..].to_vec();

        let build_fragment = |payload: &[u8], fragment_offset_blocks: u16, more_fragments: bool| {
            let total_len: u16 = (20 + payload.len()) as u16;
            let mut pkt = vec![0u8; total_len as usize];
            pkt[0] = 0x45;
            pkt[2] = (total_len >> 8) as u8;
            pkt[3] = (total_len & 0xFF) as u8;
            pkt[4] = 0x12;
            pkt[5] = 0x34;
            let fragment_bits =
                (fragment_offset_blocks & 0x1FFF) | if more_fragments { 0x2000 } else { 0 };
            pkt[6..8].copy_from_slice(&fragment_bits.to_be_bytes());
            pkt[8] = 64;
            pkt[9] = IPPROTO_UDP;
            pkt[12..16].copy_from_slice(&src.octets());
            pkt[16..20].copy_from_slice(&dst.octets());
            pkt[20..].copy_from_slice(payload);
            recalculate_ip_checksum(&mut pkt);
            pkt
        };

        (
            build_fragment(&first_payload, 0, true),
            build_fragment(&second_payload, 3, false),
        )
    }

    /// Verify that the IP checksum validates to zero when checked.
    fn verify_ip_checksum(packet: &[u8]) -> bool {
        let ihl = ((packet[0] & 0x0F) as usize) * 4;
        super::super::calculate_ip_checksum(&packet[..ihl]) == 0
    }

    /// Verify that the TCP checksum validates by recomputing and comparing.
    fn verify_tcp_checksum(packet: &[u8]) -> bool {
        let mut clone = packet.to_vec();
        recalculate_tcp_checksum(&mut clone);
        // If the original checksum was correct, recomputing should produce the same bytes.
        let ihl = ((packet[0] & 0x0F) as usize) * 4;
        clone[ihl + 16] == packet[ihl + 16] && clone[ihl + 17] == packet[ihl + 17]
    }

    fn verify_udp_checksum(packet: &[u8]) -> bool {
        let ihl = ((packet[0] & 0x0F) as usize) * 4;
        let checksum = u16::from_be_bytes([packet[ihl + 6], packet[ihl + 7]]);
        if checksum == 0 {
            return true;
        }
        let mut clone = packet.to_vec();
        recalculate_udp_checksum(&mut clone);
        clone[ihl + 6] == packet[ihl + 6] && clone[ihl + 7] == packet[ihl + 7]
    }

    fn reassemble_udp_fragments(first: &[u8], second: &[u8]) -> Vec<u8> {
        let mut packet = first.to_vec();
        packet[2..4]
            .copy_from_slice(&((20 + first.len() + second.len() - 40) as u16).to_be_bytes());
        packet[6..8].copy_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&second[20..]);
        recalculate_ip_checksum(&mut packet);
        packet
    }

    #[test]
    fn test_ip_checksum_round_trip() {
        let pkt = make_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(93, 184, 216, 34),
        );
        assert!(verify_ip_checksum(&pkt));
    }

    #[test]
    fn test_tcp_checksum_round_trip() {
        let pkt = make_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(93, 184, 216, 34),
        );
        assert!(verify_tcp_checksum(&pkt));
    }

    #[test]
    fn test_rewrite_src_preserves_checksums() {
        let mut pkt = make_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(93, 184, 216, 34),
        );
        let new_src = Ipv4Addr::new(10, 200, 42, 7);
        rewrite_src_ip(&mut pkt, new_src);

        // Verify new source IP is in place.
        assert_eq!(&pkt[12..16], &new_src.octets());
        // Verify checksums are valid.
        assert!(verify_ip_checksum(&pkt));
        assert!(verify_tcp_checksum(&pkt));
    }

    #[test]
    fn test_rewrite_dst_preserves_checksums() {
        let mut pkt = make_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(93, 184, 216, 34),
        );
        let new_dst = Ipv4Addr::new(10, 0, 0, 1);
        rewrite_dst_ip(&mut pkt, new_dst);

        assert_eq!(&pkt[16..20], &new_dst.octets());
        assert!(verify_ip_checksum(&pkt));
        assert!(verify_tcp_checksum(&pkt));
    }

    #[test]
    fn test_rewrite_both_directions() {
        let original_src = Ipv4Addr::new(172, 16, 0, 50);
        let original_dst = Ipv4Addr::new(1, 2, 3, 4);
        let mut pkt = make_tcp_packet(original_src, original_dst);

        // Simulate client -> TUN: rewrite src.
        let tun_ip = Ipv4Addr::new(10, 200, 0xAA, 0xBB);
        rewrite_src_ip(&mut pkt, tun_ip);
        assert_eq!(&pkt[12..16], &tun_ip.octets());
        assert_eq!(&pkt[16..20], &original_dst.octets());
        assert!(verify_ip_checksum(&pkt));
        assert!(verify_tcp_checksum(&pkt));

        // Simulate TUN -> client: rewrite dst back.
        rewrite_dst_ip(&mut pkt, original_src);
        assert_eq!(&pkt[12..16], &tun_ip.octets());
        assert_eq!(&pkt[16..20], &original_src.octets());
        assert!(verify_ip_checksum(&pkt));
        assert!(verify_tcp_checksum(&pkt));
    }

    #[test]
    fn test_rewrite_udp_preserves_nonzero_checksum() {
        let mut pkt = make_udp_packet(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(1, 1, 1, 1),
            0x1234,
        );
        rewrite_src_ip(&mut pkt, Ipv4Addr::new(10, 200, 42, 7));
        rewrite_dst_ip(&mut pkt, Ipv4Addr::new(10, 0, 0, 1));
        assert!(verify_ip_checksum(&pkt));
        assert!(verify_udp_checksum(&pkt));
    }

    #[test]
    fn test_rewrite_udp_preserves_zero_checksum_mode() {
        let mut pkt = make_udp_packet(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(1, 1, 1, 1),
            0,
        );
        rewrite_src_ip(&mut pkt, Ipv4Addr::new(10, 200, 42, 7));
        let ihl = ((pkt[0] & 0x0F) as usize) * 4;
        assert_eq!(u16::from_be_bytes([pkt[ihl + 6], pkt[ihl + 7]]), 0);
        assert!(verify_ip_checksum(&pkt));
    }

    #[test]
    fn test_ipv4_fragment_detection() {
        let (first, tail) =
            make_udp_fragment_pair(Ipv4Addr::new(192, 168, 1, 10), Ipv4Addr::new(8, 8, 8, 8));

        assert!(ipv4_is_fragment(&first));
        assert!(ipv4_is_fragment(&tail));
        assert!(!ipv4_is_fragment(&make_udp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(8, 8, 8, 8),
            0x1234,
        )));
    }

    #[test]
    fn test_rewrite_src_preserves_udp_fragment_payload_bytes() {
        let (mut pkt, _) =
            make_udp_fragment_pair(Ipv4Addr::new(192, 168, 1, 100), Ipv4Addr::new(1, 1, 1, 1));
        let before_transport = pkt[20..].to_vec();

        rewrite_src_ip(&mut pkt, Ipv4Addr::new(10, 200, 42, 7));

        assert_eq!(&pkt[20..26], &before_transport[20 - 20..26 - 20]);
        assert_eq!(&pkt[28..], &before_transport[8..]);
        assert!(verify_ip_checksum(&pkt));
    }

    #[test]
    fn test_rewrite_dst_preserves_non_initial_udp_fragment_payload_bytes() {
        let (_, mut pkt) =
            make_udp_fragment_pair(Ipv4Addr::new(192, 168, 1, 100), Ipv4Addr::new(1, 1, 1, 1));
        let before_transport = pkt[20..].to_vec();

        rewrite_dst_ip(&mut pkt, Ipv4Addr::new(10, 200, 42, 7));

        assert_eq!(pkt[20..], before_transport);
        assert!(verify_ip_checksum(&pkt));
    }

    #[test]
    fn test_rewrite_src_keeps_fragmented_udp_checksum_valid_after_reassembly() {
        let new_src = Ipv4Addr::new(10, 200, 42, 7);
        let (mut first, mut second) =
            make_udp_fragment_pair(Ipv4Addr::new(192, 168, 1, 100), Ipv4Addr::new(1, 1, 1, 1));

        rewrite_src_ip(&mut first, new_src);
        rewrite_src_ip(&mut second, new_src);

        let reassembled = reassemble_udp_fragments(&first, &second);
        assert_eq!(&reassembled[12..16], &new_src.octets());
        assert!(verify_ip_checksum(&reassembled));
        assert!(verify_udp_checksum(&reassembled));
    }

    #[test]
    fn test_rewrite_dst_keeps_fragmented_udp_checksum_valid_after_reassembly() {
        let new_dst = Ipv4Addr::new(10, 0, 0, 1);
        let (mut first, mut second) =
            make_udp_fragment_pair(Ipv4Addr::new(192, 168, 1, 100), Ipv4Addr::new(1, 1, 1, 1));

        rewrite_dst_ip(&mut first, new_dst);
        rewrite_dst_ip(&mut second, new_dst);

        let reassembled = reassemble_udp_fragments(&first, &second);
        assert_eq!(&reassembled[16..20], &new_dst.octets());
        assert!(verify_ip_checksum(&reassembled));
        assert!(verify_udp_checksum(&reassembled));
    }

    /// Helper to create a SessionMapping for tests.
    fn test_mapping(session_id: [u8; 8]) -> SessionMapping {
        SessionMapping {
            session_id,
            client_addr: "127.0.0.1:1234".parse().unwrap(),
            original_src_ip: Ipv4Addr::new(192, 168, 1, 1),
        }
    }

    #[test]
    fn test_assign_session_ip_basic() {
        let map: DashMap<Ipv4Addr, SessionMapping> = DashMap::new();
        let sid = [0x42, 0x07, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let ip = assign_session_ip(&sid, &map);
        assert_eq!(ip, Ipv4Addr::new(10, 200, 0x42, 0x07));
    }

    #[test]
    fn test_assign_session_ip_collision() {
        let map: DashMap<Ipv4Addr, SessionMapping> = DashMap::new();

        // First session claims 10.200.42.7.
        let sid1 = [0x2A, 0x07, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let ip1 = assign_session_ip(&sid1, &map);
        map.insert(ip1, test_mapping(sid1));
        assert_eq!(ip1, Ipv4Addr::new(10, 200, 0x2A, 0x07));

        // Second session has same first two bytes but different remaining.
        let sid2 = [0x2A, 0x07, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC];
        let ip2 = assign_session_ip(&sid2, &map);
        // Should fall back to bytes 2,3 since 0,1 collide.
        assert_eq!(ip2, Ipv4Addr::new(10, 200, 0x77, 0x88));
    }

    #[test]
    fn test_assign_session_ip_skips_zero() {
        let map: DashMap<Ipv4Addr, SessionMapping> = DashMap::new();
        let sid = [0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let ip = assign_session_ip(&sid, &map);
        // First pair (0,0) is skipped, should use (0xAA, 0xBB).
        assert_eq!(ip, Ipv4Addr::new(10, 200, 0xAA, 0xBB));
    }

    #[test]
    fn test_assign_session_ip_reserved_pairs_fallback() {
        let map: DashMap<Ipv4Addr, SessionMapping> = DashMap::new();
        let sid = [0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF];
        let ip = assign_session_ip(&sid, &map);
        assert_eq!(ip, Ipv4Addr::new(10, 200, 0, 1));
    }

    #[test]
    fn test_runt_packet_ignored() {
        // Packet too short for IPv4 header.
        let mut pkt = vec![0x45, 0x00, 0x00, 0x14];
        rewrite_src_ip(&mut pkt, Ipv4Addr::new(10, 0, 0, 1));
        // Should be a no-op (no panic).
        assert_eq!(pkt.len(), 4);
    }
}
