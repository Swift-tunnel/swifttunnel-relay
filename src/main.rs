//! SwiftTunnel V3 UDP Relay Server
//!
//! High-performance UDP relay for game traffic. No encryption, lowest latency.
//! Inspired by ExitLag/WTFast architecture.
//!
//! Protocol:
//! - Client sends: [session_id:8][IP packet]
//! - Relay parses IP packet, extracts destination, forwards UDP payload
//! - Game server responds to relay
//! - Relay reconstructs IP packet and sends: [session_id:8][IP packet] back to client
//!
//! Architecture:
//! - Main task: Receives from clients, parses packets, routes to flow tasks
//! - Flow tasks: One per (session, game_server) pair, handles bidirectional forwarding
//! - Response task: Sends responses back to clients
//!
//! v1.4.0 Changes:
//! - Configurable port via RELAY_PORT env var (default: 51821)
//! - MIT license for open-source release
//! - Package renamed to swifttunnel-relay
//!
//! v1.3.0 Stability Improvements:
//! - Atomic flow creation (no race conditions)
//! - Graceful error recovery (transient errors don't kill flows)
//! - Bounded channels with backpressure
//! - NAT rebinding resilience
//! - Longer session timeout (3 minutes)
//! - Flow soft-delete with grace period

use anyhow::{Context, Result};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use std::env;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::time::interval;

const SESSION_ID_LEN: usize = 8;
const DEFAULT_PORT: u16 = 51821;

/// Get listen port from RELAY_PORT env var or use default
fn get_listen_port() -> u16 {
    env::var("RELAY_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PORT)
}
/// Session timeout increased from 60s to 180s to survive network hiccups
const SESSION_TIMEOUT: Duration = Duration::from_secs(180);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
/// Grace period before fully removing a flow (allows late packets)
const FLOW_GRACE_PERIOD: Duration = Duration::from_secs(30);
const MAX_PACKET_SIZE: usize = 1600;
/// Channel capacity per flow (prevents OOM, games handle packet loss)
const FLOW_CHANNEL_CAPACITY: usize = 64;

/// Minimum IP header size
const IP_HEADER_MIN: usize = 20;
/// UDP header size
const UDP_HEADER_SIZE: usize = 8;

/// Channel for sending packets to a flow (bounded for backpressure)
type FlowTx = mpsc::Sender<Vec<u8>>;

/// Channel for sending responses back to clients
type ResponseTx = mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>;

/// Check if a receive error is transient and can be ignored
fn is_transient_recv_error(e: &std::io::Error) -> bool {
    matches!(e.kind(),
        ErrorKind::WouldBlock |
        ErrorKind::TimedOut |
        ErrorKind::Interrupted |
        ErrorKind::ConnectionReset  // Can happen spuriously on recv
    )
}

/// Check if a send error is transient and can be ignored
/// NOTE: ConnectionReset on send = ICMP port unreachable = game server down
fn is_transient_send_error(e: &std::io::Error) -> bool {
    matches!(e.kind(),
        ErrorKind::WouldBlock |
        ErrorKind::TimedOut |
        ErrorKind::Interrupted
        // ConnectionReset on send is NOT transient - game server unreachable
    )
}

/// Original packet info needed to reconstruct responses
#[derive(Clone, Copy)]
struct OriginalPacketInfo {
    /// Client's source IP (tunnel IP like 10.0.0.x)
    src_ip: std::net::Ipv4Addr,
    /// Client's source port
    src_port: u16,
    /// Game server IP
    dst_ip: std::net::Ipv4Addr,
    /// Game server port
    dst_port: u16,
}

/// Flow entry in the flow map
struct FlowEntry {
    tx: FlowTx,
    client_addr: SocketAddr,
    last_activity: Instant,
    /// Original packet info for response reconstruction
    original_info: OriginalPacketInfo,
    /// If set, flow is marked for removal after grace period
    marked_for_removal: Option<Instant>,
}

/// Global statistics
struct Stats {
    packets_in: AtomicU64,
    packets_out: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    active_flows: AtomicU64,
    active_sessions: AtomicU64,
    /// Packets dropped due to full channel
    dropped_in: AtomicU64,
    /// Response packets dropped
    dropped_out: AtomicU64,
}

impl Stats {
    fn new() -> Self {
        Self {
            packets_in: AtomicU64::new(0),
            packets_out: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            active_flows: AtomicU64::new(0),
            active_sessions: AtomicU64::new(0),
            dropped_in: AtomicU64::new(0),
            dropped_out: AtomicU64::new(0),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let listen_port = get_listen_port();

    log::info!("╔════════════════════════════════════════════╗");
    log::info!("║     SwiftTunnel V3 UDP Relay v1.4.0        ║");
    log::info!("║     Low Latency Game Packet Forwarding     ║");
    log::info!("╚════════════════════════════════════════════╝");

    // Bind main socket
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", listen_port))
        .await
        .context(format!("Failed to bind to port {}", listen_port))?;

    log::info!("Listening on 0.0.0.0:{}", listen_port);

    let socket = Arc::new(socket);
    let stats = Arc::new(Stats::new());

    // Session tracking: session_id -> client_addr
    let sessions: Arc<DashMap<[u8; SESSION_ID_LEN], SocketAddr>> = Arc::new(DashMap::new());

    // Flow tracking: "session_hex:game_addr" -> FlowEntry
    let flows: Arc<DashMap<String, FlowEntry>> = Arc::new(DashMap::new());

    // Channel for sending responses back to clients
    let (response_tx, mut response_rx) = mpsc::unbounded_channel::<(SocketAddr, Vec<u8>)>();

    // Spawn response sender task
    let socket_sender = Arc::clone(&socket);
    let stats_out = Arc::clone(&stats);
    tokio::spawn(async move {
        while let Some((addr, data)) = response_rx.recv().await {
            if let Err(e) = socket_sender.send_to(&data, addr).await {
                log::warn!("Failed to send response to {}: {}", addr, e);
            } else {
                stats_out.packets_out.fetch_add(1, Ordering::Relaxed);
                stats_out.bytes_out.fetch_add(data.len() as u64, Ordering::Relaxed);
            }
        }
    });

    // Spawn cleanup task with soft-delete grace period
    let sessions_cleanup = Arc::clone(&sessions);
    let flows_cleanup = Arc::clone(&flows);
    let stats_cleanup = Arc::clone(&stats);
    tokio::spawn(async move {
        let mut cleanup_timer = interval(CLEANUP_INTERVAL);
        loop {
            cleanup_timer.tick().await;
            let now = Instant::now();

            let mut marked_count = 0u32;
            let mut revived_count = 0u32;
            let mut removed_count = 0u32;

            // Two-phase cleanup: mark for removal, then remove after grace period
            flows_cleanup.retain(|key, flow| {
                let idle_time = now.duration_since(flow.last_activity);

                if let Some(marked_at) = flow.marked_for_removal {
                    // Already marked - check if we should remove or if it was revived
                    if now.duration_since(marked_at) >= FLOW_GRACE_PERIOD {
                        // Grace period expired, remove
                        log::debug!("Removing flow {} after grace period", key);
                        removed_count += 1;
                        return false;
                    }
                    // Still in grace period - check if revived (recent activity)
                    if idle_time < Duration::from_secs(10) {
                        flow.marked_for_removal = None;
                        log::debug!("Flow {} revived during grace period", key);
                        revived_count += 1;
                    }
                    return true;
                }

                // Not marked yet - mark if idle past timeout
                if idle_time >= SESSION_TIMEOUT {
                    flow.marked_for_removal = Some(now);
                    log::debug!("Marking flow {} for removal (idle {}s)", key, idle_time.as_secs());
                    marked_count += 1;
                }
                true
            });

            // Update stats
            stats_cleanup.active_flows.store(flows_cleanup.len() as u64, Ordering::Relaxed);
            stats_cleanup.active_sessions.store(sessions_cleanup.len() as u64, Ordering::Relaxed);

            if removed_count > 0 || marked_count > 0 || revived_count > 0 {
                log::info!(
                    "Cleanup: marked={}, revived={}, removed={}, sessions={}, flows={}",
                    marked_count,
                    revived_count,
                    removed_count,
                    sessions_cleanup.len(),
                    flows_cleanup.len()
                );
            }
        }
    });

    // Spawn stats logging task
    let stats_log = Arc::clone(&stats);
    tokio::spawn(async move {
        let mut stats_timer = interval(Duration::from_secs(60));
        let start = Instant::now();
        loop {
            stats_timer.tick().await;
            let elapsed = start.elapsed().as_secs_f64();
            let pkts_in = stats_log.packets_in.load(Ordering::Relaxed);
            let pkts_out = stats_log.packets_out.load(Ordering::Relaxed);
            let bytes_in = stats_log.bytes_in.load(Ordering::Relaxed);
            let bytes_out = stats_log.bytes_out.load(Ordering::Relaxed);
            let dropped_in = stats_log.dropped_in.load(Ordering::Relaxed);
            let dropped_out = stats_log.dropped_out.load(Ordering::Relaxed);

            log::info!(
                "Stats: in={} out={} ({:.1}/{:.1} MB), {:.0} pkt/s, sessions={}, flows={}, dropped={}+{}",
                pkts_in,
                pkts_out,
                bytes_in as f64 / 1_000_000.0,
                bytes_out as f64 / 1_000_000.0,
                (pkts_in + pkts_out) as f64 / elapsed,
                stats_log.active_sessions.load(Ordering::Relaxed),
                stats_log.active_flows.load(Ordering::Relaxed),
                dropped_in,
                dropped_out,
            );
        }
    });

    // Main receive loop
    let mut buf = [0u8; MAX_PACKET_SIZE];

    loop {
        let (len, client_addr) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                log::warn!("Recv error: {}", e);
                continue;
            }
        };

        stats.packets_in.fetch_add(1, Ordering::Relaxed);
        stats.bytes_in.fetch_add(len as u64, Ordering::Relaxed);

        // Need at least session_id
        if len < SESSION_ID_LEN {
            continue;
        }

        // Extract session ID
        let mut session_id = [0u8; SESSION_ID_LEN];
        session_id.copy_from_slice(&buf[..SESSION_ID_LEN]);

        // Update session
        sessions.insert(session_id, client_addr);

        // Keepalive packet (just session ID, no payload)
        if len == SESSION_ID_LEN {
            log::trace!("Keepalive from {:016x}", u64::from_be_bytes(session_id));

            // IMPORTANT: Update activity time for ALL flows belonging to this session
            // This prevents flows from expiring during idle game periods (loading screens, menus)
            // which would cause Error 277 (connection lost)
            let session_prefix = format!("{:016x}:", u64::from_be_bytes(session_id));
            let mut flows_refreshed = 0;
            for mut entry in flows.iter_mut() {
                if entry.key().starts_with(&session_prefix) {
                    entry.last_activity = Instant::now();
                    entry.client_addr = client_addr; // Update client addr in case of NAT rebind
                    flows_refreshed += 1;
                }
            }
            if flows_refreshed > 0 {
                log::trace!("Keepalive refreshed {} flows for session {:016x}",
                    flows_refreshed, u64::from_be_bytes(session_id));
            }

            continue;
        }

        // Need enough for IP header
        if len < SESSION_ID_LEN + IP_HEADER_MIN {
            continue;
        }

        // Parse IP packet
        let ip_packet = &buf[SESSION_ID_LEN..len];
        let Some((game_addr, udp_payload, original_info)) = parse_ip_packet_full(ip_packet) else {
            continue;
        };

        // Create flow key
        let flow_key = format!("{:016x}:{}", u64::from_be_bytes(session_id), game_addr);

        // Atomic get-or-create using entry() API to prevent race conditions
        match flows.entry(flow_key.clone()) {
            Entry::Occupied(mut entry) => {
                // Existing flow - update and send
                let flow = entry.get_mut();
                flow.last_activity = Instant::now();
                flow.client_addr = client_addr; // NAT rebind support
                flow.original_info = original_info;
                flow.marked_for_removal = None; // Revive if was marked

                // Bounded channel - drop packet if full (games handle packet loss)
                match flow.tx.try_send(udp_payload.to_vec()) {
                    Ok(_) => {}
                    Err(TrySendError::Full(_)) => {
                        stats.dropped_in.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(TrySendError::Closed(_)) => {
                        // Flow task died, remove entry so it can be recreated
                        drop(entry);
                        flows.remove(&flow_key);
                    }
                }
            }
            Entry::Vacant(entry) => {
                // New flow - create atomically
                let (tx, rx) = mpsc::channel(FLOW_CHANNEL_CAPACITY);

                // Send first packet (should never fail on fresh channel)
                if tx.try_send(udp_payload.to_vec()).is_err() {
                    log::warn!("Failed to queue first packet for new flow {}", flow_key);
                }

                // Insert atomically
                entry.insert(FlowEntry {
                    tx,
                    client_addr,
                    last_activity: Instant::now(),
                    original_info,
                    marked_for_removal: None,
                });

                // Spawn flow handler
                let response_tx = response_tx.clone();
                let flows_ref = Arc::clone(&flows);
                let sessions_ref = Arc::clone(&sessions);
                let stats_ref = Arc::clone(&stats);

                tokio::spawn(async move {
                    run_flow_handler(
                        flow_key,
                        game_addr,
                        session_id,
                        rx,
                        response_tx,
                        flows_ref,
                        sessions_ref,
                        stats_ref,
                    )
                    .await;
                });

                log::debug!(
                    "New flow: {:016x} -> {} from {} (client {}:{} -> game)",
                    u64::from_be_bytes(session_id),
                    game_addr,
                    client_addr,
                    original_info.src_ip,
                    original_info.src_port
                );
            }
        }
    }
}

/// Handle a flow: receive packets from main loop, send to game server, receive responses
async fn run_flow_handler(
    flow_key: String,
    game_addr: SocketAddr,
    session_id: [u8; SESSION_ID_LEN],
    mut rx: mpsc::Receiver<Vec<u8>>,
    response_tx: ResponseTx,
    flows: Arc<DashMap<String, FlowEntry>>,
    sessions: Arc<DashMap<[u8; SESSION_ID_LEN], SocketAddr>>,
    stats: Arc<Stats>,
) {
    // Create socket for this flow
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            log::warn!("Failed to create flow socket: {}", e);
            flows.remove(&flow_key);
            return;
        }
    };

    // Connect to game server (for recv filtering)
    if let Err(e) = socket.connect(game_addr).await {
        log::warn!("Failed to connect to {}: {}", game_addr, e);
        flows.remove(&flow_key);
        return;
    }

    log::trace!("Flow {} started, local {}", flow_key, socket.local_addr().unwrap_or_else(|_| "?".parse().unwrap()));

    let mut recv_buf = [0u8; MAX_PACKET_SIZE];
    let mut consecutive_recv_errors: u32 = 0;
    let mut consecutive_send_errors: u32 = 0;

    loop {
        tokio::select! {
            // Receive packet from main loop to send to game server
            packet = rx.recv() => {
                match packet {
                    Some(data) => {
                        match socket.send(&data).await {
                            Ok(_) => {
                                consecutive_send_errors = 0;
                            }
                            Err(e) if is_transient_send_error(&e) => {
                                // Transient error (WouldBlock/TimedOut/Interrupted), ignore
                                continue;
                            }
                            Err(e) => {
                                consecutive_send_errors += 1;
                                log::debug!("Flow {} send error #{}: {} (kind={:?})", flow_key, consecutive_send_errors, e, e.kind());
                                if consecutive_send_errors >= 5 {
                                    break;
                                }
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                        }
                    }
                    None => {
                        // Channel closed
                        break;
                    }
                }
            }

            // Receive response from game server
            result = socket.recv(&mut recv_buf) => {
                match result {
                    Ok(len) => {
                        consecutive_recv_errors = 0;

                        // Look up current client address and original packet info
                        let (client_addr, original_info) = match flows.get(&flow_key) {
                            Some(entry) => (entry.client_addr, entry.original_info),
                            None => {
                                // Flow removed, try session fallback
                                if sessions.contains_key(&session_id) {
                                    log::warn!("Flow {} removed but session exists, skipping response", flow_key);
                                    continue;
                                }
                                break;
                            }
                        };

                        // Build response IP packet with swapped addresses
                        // Source = game server, Dest = client's original source
                        let response_ip_packet = build_response_ip_packet(
                            &recv_buf[..len],
                            original_info,
                        );

                        // Build final response: [session_id][IP packet]
                        let mut response = Vec::with_capacity(SESSION_ID_LEN + response_ip_packet.len());
                        response.extend_from_slice(&session_id);
                        response.extend_from_slice(&response_ip_packet);

                        // Send to client (non-blocking, track drops)
                        if response_tx.send((client_addr, response)).is_err() {
                            stats.dropped_out.fetch_add(1, Ordering::Relaxed);
                        }

                        // Update flow activity
                        if let Some(mut entry) = flows.get_mut(&flow_key) {
                            entry.last_activity = Instant::now();
                            entry.marked_for_removal = None; // Keep alive
                        }
                    }
                    Err(e) if is_transient_recv_error(&e) => {
                        // Transient error (WouldBlock/TimedOut/Interrupted/ConnectionReset), ignore and continue
                        continue;
                    }
                    Err(e) => {
                        consecutive_recv_errors += 1;
                        log::debug!("Flow {} recv error #{}: {} (kind={:?})", flow_key, consecutive_recv_errors, e, e.kind());
                        if consecutive_recv_errors >= 5 {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }

            // Idle timeout check
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                // Check if flow is still in map (cleanup task may have removed it)
                if !flows.contains_key(&flow_key) {
                    break;
                }
            }
        }
    }

    // Cleanup
    flows.remove(&flow_key);
    log::trace!("Flow {} ended", flow_key);
}

/// Parse an IP packet and extract destination, UDP payload, and original packet info
fn parse_ip_packet_full(packet: &[u8]) -> Option<(SocketAddr, &[u8], OriginalPacketInfo)> {
    if packet.len() < IP_HEADER_MIN {
        return None;
    }

    // Check IP version (should be 4)
    let version = (packet[0] >> 4) & 0x0F;
    if version != 4 {
        return None;
    }

    // Get IP header length (IHL field * 4)
    let ihl = (packet[0] & 0x0F) as usize * 4;
    if ihl < IP_HEADER_MIN || packet.len() < ihl {
        return None;
    }

    // Check protocol (should be UDP = 17)
    let protocol = packet[9];
    if protocol != 17 {
        return None;
    }

    // Extract source IP (bytes 12-15)
    let src_ip = std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);

    // Extract destination IP (bytes 16-19)
    let dst_ip = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    // Parse UDP header
    let udp_start = ihl;
    if packet.len() < udp_start + UDP_HEADER_SIZE {
        return None;
    }

    // Source port (bytes 0-1 of UDP header)
    let src_port = u16::from_be_bytes([packet[udp_start], packet[udp_start + 1]]);

    // Destination port (bytes 2-3 of UDP header)
    let dst_port = u16::from_be_bytes([packet[udp_start + 2], packet[udp_start + 3]]);

    // UDP payload starts after 8-byte UDP header
    let payload_start = udp_start + UDP_HEADER_SIZE;
    let payload = if packet.len() > payload_start {
        &packet[payload_start..]
    } else {
        &[]
    };

    let original_info = OriginalPacketInfo {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
    };

    Some((SocketAddr::from((dst_ip, dst_port)), payload, original_info))
}

/// Build a response IP packet from game server response
/// Swaps source/dest so response goes back to client
fn build_response_ip_packet(udp_payload: &[u8], original: OriginalPacketInfo) -> Vec<u8> {
    let udp_len = UDP_HEADER_SIZE + udp_payload.len();
    let total_len = IP_HEADER_MIN + udp_len;

    let mut packet = vec![0u8; total_len];

    // === IP Header (20 bytes) ===
    // Version (4) + IHL (5 = 20 bytes)
    packet[0] = 0x45;
    // DSCP + ECN
    packet[1] = 0;
    // Total length
    packet[2] = ((total_len >> 8) & 0xFF) as u8;
    packet[3] = (total_len & 0xFF) as u8;
    // Identification (random)
    let id = rand::random::<u16>();
    packet[4] = (id >> 8) as u8;
    packet[5] = (id & 0xFF) as u8;
    // Flags + Fragment offset (Don't Fragment)
    packet[6] = 0x40;
    packet[7] = 0;
    // TTL
    packet[8] = 64;
    // Protocol (UDP = 17)
    packet[9] = 17;
    // Header checksum (calculated below)
    packet[10] = 0;
    packet[11] = 0;
    // Source IP = game server (original destination)
    let src_octets = original.dst_ip.octets();
    packet[12..16].copy_from_slice(&src_octets);
    // Destination IP = client's tunnel IP (original source)
    let dst_octets = original.src_ip.octets();
    packet[16..20].copy_from_slice(&dst_octets);

    // Calculate IP header checksum
    let ip_checksum = calculate_ip_checksum(&packet[..IP_HEADER_MIN]);
    packet[10] = (ip_checksum >> 8) as u8;
    packet[11] = (ip_checksum & 0xFF) as u8;

    // === UDP Header (8 bytes) ===
    let udp_start = IP_HEADER_MIN;
    // Source port = game server port (original destination port)
    packet[udp_start] = (original.dst_port >> 8) as u8;
    packet[udp_start + 1] = (original.dst_port & 0xFF) as u8;
    // Destination port = client's port (original source port)
    packet[udp_start + 2] = (original.src_port >> 8) as u8;
    packet[udp_start + 3] = (original.src_port & 0xFF) as u8;
    // UDP length
    packet[udp_start + 4] = ((udp_len >> 8) & 0xFF) as u8;
    packet[udp_start + 5] = (udp_len & 0xFF) as u8;
    // UDP checksum (0 = disabled for IPv4)
    packet[udp_start + 6] = 0;
    packet[udp_start + 7] = 0;

    // === UDP Payload ===
    let payload_start = udp_start + UDP_HEADER_SIZE;
    packet[payload_start..].copy_from_slice(udp_payload);

    packet
}

/// Calculate IP header checksum (RFC 1071)
fn calculate_ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum 16-bit words
    for i in (0..header.len()).step_by(2) {
        let word = if i + 1 < header.len() {
            ((header[i] as u32) << 8) | (header[i + 1] as u32)
        } else {
            (header[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    !sum as u16
}

/// Generate random u16 (simple LCG for packet ID)
mod rand {
    use std::sync::atomic::{AtomicU32, Ordering};

    static SEED: AtomicU32 = AtomicU32::new(0);

    pub fn random<T>() -> T
    where
        T: From<u16>,
    {
        let mut seed = SEED.load(Ordering::Relaxed);
        if seed == 0 {
            seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u32;
        }
        // LCG: next = (a * seed + c) mod m
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        SEED.store(seed, Ordering::Relaxed);
        T::from((seed >> 16) as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip_packet_full() {
        // Build a test IPv4 UDP packet
        let mut packet = vec![0u8; 32];

        // IP version 4, IHL 5 (20 bytes)
        packet[0] = 0x45;
        // Protocol = UDP (17)
        packet[9] = 17;
        // Source IP = 10.0.0.5
        packet[12] = 10;
        packet[13] = 0;
        packet[14] = 0;
        packet[15] = 5;
        // Destination IP = 1.2.3.4
        packet[16] = 1;
        packet[17] = 2;
        packet[18] = 3;
        packet[19] = 4;
        // UDP source port = 54321 (0xD431)
        packet[20] = 0xD4;
        packet[21] = 0x31;
        // UDP dest port = 12345 (0x3039)
        packet[22] = 0x30;
        packet[23] = 0x39;
        // Payload
        packet[28..32].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let result = parse_ip_packet_full(&packet);
        assert!(result.is_some());

        let (addr, payload, info) = result.unwrap();
        assert_eq!(addr.ip().to_string(), "1.2.3.4");
        assert_eq!(addr.port(), 12345);
        assert_eq!(payload, &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(info.src_ip.to_string(), "10.0.0.5");
        assert_eq!(info.src_port, 54321);
        assert_eq!(info.dst_ip.to_string(), "1.2.3.4");
        assert_eq!(info.dst_port, 12345);
    }

    #[test]
    fn test_build_response_ip_packet() {
        let payload = &[0x01, 0x02, 0x03, 0x04];
        let original = OriginalPacketInfo {
            src_ip: "10.0.0.5".parse().unwrap(),
            src_port: 54321,
            dst_ip: "1.2.3.4".parse().unwrap(),
            dst_port: 12345,
        };

        let packet = build_response_ip_packet(payload, original);

        // Check total length
        assert_eq!(packet.len(), 20 + 8 + 4); // IP + UDP + payload

        // Check IP version
        assert_eq!((packet[0] >> 4) & 0x0F, 4);

        // Check protocol is UDP
        assert_eq!(packet[9], 17);

        // Check source IP is now game server (was destination)
        assert_eq!(&packet[12..16], &[1, 2, 3, 4]);

        // Check destination IP is now client (was source)
        assert_eq!(&packet[16..20], &[10, 0, 0, 5]);

        // Check source port is now game server port
        let src_port = u16::from_be_bytes([packet[20], packet[21]]);
        assert_eq!(src_port, 12345);

        // Check destination port is now client port
        let dst_port = u16::from_be_bytes([packet[22], packet[23]]);
        assert_eq!(dst_port, 54321);

        // Check payload
        assert_eq!(&packet[28..32], payload);
    }

    #[test]
    fn test_ip_checksum() {
        // Test vector from RFC 1071
        let header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
            0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
            0xc0, 0xa8, 0x00, 0xc7,
        ];
        let checksum = calculate_ip_checksum(&header);
        // The checksum should make the header sum to 0xFFFF
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_non_udp_rejected() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = 6; // TCP, not UDP

        assert!(parse_ip_packet_full(&packet).is_none());
    }
}
