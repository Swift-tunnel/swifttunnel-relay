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
//! - Datapath v1: Main task receives from clients and routes to per-flow tasks
//! - Datapath v2: Sharded event loop (mio) + buffer pool + single TX thread
//!
//! v1.5.0 Improvements:
//! - Optional sharded datapath (env RELAY_DATAPATH=v2) to cut jitter under load
//! - Optional control-plane ping/pong frames (0xA3/0xA4) for RTT/jitter measurement
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
use base64::engine::general_purpose::{
    STANDARD as BASE64_STANDARD, URL_SAFE as BASE64_URL_SAFE,
    URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD,
};
use base64::Engine as _;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::Deserialize;
use std::env;
use std::io::{ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::net::{Ipv4Addr, Shutdown};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::time::interval;

mod datapath_v2;
mod tcp_tun;

const SESSION_ID_LEN: usize = 8;
const DEFAULT_PORT: u16 = 51821;
const DEFAULT_STATS_PORT: u16 = 51822;
const MAX_HTTP_REQUEST_SIZE: usize = 8192;
const STATS_HTTP_READ_TIMEOUT_SECS: u64 = 5;
const STATS_HTTP_WRITE_TIMEOUT_SECS: u64 = 5;
const STATS_RATE_SAMPLE_MIN_MS: u64 = 1000;
const CONNECTION_SNAPSHOT_INTERVAL_MS: u64 = 1000;
const RELAY_VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTH_HELLO_FRAME_TYPE: u8 = 0xA1;
const AUTH_ACK_FRAME_TYPE: u8 = 0xA2;
// Control plane: RTT/jitter pings (optional, backward-compatible).
const PING_FRAME_TYPE: u8 = 0xA3;
const PONG_FRAME_TYPE: u8 = 0xA4;
const AUTH_ACK_OK: u8 = 0;
const AUTH_ACK_BAD_FORMAT: u8 = 1;
const AUTH_ACK_BAD_SIGNATURE: u8 = 2;
const AUTH_ACK_EXPIRED: u8 = 3;
const AUTH_ACK_SID_MISMATCH: u8 = 4;
const AUTH_ACK_SERVER_MISMATCH: u8 = 5;
const AUTH_ACK_AUTH_DISABLED: u8 = 6;
const MAX_AUTH_TOKEN_LEN: usize = 4096;
const AUTH_CLOCK_SKEW_SECS: u64 = 30;
const PING_FRAME_LEN: usize = SESSION_ID_LEN + 1 + 4 + 8;
const PONG_FRAME_LEN: usize = SESSION_ID_LEN + 1 + 4 + 8 + 8;
/// Client-reported RTT (optional, backward-compatible).
const RTT_REPORT_FRAME_TYPE: u8 = 0xA5;
/// [session_id:8][0xA5][rtt_us_be_u32] = 13 bytes
const RTT_REPORT_FRAME_LEN: usize = SESSION_ID_LEN + 1 + 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayAuthMode {
    Off,
    Optional,
    Required,
}

impl RelayAuthMode {
    fn from_env(value: Option<String>) -> Self {
        match value
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("required") => Self::Required,
            Some("optional") => Self::Optional,
            _ => Self::Off,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Optional => "optional",
            Self::Required => "required",
        }
    }

    fn requires_auth(self) -> bool {
        matches!(self, Self::Required)
    }
}

#[derive(Clone)]
struct RelayAuthConfig {
    mode: RelayAuthMode,
    public_key: Option<Vec<u8>>,
    server_id: Option<String>,
}

impl RelayAuthConfig {
    fn from_env() -> Result<Self> {
        let mode = RelayAuthMode::from_env(env::var("RELAY_AUTH_MODE").ok());
        if mode == RelayAuthMode::Off {
            return Ok(Self {
                mode,
                public_key: None,
                server_id: None,
            });
        }

        let key_b64 = env::var("RELAY_AUTH_PUBLIC_KEY_B64")
            .context("RELAY_AUTH_PUBLIC_KEY_B64 is required when RELAY_AUTH_MODE != off")?;
        let key_bytes = decode_base64_flexible(key_b64.trim())
            .context("RELAY_AUTH_PUBLIC_KEY_B64 is not valid base64/base64url")?;
        if key_bytes.len() != 32 {
            anyhow::bail!(
                "RELAY_AUTH_PUBLIC_KEY_B64 must decode to 32 bytes (got {})",
                key_bytes.len()
            );
        }

        let server_id = env::var("RELAY_SERVER_ID")
            .context("RELAY_SERVER_ID is required when RELAY_AUTH_MODE != off")?;
        if server_id.trim().is_empty() {
            anyhow::bail!("RELAY_SERVER_ID cannot be empty");
        }

        Ok(Self {
            mode,
            public_key: Some(key_bytes),
            server_id: Some(server_id),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionAuthState {
    Legacy,
    Authenticated,
}

impl SessionAuthState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Authenticated => "authenticated",
        }
    }
}

#[derive(Debug, Deserialize)]
struct RelayTicketClaims {
    v: u8,
    iss: String,
    aud: String,
    sub: String,
    sid: String,
    srv: String,
    iat: u64,
    exp: u64,
    #[allow(dead_code)]
    jti: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayAuthVerifyError {
    BadFormat,
    BadSignature,
    Expired,
    SidMismatch,
    ServerMismatch,
}

impl RelayAuthVerifyError {
    fn ack_status(self) -> u8 {
        match self {
            Self::BadFormat => AUTH_ACK_BAD_FORMAT,
            Self::BadSignature => AUTH_ACK_BAD_SIGNATURE,
            Self::Expired => AUTH_ACK_EXPIRED,
            Self::SidMismatch => AUTH_ACK_SID_MISMATCH,
            Self::ServerMismatch => AUTH_ACK_SERVER_MISMATCH,
        }
    }
}

/// Get listen port from RELAY_PORT env var or use default
fn get_listen_port() -> u16 {
    env::var("RELAY_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PORT)
}

/// Get localhost stats port from RELAY_STATS_PORT env var or use default
fn get_stats_port() -> u16 {
    env::var("RELAY_STATS_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_STATS_PORT)
}

/// Get stats API token from RELAY_STATS_TOKEN env var
fn get_stats_token() -> Option<String> {
    env::var("RELAY_STATS_TOKEN").ok().and_then(|token| {
        if token.trim().is_empty() {
            None
        } else {
            Some(token)
        }
    })
}

fn decode_base64_flexible(input: &str) -> Option<Vec<u8>> {
    BASE64_URL_SAFE_NO_PAD
        .decode(input)
        .ok()
        .or_else(|| BASE64_URL_SAFE.decode(input).ok())
        .or_else(|| BASE64_STANDARD.decode(input).ok())
}

fn verify_relay_ticket(
    token: &str,
    session_id: [u8; SESSION_ID_LEN],
    auth: &RelayAuthConfig,
    now_unix: u64,
) -> Result<String, RelayAuthVerifyError> {
    if token.is_empty() || token.len() > MAX_AUTH_TOKEN_LEN {
        return Err(RelayAuthVerifyError::BadFormat);
    }

    let (payload_b64, signature_b64) = token
        .split_once('.')
        .ok_or(RelayAuthVerifyError::BadFormat)?;
    let payload = decode_base64_flexible(payload_b64).ok_or(RelayAuthVerifyError::BadFormat)?;
    let signature = decode_base64_flexible(signature_b64).ok_or(RelayAuthVerifyError::BadFormat)?;

    if signature.len() != 64 {
        return Err(RelayAuthVerifyError::BadFormat);
    }

    let public_key = auth
        .public_key
        .as_deref()
        .ok_or(RelayAuthVerifyError::BadFormat)?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&payload, &signature)
        .map_err(|_| RelayAuthVerifyError::BadSignature)?;

    let claims: RelayTicketClaims =
        serde_json::from_slice(&payload).map_err(|_| RelayAuthVerifyError::BadFormat)?;
    if claims.v != 1 {
        return Err(RelayAuthVerifyError::BadFormat);
    }
    if claims.iss != "swifttunnel-web" || claims.aud != "swifttunnel-relay" || claims.sub.is_empty()
    {
        return Err(RelayAuthVerifyError::BadFormat);
    }

    let expected_sid = format!("{:016x}", u64::from_be_bytes(session_id));
    if claims.sid != expected_sid {
        return Err(RelayAuthVerifyError::SidMismatch);
    }

    let expected_server = auth
        .server_id
        .as_deref()
        .ok_or(RelayAuthVerifyError::BadFormat)?;
    if claims.srv != expected_server {
        return Err(RelayAuthVerifyError::ServerMismatch);
    }

    if claims.iat > now_unix.saturating_add(AUTH_CLOCK_SKEW_SECS) {
        return Err(RelayAuthVerifyError::BadFormat);
    }
    if now_unix > claims.exp.saturating_add(AUTH_CLOCK_SKEW_SECS) {
        return Err(RelayAuthVerifyError::Expired);
    }

    Ok(claims.sub)
}

fn parse_auth_hello_token(frame: &[u8], len: usize) -> Result<&str, RelayAuthVerifyError> {
    if len < SESSION_ID_LEN + 3 {
        return Err(RelayAuthVerifyError::BadFormat);
    }

    let token_len = u16::from_be_bytes([frame[SESSION_ID_LEN + 1], frame[SESSION_ID_LEN + 2]]);
    let token_len = token_len as usize;
    let payload_start = SESSION_ID_LEN + 3;
    let payload_end = payload_start + token_len;

    if token_len == 0 || token_len > MAX_AUTH_TOKEN_LEN || payload_end > len || payload_end != len {
        return Err(RelayAuthVerifyError::BadFormat);
    }

    std::str::from_utf8(&frame[payload_start..payload_end])
        .map_err(|_| RelayAuthVerifyError::BadFormat)
}

async fn send_auth_ack(
    socket: &UdpSocket,
    client_addr: SocketAddr,
    session_id: [u8; SESSION_ID_LEN],
    status: u8,
) {
    let mut packet = [0u8; SESSION_ID_LEN + 2];
    packet[..SESSION_ID_LEN].copy_from_slice(&session_id);
    packet[SESSION_ID_LEN] = AUTH_ACK_FRAME_TYPE;
    packet[SESSION_ID_LEN + 1] = status;
    if let Err(e) = socket.send_to(&packet, client_addr).await {
        log::debug!("Failed to send auth ack to {}: {}", client_addr, e);
    }
}
/// Session timeout increased from 60s to 180s to survive network hiccups
const SESSION_TIMEOUT: Duration = Duration::from_secs(180);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
/// Grace period before fully removing a flow (allows late packets)
const FLOW_GRACE_PERIOD: Duration = Duration::from_secs(30);
const MAX_PACKET_SIZE: usize = 1600;
/// Channel capacity per flow (prevents OOM, games handle packet loss)
const DEFAULT_FLOW_CHANNEL_CAPACITY: usize = 256;
const MIN_FLOW_CHANNEL_CAPACITY: usize = 8;
const MAX_FLOW_CHANNEL_CAPACITY: usize = 4096;

/// Minimum IP header size
pub(crate) const IP_HEADER_MIN: usize = 20;
/// UDP header size
const UDP_HEADER_SIZE: usize = 8;

/// Channel for sending packets to a flow (bounded for backpressure)
type FlowTx = mpsc::Sender<Vec<u8>>;

/// Channel for sending responses back to clients
type ResponseTx = mpsc::UnboundedSender<(SocketAddr, [u8; SESSION_ID_LEN], Vec<u8>)>;

/// Check if a receive error is transient and can be ignored
fn is_transient_recv_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::WouldBlock
            | ErrorKind::TimedOut
            | ErrorKind::Interrupted
            | ErrorKind::ConnectionReset // Can happen spuriously on recv
    )
}

/// Check if a send error is transient and can be ignored
/// NOTE: ConnectionReset on send = ICMP port unreachable = game server down
fn is_transient_send_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted // ConnectionReset on send is NOT transient - game server unreachable
    )
}

fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

fn mono_timestamp_ms() -> u64 {
    use std::sync::OnceLock;

    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

fn parse_flow_channel_capacity(raw: Option<String>) -> usize {
    let parsed = raw
        .as_deref()
        .map(str::trim)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_FLOW_CHANNEL_CAPACITY);
    parsed.clamp(MIN_FLOW_CHANNEL_CAPACITY, MAX_FLOW_CHANNEL_CAPACITY)
}

fn get_flow_channel_capacity() -> usize {
    parse_flow_channel_capacity(env::var("RELAY_FLOW_CHANNEL_CAPACITY").ok())
}

/// Default identity until we observe a tunnel source IP or strict auth identity.
fn derive_user_id(session_id: [u8; SESSION_ID_LEN]) -> String {
    format!("session-{:016x}", u64::from_be_bytes(session_id))
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

/// Session metadata tracked by the relay
struct SessionEntry {
    user_id: String,
    auth_state: SessionAuthState,
    client_addr: SocketAddr,
    created_at_unix: u64,
    last_activity: Instant,
    last_activity_unix: u64,
}

/// Session traffic counters used by local stats API
struct SessionTraffic {
    connected_at_unix: u64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    packets_in: AtomicU64,
    packets_out: AtomicU64,
    last_activity_unix: AtomicU64,
    /// Last client-reported RTT in microseconds (via 0xA5 frame)
    last_rtt_us: AtomicU64,
}

impl SessionTraffic {
    fn new(connected_at_unix: u64) -> Self {
        Self {
            connected_at_unix,
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            packets_in: AtomicU64::new(0),
            packets_out: AtomicU64::new(0),
            last_activity_unix: AtomicU64::new(connected_at_unix),
            last_rtt_us: AtomicU64::new(0),
        }
    }
}

/// Update per-session traffic counters without keeping a `DashMap` guard alive.
///
/// The relay must never hold a `session_traffic` shard lock while touching the
/// live `sessions` map. Cleanup and snapshot tasks lock those maps in the
/// opposite order, so retaining a traffic entry guard across later session-map
/// work can wedge the datapath.
fn record_session_ingress(
    session_traffic: &DashMap<[u8; SESSION_ID_LEN], Arc<SessionTraffic>>,
    session_id: [u8; SESSION_ID_LEN],
    connected_at_unix: u64,
    packet_len: usize,
) {
    let traffic = {
        let entry = session_traffic
            .entry(session_id)
            .or_insert_with(|| Arc::new(SessionTraffic::new(connected_at_unix)));
        Arc::clone(entry.value())
    };

    traffic
        .bytes_in
        .fetch_add(packet_len as u64, Ordering::Relaxed);
    traffic.packets_in.fetch_add(1, Ordering::Relaxed);
    traffic
        .last_activity_unix
        .store(connected_at_unix, Ordering::Relaxed);
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

struct StatsApiContext {
    sessions: Arc<DashMap<[u8; SESSION_ID_LEN], SessionEntry>>,
    session_traffic: Arc<DashMap<[u8; SESSION_ID_LEN], Arc<SessionTraffic>>>,
    stats: Arc<Stats>,
    started_at: Instant,
    rate_window: Mutex<StatsRateWindow>,
    connections_snapshot: RwLock<String>,
}

struct StatsRateWindow {
    last_sample_at: Option<Instant>,
    last_bytes_in: u64,
    last_bytes_out: u64,
    inbound_bps: u64,
    outbound_bps: u64,
}

impl StatsRateWindow {
    fn new() -> Self {
        Self {
            last_sample_at: None,
            last_bytes_in: 0,
            last_bytes_out: 0,
            inbound_bps: 0,
            outbound_bps: 0,
        }
    }
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
    /// Users currently in throttled state (reserved for quota integration)
    throttled_users: AtomicU64,
    /// TCP packets forwarded to the TUN handler
    tcp_forwarded: AtomicU64,
    /// UDP IPv4 packets forwarded to the TUN handler
    tun_udp_forwarded: AtomicU64,
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
            throttled_users: AtomicU64::new(0),
            tcp_forwarded: AtomicU64::new(0),
            tun_udp_forwarded: AtomicU64::new(0),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let listen_port = get_listen_port();
    let stats_port = get_stats_port();
    let stats_token = get_stats_token();
    let auth_config = RelayAuthConfig::from_env()?;
    let datapath = datapath_v2::get_relay_datapath();

    let stats = Arc::new(Stats::new());
    let started_at = Instant::now();
    let session_traffic: Arc<DashMap<[u8; SESSION_ID_LEN], Arc<SessionTraffic>>> =
        Arc::new(DashMap::new());

    log::info!("╔════════════════════════════════════════════╗");
    log::info!("║     SwiftTunnel V3 UDP Relay v{}        ║", RELAY_VERSION);
    log::info!("║     Low Latency Game Packet Forwarding     ║");
    log::info!("╚════════════════════════════════════════════╝");

    // Bind the main UDP socket early so the TUN response thread can share it.
    // Reuse the existing datapath-v2 helper so RELAY_SOCKET_RCVBUF_BYTES /
    // RELAY_SOCKET_SNDBUF_BYTES tuning still applies.
    let main_std_socket = datapath_v2::bind_main_socket(listen_port)?;
    log::info!("Listening on 0.0.0.0:{}", listen_port);

    // TUN-backed forwarding (opt-in).
    let mut tcp_enabled = env::var("RELAY_TCP_ENABLED")
        .ok()
        .map(|v| v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let mut tun_udp_enabled = env::var("RELAY_TUN_UDP")
        .ok()
        .map(|v| v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let tun_session_cleanup: Option<tcp_tun::TunSessionCleanup>;
    let tun_tx_sender: Option<crossbeam_channel::Sender<tcp_tun::InboundTunPacket>> =
        if tcp_enabled || tun_udp_enabled {
            log::info!(
                "TUN forwarding enabled (RELAY_TCP_ENABLED={}, RELAY_TUN_UDP={})",
                tcp_enabled,
                tun_udp_enabled
            );
            // Bounded to prevent OOM if the response thread falls behind.
            let (tcp_response_tx, tcp_response_rx) =
                crossbeam_channel::bounded::<tcp_tun::TxPacket>(4096);
            match tcp_tun::TunHandler::new(tcp_response_tx) {
                Ok((handler, sender, tun_cleanup)) => {
                    // Spawn the TUN handler on its own thread.
                    std::thread::Builder::new()
                        .name("relay-tun".into())
                        .spawn(move || handler.run())
                        .expect("Failed to spawn relay TUN handler");

                    // Clone the main socket so TUN responses go out on port 51821.
                    let resp_socket = main_std_socket
                        .try_clone()
                        .expect("Failed to clone main socket for TUN responses");

                    // Spawn a thread that drains TUN response packets and sends
                    // them back to clients via the main relay socket.
                    let stats_tun_resp = Arc::clone(&stats);
                    let session_traffic_tun_resp = Arc::clone(&session_traffic);
                    std::thread::Builder::new()
                        .name("relay-tun-resp".into())
                        .spawn(move || {
                            while let Ok(tx_pkt) = tcp_response_rx.recv() {
                                // Build relay frame: [session_id][ip_packet]
                                let mut frame =
                                    Vec::with_capacity(SESSION_ID_LEN + tx_pkt.ip_packet.len());
                                frame.extend_from_slice(&tx_pkt.session_id);
                                frame.extend_from_slice(&tx_pkt.ip_packet);
                                if let Err(e) = resp_socket.send_to(&frame, tx_pkt.client_addr) {
                                    log::trace!(
                                        "TCP response send error to {}: {}",
                                        tx_pkt.client_addr,
                                        e
                                    );
                                } else {
                                    let len = frame.len() as u64;
                                    stats_tun_resp.packets_out.fetch_add(1, Ordering::Relaxed);
                                    stats_tun_resp.bytes_out.fetch_add(len, Ordering::Relaxed);
                                    if let Some(entry) =
                                        session_traffic_tun_resp.get(&tx_pkt.session_id)
                                    {
                                        entry.value().bytes_out.fetch_add(len, Ordering::Relaxed);
                                        entry.value().packets_out.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                        })
                        .expect("Failed to spawn TUN response thread");

                    tun_session_cleanup = Some(tun_cleanup);
                    Some(sender)
                }
                Err(e) => {
                    log::error!(
                        "Failed to create relay TUN handler: {}. TUN forwarding disabled.",
                        e
                    );
                    tcp_enabled = false;
                    tun_udp_enabled = false;
                    tun_session_cleanup = None;
                    None
                }
            }
        } else {
            log::info!(
                "TUN forwarding disabled (set RELAY_TCP_ENABLED=true and/or RELAY_TUN_UDP=true)"
            );
            tun_session_cleanup = None;
            None
        };

    if matches!(datapath, datapath_v2::RelayDatapath::V2) {
        return datapath_v2::run_datapath_v2(
            main_std_socket,
            stats_port,
            stats_token,
            auth_config,
            stats,
            started_at,
            tun_tx_sender,
            tun_session_cleanup,
            tun_udp_enabled,
            tcp_enabled,
            session_traffic,
        )
        .await;
    }

    log::info!("Relay datapath: v1 (tokio per-flow tasks)");

    let flow_channel_capacity = get_flow_channel_capacity();

    // Convert std socket to tokio async socket for v1 datapath.
    main_std_socket
        .set_nonblocking(true)
        .context("Failed to set non-blocking for tokio")?;
    let socket =
        UdpSocket::from_std(main_std_socket).context("Failed to convert to tokio UdpSocket")?;

    if stats_token.is_some() {
        log::info!("Local stats API enabled on 127.0.0.1:{}", stats_port);
    } else {
        log::warn!(
            "Local stats API disabled (set RELAY_STATS_TOKEN to enable localhost endpoints)"
        );
    }
    log::info!("Relay auth mode: {}", auth_config.mode.as_str());
    log::info!(
        "Flow channel capacity: {} (env RELAY_FLOW_CHANNEL_CAPACITY)",
        flow_channel_capacity
    );

    let socket = Arc::new(socket);

    // Session tracking
    let sessions: Arc<DashMap<[u8; SESSION_ID_LEN], SessionEntry>> = Arc::new(DashMap::new());

    // Flow tracking: "session_hex:game_addr" -> FlowEntry
    let flows: Arc<DashMap<String, FlowEntry>> = Arc::new(DashMap::new());

    if let Some(token) = stats_token {
        let ctx = Arc::new(StatsApiContext {
            sessions: Arc::clone(&sessions),
            session_traffic: Arc::clone(&session_traffic),
            stats: Arc::clone(&stats),
            started_at,
            rate_window: Mutex::new(StatsRateWindow::new()),
            connections_snapshot: RwLock::new(empty_connections_payload()),
        });

        spawn_connections_snapshot_updater(Arc::clone(&ctx));
        tokio::spawn(async move {
            if let Err(e) = run_stats_http_server(stats_port, token, ctx).await {
                log::error!("Stats API server error: {}", e);
            }
        });
    }

    // Channel for sending responses back to clients
    let (response_tx, mut response_rx) =
        mpsc::unbounded_channel::<(SocketAddr, [u8; SESSION_ID_LEN], Vec<u8>)>();

    // Spawn response sender task
    let socket_sender = Arc::clone(&socket);
    let stats_out = Arc::clone(&stats);
    let session_traffic_out = Arc::clone(&session_traffic);
    tokio::spawn(async move {
        while let Some((addr, session_id, data)) = response_rx.recv().await {
            if let Err(e) = socket_sender.send_to(&data, addr).await {
                log::warn!("Failed to send response to {}: {}", addr, e);
            } else {
                stats_out.packets_out.fetch_add(1, Ordering::Relaxed);
                stats_out
                    .bytes_out
                    .fetch_add(data.len() as u64, Ordering::Relaxed);
                if let Some(entry) = session_traffic_out.get(&session_id) {
                    entry
                        .value()
                        .bytes_out
                        .fetch_add(data.len() as u64, Ordering::Relaxed);
                    entry.value().packets_out.fetch_add(1, Ordering::Relaxed);
                    entry
                        .value()
                        .last_activity_unix
                        .store(unix_timestamp_secs(), Ordering::Relaxed);
                }
            }
        }
    });

    // Spawn cleanup task with soft-delete grace period
    let sessions_cleanup = Arc::clone(&sessions);
    let flows_cleanup = Arc::clone(&flows);
    let stats_cleanup = Arc::clone(&stats);
    let session_traffic_cleanup = Arc::clone(&session_traffic);
    let tcp_cleanup = tun_session_cleanup;
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
                    log::debug!(
                        "Marking flow {} for removal (idle {}s)",
                        key,
                        idle_time.as_secs()
                    );
                    marked_count += 1;
                }
                true
            });

            let mut sessions_removed = 0u32;
            let session_idle_limit = SESSION_TIMEOUT + FLOW_GRACE_PERIOD;
            sessions_cleanup.retain(|session_id, session| {
                if now.duration_since(session.last_activity) >= session_idle_limit {
                    session_traffic_cleanup.remove(session_id);
                    sessions_removed += 1;
                    stats_cleanup
                        .active_sessions
                        .fetch_sub(1, Ordering::Relaxed);
                    return false;
                }
                true
            });

            // Clean up TCP TUN session mappings for expired sessions.
            if let Some(ref tcp) = tcp_cleanup {
                tcp.remove_expired(|sid| sessions_cleanup.contains_key(sid));
            }

            // Update stats
            stats_cleanup
                .active_flows
                .store(flows_cleanup.len() as u64, Ordering::Relaxed);

            if removed_count > 0 || marked_count > 0 || revived_count > 0 || sessions_removed > 0 {
                log::info!(
                    "Cleanup: marked={}, revived={}, removed={}, session_removed={}, sessions={}, flows={}",
                    marked_count,
                    revived_count,
                    removed_count,
                    sessions_removed,
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

        let now = Instant::now();
        let now_unix = unix_timestamp_secs();

        // Update session
        let mut session_authenticated = false;
        match sessions.entry(session_id) {
            Entry::Occupied(mut entry) => {
                let session = entry.get_mut();
                session.client_addr = client_addr;
                session.last_activity = now;
                session.last_activity_unix = now_unix;
                session_authenticated =
                    matches!(session.auth_state, SessionAuthState::Authenticated);
            }
            Entry::Vacant(entry) => {
                entry.insert(SessionEntry {
                    user_id: derive_user_id(session_id),
                    auth_state: SessionAuthState::Legacy,
                    client_addr,
                    created_at_unix: now_unix,
                    last_activity: now,
                    last_activity_unix: now_unix,
                });
                stats.active_sessions.fetch_add(1, Ordering::Relaxed);
            }
        }

        record_session_ingress(&session_traffic, session_id, now_unix, len);

        // Auth hello control frame:
        // [session_id:8][0xA1][token_len_be_u16][token_utf8]
        if len >= SESSION_ID_LEN + 3 && buf[SESSION_ID_LEN] == AUTH_HELLO_FRAME_TYPE {
            if auth_config.mode == RelayAuthMode::Off {
                send_auth_ack(
                    socket.as_ref(),
                    client_addr,
                    session_id,
                    AUTH_ACK_AUTH_DISABLED,
                )
                .await;
                continue;
            }

            let token = match parse_auth_hello_token(&buf, len) {
                Ok(value) => value,
                Err(err) => {
                    send_auth_ack(socket.as_ref(), client_addr, session_id, err.ack_status()).await;
                    continue;
                }
            };

            match verify_relay_ticket(token, session_id, &auth_config, now_unix) {
                Ok(user_id) => {
                    if let Some(mut session_entry) = sessions.get_mut(&session_id) {
                        session_entry.user_id = user_id;
                        session_entry.auth_state = SessionAuthState::Authenticated;
                    }
                    send_auth_ack(socket.as_ref(), client_addr, session_id, AUTH_ACK_OK).await;
                }
                Err(err) => {
                    send_auth_ack(socket.as_ref(), client_addr, session_id, err.ack_status()).await;
                }
            }
            continue;
        }

        // RTT/jitter ping:
        // [session_id:8][0xA3][seq_be_u32][client_ts_mono_ms_be_u64]
        if len == PING_FRAME_LEN && buf[SESSION_ID_LEN] == PING_FRAME_TYPE {
            if auth_config.mode.requires_auth() && !session_authenticated {
                stats.dropped_in.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            let seq = u32::from_be_bytes([
                buf[SESSION_ID_LEN + 1],
                buf[SESSION_ID_LEN + 2],
                buf[SESSION_ID_LEN + 3],
                buf[SESSION_ID_LEN + 4],
            ]);
            let client_ts_mono_ms = u64::from_be_bytes([
                buf[SESSION_ID_LEN + 5],
                buf[SESSION_ID_LEN + 6],
                buf[SESSION_ID_LEN + 7],
                buf[SESSION_ID_LEN + 8],
                buf[SESSION_ID_LEN + 9],
                buf[SESSION_ID_LEN + 10],
                buf[SESSION_ID_LEN + 11],
                buf[SESSION_ID_LEN + 12],
            ]);
            let server_rx_ts_mono_ms = mono_timestamp_ms();

            let mut response = [0u8; PONG_FRAME_LEN];
            response[..SESSION_ID_LEN].copy_from_slice(&session_id);
            response[SESSION_ID_LEN] = PONG_FRAME_TYPE;
            response[SESSION_ID_LEN + 1..SESSION_ID_LEN + 5].copy_from_slice(&seq.to_be_bytes());
            response[SESSION_ID_LEN + 5..SESSION_ID_LEN + 13]
                .copy_from_slice(&client_ts_mono_ms.to_be_bytes());
            response[SESSION_ID_LEN + 13..SESSION_ID_LEN + 21]
                .copy_from_slice(&server_rx_ts_mono_ms.to_be_bytes());

            if let Err(e) = socket.send_to(&response, client_addr).await {
                log::trace!("Failed to send pong to {}: {}", client_addr, e);
            } else {
                stats.packets_out.fetch_add(1, Ordering::Relaxed);
                stats
                    .bytes_out
                    .fetch_add(response.len() as u64, Ordering::Relaxed);
                if let Some(entry) = session_traffic.get(&session_id) {
                    entry
                        .value()
                        .bytes_out
                        .fetch_add(response.len() as u64, Ordering::Relaxed);
                    entry.value().packets_out.fetch_add(1, Ordering::Relaxed);
                }
            }

            continue;
        }

        // Ignore unexpected pong frames from clients (defensive).
        if len == PONG_FRAME_LEN && buf[SESSION_ID_LEN] == PONG_FRAME_TYPE {
            continue;
        }

        // Client-reported RTT: [session_id:8][0xA5][rtt_us_be_u32]
        if len == RTT_REPORT_FRAME_LEN && buf[SESSION_ID_LEN] == RTT_REPORT_FRAME_TYPE {
            if auth_config.mode.requires_auth() && !session_authenticated {
                stats.dropped_in.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let rtt_us = u32::from_be_bytes([
                buf[SESSION_ID_LEN + 1],
                buf[SESSION_ID_LEN + 2],
                buf[SESSION_ID_LEN + 3],
                buf[SESSION_ID_LEN + 4],
            ]);
            if let Some(entry) = session_traffic.get(&session_id) {
                entry
                    .value()
                    .last_rtt_us
                    .store(rtt_us as u64, Ordering::Relaxed);
            }
            continue;
        }

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
                log::trace!(
                    "Keepalive refreshed {} flows for session {:016x}",
                    flows_refreshed,
                    u64::from_be_bytes(session_id)
                );
            }

            continue;
        }

        if auth_config.mode.requires_auth() && !session_authenticated {
            stats.dropped_in.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        // Need enough for IP header
        if len < SESSION_ID_LEN + IP_HEADER_MIN {
            continue;
        }

        // Parse IP packet
        let ip_packet = &buf[SESSION_ID_LEN..len];
        let parsed = match parse_ip_packet_full(ip_packet) {
            Some(p) => p,
            None => continue,
        };

        match parsed {
            ParsedPacket::Tcp {
                original_info,
                raw_ip_packet,
            } => {
                if tcp_enabled {
                    if let Some(ref tun_sender) = tun_tx_sender {
                        let _ = tun_sender.try_send(tcp_tun::InboundTunPacket {
                            session_id,
                            client_addr,
                            raw_ip_packet: raw_ip_packet.to_vec(),
                        });
                        stats.tcp_forwarded.fetch_add(1, Ordering::Relaxed);
                    }
                }
                // Update session user_id for TCP too
                if let Some(mut session_entry) = sessions.get_mut(&session_id) {
                    if !matches!(session_entry.auth_state, SessionAuthState::Authenticated) {
                        session_entry.user_id = original_info.src_ip.to_string();
                    }
                }
                continue;
            }
            ParsedPacket::Udp {
                game_addr,
                payload: udp_payload,
                original_info,
            } => {
                if tun_udp_enabled {
                    if let Some(ref tun_sender) = tun_tx_sender {
                        let _ = tun_sender.try_send(tcp_tun::InboundTunPacket {
                            session_id,
                            client_addr,
                            raw_ip_packet: ip_packet.to_vec(),
                        });
                        stats.tun_udp_forwarded.fetch_add(1, Ordering::Relaxed);
                    } else {
                        stats.dropped_in.fetch_add(1, Ordering::Relaxed);
                    }
                    if let Some(mut session_entry) = sessions.get_mut(&session_id) {
                        if !matches!(session_entry.auth_state, SessionAuthState::Authenticated) {
                            session_entry.user_id = original_info.src_ip.to_string();
                        }
                    }
                    continue;
                }

                // In legacy mode, use tunnel source IP as best-effort user identity.
                if let Some(mut session_entry) = sessions.get_mut(&session_id) {
                    if !matches!(session_entry.auth_state, SessionAuthState::Authenticated) {
                        session_entry.user_id = original_info.src_ip.to_string();
                    }
                }

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
                        let (tx, rx) = mpsc::channel(flow_channel_capacity);

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
    sessions: Arc<DashMap<[u8; SESSION_ID_LEN], SessionEntry>>,
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

    log::trace!(
        "Flow {} started, local {}",
        flow_key,
        socket.local_addr().unwrap_or_else(|_| "?".parse().unwrap())
    );

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
                        if response_tx.send((client_addr, session_id, response)).is_err() {
                            stats.dropped_out.fetch_add(1, Ordering::Relaxed);
                        }

                        // Update flow activity
                        if let Some(mut entry) = flows.get_mut(&flow_key) {
                            entry.last_activity = Instant::now();
                            entry.marked_for_removal = None; // Keep alive
                        }
                        if let Some(mut session_entry) = sessions.get_mut(&session_id) {
                            session_entry.last_activity = Instant::now();
                            session_entry.last_activity_unix = unix_timestamp_secs();
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

async fn run_stats_http_server(
    port: u16,
    token: String,
    context: Arc<StatsApiContext>,
) -> Result<()> {
    std::thread::Builder::new()
        .name(format!("stats-http-{}", port))
        .spawn(move || {
            if let Err(e) = run_stats_http_server_blocking(port, token, context) {
                log::error!("Stats API server error: {}", e);
            }
        })
        .context("Failed to spawn stats API server thread")?;

    Ok(())
}

fn run_stats_http_server_blocking(
    port: u16,
    token: String,
    context: Arc<StatsApiContext>,
) -> Result<()> {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .context("Failed to bind stats API listener")?;
    listener
        .set_nonblocking(false)
        .context("Failed to set stats API listener blocking mode")?;

    log::info!("Stats API listening on 127.0.0.1:{}", port);

    loop {
        let (stream, addr) = listener
            .accept()
            .context("Failed to accept stats API client")?;
        let token = token.clone();
        let context = Arc::clone(&context);

        std::thread::Builder::new()
            .name("stats-http-client".into())
            .spawn(move || {
                if let Err(e) = handle_stats_http_client_blocking(stream, &token, context) {
                    log::debug!("Stats API client {} error: {}", addr, e);
                }
            })
            .context("Failed to spawn stats API client thread")?;
    }
}

fn handle_stats_http_client_blocking(
    mut stream: std::net::TcpStream,
    token: &str,
    context: Arc<StatsApiContext>,
) -> Result<()> {
    let result = (|| -> Result<()> {
        stream
            .set_nonblocking(false)
            .context("Failed to set stats API stream blocking mode")?;
        stream
            .set_read_timeout(Some(Duration::from_secs(STATS_HTTP_READ_TIMEOUT_SECS)))
            .context("Failed to set stats API read timeout")?;
        stream
            .set_write_timeout(Some(Duration::from_secs(STATS_HTTP_WRITE_TIMEOUT_SECS)))
            .context("Failed to set stats API write timeout")?;

        let mut request_buf = [0u8; MAX_HTTP_REQUEST_SIZE];
        let mut total_read = 0usize;
        let mut header_complete = false;

        loop {
            if total_read >= MAX_HTTP_REQUEST_SIZE {
                write_http_response_blocking(
                    &mut stream,
                    431,
                    "Request Header Fields Too Large",
                    "{\"error\":\"request_too_large\"}",
                )?;
                return Ok(());
            }

            let read_len = match stream.read(&mut request_buf[total_read..]) {
                Ok(0) => break,
                Ok(read_len) => read_len,
                Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                    write_http_response_blocking(
                        &mut stream,
                        408,
                        "Request Timeout",
                        "{\"error\":\"request_timeout\"}",
                    )?;
                    return Ok(());
                }
                Err(e) => {
                    return Err(e).context("Failed to read stats API request");
                }
            };

            total_read += read_len;

            if find_http_header_end(&request_buf[..total_read]).is_some() {
                header_complete = true;
                break;
            }
        }

        if total_read == 0 {
            return Ok(());
        }

        if !header_complete {
            write_http_response_blocking(
                &mut stream,
                400,
                "Bad Request",
                "{\"error\":\"incomplete_request_headers\"}",
            )?;
            return Ok(());
        }

        let header_end = find_http_header_end(&request_buf[..total_read]).unwrap_or(total_read);
        let request = String::from_utf8_lossy(&request_buf[..header_end]);
        let mut lines = request.split("\r\n");
        let request_line = lines.next().unwrap_or("");
        let mut request_parts = request_line.split_whitespace();
        let method = request_parts.next().unwrap_or("");
        let path = request_parts.next().unwrap_or("");

        if method.is_empty() || path.is_empty() {
            write_http_response_blocking(
                &mut stream,
                400,
                "Bad Request",
                "{\"error\":\"bad_request_line\"}",
            )?;
            return Ok(());
        }

        let mut auth_header: Option<String> = None;
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("authorization") {
                    auth_header = Some(value.trim().to_string());
                }
            }
        }

        if method != "GET" {
            write_http_response_blocking(
                &mut stream,
                405,
                "Method Not Allowed",
                "{\"error\":\"method_not_allowed\"}",
            )?;
            return Ok(());
        }

        let expected_auth = format!("Bearer {}", token);
        if auth_header.as_deref() != Some(expected_auth.as_str()) {
            write_http_response_blocking(
                &mut stream,
                401,
                "Unauthorized",
                "{\"error\":\"unauthorized\"}",
            )?;
            return Ok(());
        }

        match path {
            "/v1/stats" => {
                let body = render_stats_payload(&context);
                write_http_response_blocking(&mut stream, 200, "OK", &body)?;
            }
            "/v1/connections" => {
                let body = render_connections_snapshot_payload(&context);
                write_http_response_blocking(&mut stream, 200, "OK", &body)?;
            }
            _ => {
                write_http_response_blocking(
                    &mut stream,
                    404,
                    "Not Found",
                    "{\"error\":\"not_found\"}",
                )?;
            }
        }

        Ok(())
    })();

    let _ = stream.shutdown(Shutdown::Both);
    result
}

async fn handle_stats_http_client(
    mut stream: TcpStream,
    token: &str,
    context: Arc<StatsApiContext>,
) -> Result<()> {
    let mut request_buf = [0u8; MAX_HTTP_REQUEST_SIZE];
    let mut total_read = 0usize;
    let mut header_complete = false;

    loop {
        if total_read >= MAX_HTTP_REQUEST_SIZE {
            write_http_response(
                &mut stream,
                431,
                "Request Header Fields Too Large",
                "{\"error\":\"request_too_large\"}",
            )
            .await?;
            return Ok(());
        }

        let read_len = match tokio::time::timeout(
            Duration::from_secs(STATS_HTTP_READ_TIMEOUT_SECS),
            stream.read(&mut request_buf[total_read..]),
        )
        .await
        {
            Ok(read_result) => read_result.context("Failed to read stats API request")?,
            Err(_) => {
                write_http_response(
                    &mut stream,
                    408,
                    "Request Timeout",
                    "{\"error\":\"request_timeout\"}",
                )
                .await?;
                return Ok(());
            }
        };

        if read_len == 0 {
            break;
        }

        total_read += read_len;

        if find_http_header_end(&request_buf[..total_read]).is_some() {
            header_complete = true;
            break;
        }
    }

    if total_read == 0 {
        return Ok(());
    }

    if !header_complete {
        write_http_response(
            &mut stream,
            400,
            "Bad Request",
            "{\"error\":\"incomplete_request_headers\"}",
        )
        .await?;
        return Ok(());
    }

    let header_end = find_http_header_end(&request_buf[..total_read]).unwrap_or(total_read);
    let request = String::from_utf8_lossy(&request_buf[..header_end]);
    let mut lines = request.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or("");
    let path = request_parts.next().unwrap_or("");

    if method.is_empty() || path.is_empty() {
        write_http_response(
            &mut stream,
            400,
            "Bad Request",
            "{\"error\":\"bad_request_line\"}",
        )
        .await?;
        return Ok(());
    }

    let mut auth_header: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("authorization") {
                auth_header = Some(value.trim().to_string());
            }
        }
    }

    if method != "GET" {
        write_http_response(
            &mut stream,
            405,
            "Method Not Allowed",
            "{\"error\":\"method_not_allowed\"}",
        )
        .await?;
        return Ok(());
    }

    let expected_auth = format!("Bearer {}", token);
    if auth_header.as_deref() != Some(expected_auth.as_str()) {
        write_http_response(
            &mut stream,
            401,
            "Unauthorized",
            "{\"error\":\"unauthorized\"}",
        )
        .await?;
        return Ok(());
    }

    match path {
        "/v1/stats" => {
            let body = render_stats_payload(&context);
            write_http_response(&mut stream, 200, "OK", &body).await?;
        }
        "/v1/connections" => {
            let body = render_connections_payload(&context);
            write_http_response(&mut stream, 200, "OK", &body).await?;
        }
        _ => {
            write_http_response(&mut stream, 404, "Not Found", "{\"error\":\"not_found\"}").await?;
        }
    }

    Ok(())
}

async fn write_http_response(
    stream: &mut TcpStream,
    status_code: u16,
    status_text: &str,
    body: &str,
) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status_code,
        status_text,
        body.len(),
        body
    );
    stream
        .write_all(response.as_bytes())
        .await
        .context("Failed to write stats API response")?;
    Ok(())
}

fn write_http_response_blocking(
    stream: &mut std::net::TcpStream,
    status_code: u16,
    status_text: &str,
    body: &str,
) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status_code,
        status_text,
        body.len(),
        body
    );
    stream
        .write_all(response.as_bytes())
        .context("Failed to write blocking stats API response")?;
    stream
        .flush()
        .context("Failed to flush stats API response")?;
    Ok(())
}

fn render_stats_payload(context: &StatsApiContext) -> String {
    let bytes_in = context.stats.bytes_in.load(Ordering::Relaxed);
    let bytes_out = context.stats.bytes_out.load(Ordering::Relaxed);
    let dropped_in = context.stats.dropped_in.load(Ordering::Relaxed);
    let dropped_out = context.stats.dropped_out.load(Ordering::Relaxed);
    let elapsed_secs = context.started_at.elapsed().as_secs();
    let (inbound_bps, outbound_bps) =
        sample_stats_rates(context, bytes_in, bytes_out, Instant::now());
    let dropped_pps = if elapsed_secs > 0 {
        (dropped_in + dropped_out) / elapsed_secs
    } else {
        0
    };

    let active_sessions = context.stats.active_sessions.load(Ordering::Relaxed);
    // Keep /v1/stats independent from live DashMap iteration so the card-level
    // telemetry path stays responsive even when detailed session scans wedge.
    let active_users = active_sessions;

    format!(
        "{{\"version\":\"{}\",\"timestamp\":{},\"active_users\":{},\"active_sessions\":{},\"throttled_users\":{},\"inbound_bps\":{},\"outbound_bps\":{},\"dropped_in\":{},\"dropped_out\":{},\"dropped_pps\":{},\"tcp_forwarded\":{},\"tun_udp_forwarded\":{}}}",
        RELAY_VERSION,
        unix_timestamp_secs(),
        active_users,
        active_sessions,
        context.stats.throttled_users.load(Ordering::Relaxed),
        inbound_bps,
        outbound_bps,
        dropped_in,
        dropped_out,
        dropped_pps,
        context.stats.tcp_forwarded.load(Ordering::Relaxed),
        context.stats.tun_udp_forwarded.load(Ordering::Relaxed)
    )
}

fn sample_stats_rates(
    context: &StatsApiContext,
    bytes_in: u64,
    bytes_out: u64,
    now: Instant,
) -> (u64, u64) {
    let mut window = context
        .rate_window
        .lock()
        .expect("stats rate window mutex poisoned");

    match window.last_sample_at {
        None => {
            window.last_sample_at = Some(now);
            window.last_bytes_in = bytes_in;
            window.last_bytes_out = bytes_out;
        }
        Some(last_sample_at) => {
            let elapsed = now.saturating_duration_since(last_sample_at);
            if elapsed >= Duration::from_millis(STATS_RATE_SAMPLE_MIN_MS) {
                let elapsed_secs = elapsed.as_secs_f64();
                let delta_in = bytes_in.saturating_sub(window.last_bytes_in);
                let delta_out = bytes_out.saturating_sub(window.last_bytes_out);

                window.inbound_bps = (delta_in as f64 / elapsed_secs).round() as u64;
                window.outbound_bps = (delta_out as f64 / elapsed_secs).round() as u64;
                window.last_sample_at = Some(now);
                window.last_bytes_in = bytes_in;
                window.last_bytes_out = bytes_out;
            }
        }
    }

    (window.inbound_bps, window.outbound_bps)
}

pub(crate) fn empty_connections_payload() -> String {
    format!(
        "{{\"timestamp\":{},\"connections\":[]}}",
        unix_timestamp_secs()
    )
}

fn render_connections_snapshot_payload(context: &StatsApiContext) -> String {
    match context.connections_snapshot.read() {
        Ok(snapshot) => snapshot.clone(),
        Err(_) => empty_connections_payload(),
    }
}

pub(crate) fn spawn_connections_snapshot_updater(context: Arc<StatsApiContext>) {
    std::thread::Builder::new()
        .name("stats-snapshot".into())
        .spawn(move || loop {
            let payload = render_connections_payload(&context);
            match context.connections_snapshot.write() {
                Ok(mut snapshot) => {
                    *snapshot = payload;
                }
                Err(_) => {
                    log::warn!("Connections snapshot cache poisoned; stopping updater thread");
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(CONNECTION_SNAPSHOT_INTERVAL_MS));
        })
        .expect("failed to spawn stats-snapshot thread");
}

fn find_http_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|i| i + 4)
}

fn render_connections_payload(context: &StatsApiContext) -> String {
    struct ConnectionSnapshot {
        user_id: String,
        session_id: String,
        auth_state: String,
        connected_at: u64,
        last_activity_at: u64,
        bytes_in: u64,
        bytes_out: u64,
        client_endpoint: String,
        packets_in: u64,
        packets_out: u64,
        rtt_us: u64,
    }

    #[derive(Clone)]
    struct SessionSnapshotMeta {
        user_id: String,
        auth_state: String,
        client_endpoint: String,
        connected_at: u64,
        last_activity_at: u64,
    }

    // Clone the live session metadata up front so the snapshot thread never
    // holds a session_traffic shard lock while trying to lock sessions. The RX
    // path updates these maps in the opposite order, so nested locking here can
    // wedge the datapath under load.
    let mut session_meta =
        std::collections::HashMap::<[u8; SESSION_ID_LEN], SessionSnapshotMeta>::new();
    for entry in context.sessions.iter() {
        session_meta.insert(
            *entry.key(),
            SessionSnapshotMeta {
                user_id: entry.user_id.clone(),
                auth_state: entry.auth_state.as_str().to_string(),
                client_endpoint: entry.client_addr.to_string(),
                connected_at: entry.created_at_unix,
                last_activity_at: entry.last_activity_unix,
            },
        );
    }

    let mut seen_sessions = std::collections::HashSet::<[u8; SESSION_ID_LEN]>::new();
    let mut snapshots = Vec::<ConnectionSnapshot>::new();
    for entry in context.session_traffic.iter() {
        let session_id = *entry.key();
        let traffic = entry.value();
        let Some(session) = session_meta.get(&session_id) else {
            continue;
        };
        seen_sessions.insert(session_id);
        let session_hex = format!("{:016x}", u64::from_be_bytes(session_id));

        snapshots.push(ConnectionSnapshot {
            user_id: session.user_id.clone(),
            session_id: session_hex,
            auth_state: session.auth_state.clone(),
            connected_at: traffic.connected_at_unix.max(session.connected_at),
            last_activity_at: traffic.last_activity_unix.load(Ordering::Relaxed),
            bytes_in: traffic.bytes_in.load(Ordering::Relaxed),
            bytes_out: traffic.bytes_out.load(Ordering::Relaxed),
            client_endpoint: session.client_endpoint.clone(),
            packets_in: traffic.packets_in.load(Ordering::Relaxed),
            packets_out: traffic.packets_out.load(Ordering::Relaxed),
            rtt_us: traffic.last_rtt_us.load(Ordering::Relaxed),
        });
    }

    for (session_id, entry) in session_meta {
        if seen_sessions.contains(&session_id) {
            continue;
        }

        snapshots.push(ConnectionSnapshot {
            user_id: entry.user_id.clone(),
            session_id: format!("{:016x}", u64::from_be_bytes(session_id)),
            auth_state: entry.auth_state,
            connected_at: entry.connected_at,
            last_activity_at: entry.last_activity_at,
            bytes_in: 0,
            bytes_out: 0,
            client_endpoint: entry.client_endpoint,
            packets_in: 0,
            packets_out: 0,
            rtt_us: 0,
        });
    }

    snapshots.sort_by(|a, b| b.last_activity_at.cmp(&a.last_activity_at));

    let mut body = format!(
        "{{\"timestamp\":{},\"connections\":[",
        unix_timestamp_secs()
    );
    for (index, conn) in snapshots.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        body.push_str(&format!(
            "{{\"user_id\":\"{}\",\"session_id\":\"{}\",\"auth_state\":\"{}\",\"connected_at\":{},\"last_activity_at\":{},\"bytes_in\":{},\"bytes_out\":{},\"client_endpoint\":\"{}\",\"packets_in\":{},\"packets_out\":{},\"rtt_us\":{}}}",
            escape_json(&conn.user_id),
            escape_json(&conn.session_id),
            escape_json(&conn.auth_state),
            conn.connected_at,
            conn.last_activity_at,
            conn.bytes_in,
            conn.bytes_out,
            escape_json(&conn.client_endpoint),
            conn.packets_in,
            conn.packets_out,
            conn.rtt_us,
        ));
    }
    body.push_str("]}");
    body
}

fn escape_json(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// Parsed result from `parse_ip_packet_full`.
pub(crate) enum ParsedPacket<'a> {
    Udp {
        game_addr: SocketAddr,
        payload: &'a [u8],
        original_info: OriginalPacketInfo,
    },
    Tcp {
        original_info: OriginalPacketInfo,
        raw_ip_packet: &'a [u8],
    },
}

/// Parse an IP packet and extract protocol-specific information.
///
/// Returns `ParsedPacket::Udp` for UDP (protocol 17) with the game address,
/// payload, and original packet info. Returns `ParsedPacket::Tcp` for TCP
/// (protocol 6) with the original packet info and a reference to the raw IP
/// packet. Returns `None` for other protocols or malformed packets.
fn parse_ip_packet_full(packet: &[u8]) -> Option<ParsedPacket<'_>> {
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

    let protocol = packet[9];

    // Extract source IP (bytes 12-15)
    let src_ip = std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);

    // Extract destination IP (bytes 16-19)
    let dst_ip = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    match protocol {
        17 => {
            // UDP
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

            Some(ParsedPacket::Udp {
                game_addr: SocketAddr::from((dst_ip, dst_port)),
                payload,
                original_info,
            })
        }
        6 => {
            // TCP — need at least the TCP header (20 bytes) after the IP header
            const TCP_HEADER_MIN: usize = 20;
            let tcp_start = ihl;
            if packet.len() < tcp_start + TCP_HEADER_MIN {
                return None;
            }

            let src_port = u16::from_be_bytes([packet[tcp_start], packet[tcp_start + 1]]);
            let dst_port = u16::from_be_bytes([packet[tcp_start + 2], packet[tcp_start + 3]]);

            let original_info = OriginalPacketInfo {
                src_ip,
                src_port,
                dst_ip,
                dst_port,
            };

            Some(ParsedPacket::Tcp {
                original_info,
                raw_ip_packet: packet,
            })
        }
        _ => None,
    }
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
    // Identification (unused when DF is set; keep deterministic to avoid RNG overhead).
    packet[4] = 0;
    packet[5] = 0;
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
pub(crate) fn calculate_ip_checksum(header: &[u8]) -> u16 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn test_auth_materials() -> (Ed25519KeyPair, RelayAuthConfig) {
        let seed = [7u8; 32];
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed).expect("seed must be valid");
        let auth_config = RelayAuthConfig {
            mode: RelayAuthMode::Required,
            public_key: Some(key_pair.public_key().as_ref().to_vec()),
            server_id: Some("us-east-nj".to_string()),
        };
        (key_pair, auth_config)
    }

    fn make_ticket_token(
        key_pair: &Ed25519KeyPair,
        sid: &str,
        server: &str,
        now: u64,
        exp: u64,
    ) -> String {
        let payload = serde_json::json!({
            "v": 1,
            "iss": "swifttunnel-web",
            "aud": "swifttunnel-relay",
            "sub": "11111111-1111-1111-1111-111111111111",
            "sid": sid,
            "srv": server,
            "iat": now,
            "exp": exp,
            "jti": "22222222-2222-2222-2222-222222222222",
        });
        let payload_bytes = serde_json::to_vec(&payload).expect("json serialization must work");
        let signature = key_pair.sign(&payload_bytes);
        format!(
            "{}.{}",
            BASE64_URL_SAFE_NO_PAD.encode(&payload_bytes),
            BASE64_URL_SAFE_NO_PAD.encode(signature.as_ref())
        )
    }

    #[test]
    fn test_parse_flow_channel_capacity_defaults_and_clamps() {
        assert_eq!(
            parse_flow_channel_capacity(None),
            DEFAULT_FLOW_CHANNEL_CAPACITY
        );
        assert_eq!(
            parse_flow_channel_capacity(Some("2".to_string())),
            MIN_FLOW_CHANNEL_CAPACITY
        );
        assert_eq!(
            parse_flow_channel_capacity(Some("999999".to_string())),
            MAX_FLOW_CHANNEL_CAPACITY
        );
        assert_eq!(parse_flow_channel_capacity(Some("512".to_string())), 512);
    }

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

        let result = result.unwrap();
        match result {
            ParsedPacket::Udp {
                game_addr: addr,
                payload,
                original_info: info,
            } => {
                assert_eq!(addr.ip().to_string(), "1.2.3.4");
                assert_eq!(addr.port(), 12345);
                assert_eq!(payload, &[0xDE, 0xAD, 0xBE, 0xEF]);
                assert_eq!(info.src_ip.to_string(), "10.0.0.5");
                assert_eq!(info.src_port, 54321);
                assert_eq!(info.dst_ip.to_string(), "1.2.3.4");
                assert_eq!(info.dst_port, 12345);
            }
            _ => panic!("Expected ParsedPacket::Udp"),
        }
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
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
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

    #[test]
    fn test_parse_auth_hello_token_valid_and_malformed() {
        let token = "abc.def";
        let mut frame = Vec::with_capacity(SESSION_ID_LEN + 3 + token.len());
        frame.extend_from_slice(&[0u8; SESSION_ID_LEN]);
        frame.push(AUTH_HELLO_FRAME_TYPE);
        frame.extend_from_slice(&(token.len() as u16).to_be_bytes());
        frame.extend_from_slice(token.as_bytes());

        let parsed = parse_auth_hello_token(&frame, frame.len()).expect("frame should parse");
        assert_eq!(parsed, token);

        let mut malformed = frame.clone();
        malformed[SESSION_ID_LEN + 1] = 0;
        malformed[SESSION_ID_LEN + 2] = (token.len() as u8).saturating_add(1);
        assert!(matches!(
            parse_auth_hello_token(&malformed, malformed.len()),
            Err(RelayAuthVerifyError::BadFormat)
        ));
    }

    #[test]
    fn test_verify_relay_ticket_valid() {
        let (key_pair, auth_config) = test_auth_materials();
        let session_id = 0x0123_4567_89ab_cdef_u64.to_be_bytes();
        let now = 1_739_790_000_u64;
        let sid = format!("{:016x}", u64::from_be_bytes(session_id));
        let token = make_ticket_token(&key_pair, &sid, "us-east-nj", now, now + 300);

        let user = verify_relay_ticket(&token, session_id, &auth_config, now).expect("valid token");
        assert_eq!(user, "11111111-1111-1111-1111-111111111111");
    }

    #[test]
    fn test_verify_relay_ticket_sid_mismatch() {
        let (key_pair, auth_config) = test_auth_materials();
        let session_id = 0x0123_4567_89ab_cdef_u64.to_be_bytes();
        let now = 1_739_790_000_u64;
        let token = make_ticket_token(&key_pair, "ffffffffffffffff", "us-east-nj", now, now + 300);

        let result = verify_relay_ticket(&token, session_id, &auth_config, now);
        assert!(matches!(result, Err(RelayAuthVerifyError::SidMismatch)));
    }

    #[test]
    fn test_verify_relay_ticket_server_mismatch() {
        let (key_pair, auth_config) = test_auth_materials();
        let session_id = 0x0123_4567_89ab_cdef_u64.to_be_bytes();
        let now = 1_739_790_000_u64;
        let sid = format!("{:016x}", u64::from_be_bytes(session_id));
        let token = make_ticket_token(&key_pair, &sid, "tokyo-02", now, now + 300);

        let result = verify_relay_ticket(&token, session_id, &auth_config, now);
        assert!(matches!(result, Err(RelayAuthVerifyError::ServerMismatch)));
    }

    #[test]
    fn test_verify_relay_ticket_expired() {
        let (key_pair, auth_config) = test_auth_materials();
        let session_id = 0x0123_4567_89ab_cdef_u64.to_be_bytes();
        let now = 1_739_790_000_u64;
        let sid = format!("{:016x}", u64::from_be_bytes(session_id));
        let token = make_ticket_token(&key_pair, &sid, "us-east-nj", now - 600, now - 200);

        let result = verify_relay_ticket(&token, session_id, &auth_config, now);
        assert!(matches!(result, Err(RelayAuthVerifyError::Expired)));
    }

    #[test]
    fn test_verify_relay_ticket_iat_in_future_is_bad_format() {
        let (key_pair, auth_config) = test_auth_materials();
        let session_id = 0x0123_4567_89ab_cdef_u64.to_be_bytes();
        let now = 1_739_790_000_u64;
        let sid = format!("{:016x}", u64::from_be_bytes(session_id));
        let future_iat = now + AUTH_CLOCK_SKEW_SECS + 1;
        let token = make_ticket_token(&key_pair, &sid, "us-east-nj", future_iat, future_iat + 300);

        let result = verify_relay_ticket(&token, session_id, &auth_config, now);
        assert!(matches!(result, Err(RelayAuthVerifyError::BadFormat)));
    }

    #[test]
    fn test_verify_relay_ticket_bad_signature() {
        let (key_pair, auth_config) = test_auth_materials();
        let session_id = 0x0123_4567_89ab_cdef_u64.to_be_bytes();
        let now = 1_739_790_000_u64;
        let sid = format!("{:016x}", u64::from_be_bytes(session_id));
        let token = make_ticket_token(&key_pair, &sid, "us-east-nj", now, now + 300);

        let (payload, signature) = token
            .split_once('.')
            .expect("token should contain separator");
        let mut sig_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(signature)
            .expect("signature should decode");
        sig_bytes[0] ^= 0xAA;
        let tampered = format!("{}.{}", payload, BASE64_URL_SAFE_NO_PAD.encode(sig_bytes));

        let result = verify_relay_ticket(&tampered, session_id, &auth_config, now);
        assert!(matches!(result, Err(RelayAuthVerifyError::BadSignature)));
    }
}

#[cfg(test)]
mod auth_config_utility_tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn test_auth_materials() -> (Ed25519KeyPair, RelayAuthConfig) {
        let seed = [7u8; 32];
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed).expect("seed must be valid");
        let auth_config = RelayAuthConfig {
            mode: RelayAuthMode::Required,
            public_key: Some(key_pair.public_key().as_ref().to_vec()),
            server_id: Some("us-east-nj".to_string()),
        };
        (key_pair, auth_config)
    }

    fn make_ticket_token(
        key_pair: &Ed25519KeyPair,
        sid: &str,
        server: &str,
        now: u64,
        exp: u64,
    ) -> String {
        let payload = serde_json::json!({
            "v": 1,
            "iss": "swifttunnel-web",
            "aud": "swifttunnel-relay",
            "sub": "11111111-1111-1111-1111-111111111111",
            "sid": sid,
            "srv": server,
            "iat": now,
            "exp": exp,
            "jti": "22222222-2222-2222-2222-222222222222",
        });
        let payload_bytes = serde_json::to_vec(&payload).expect("json serialization must work");
        let signature = key_pair.sign(&payload_bytes);
        format!(
            "{}.{}",
            BASE64_URL_SAFE_NO_PAD.encode(&payload_bytes),
            BASE64_URL_SAFE_NO_PAD.encode(signature.as_ref())
        )
    }

    fn make_custom_ticket_token(
        key_pair: &Ed25519KeyPair,
        payload_json: serde_json::Value,
    ) -> String {
        let payload_bytes = serde_json::to_vec(&payload_json).unwrap();
        let signature = key_pair.sign(&payload_bytes);
        format!(
            "{}.{}",
            BASE64_URL_SAFE_NO_PAD.encode(&payload_bytes),
            BASE64_URL_SAFE_NO_PAD.encode(signature.as_ref())
        )
    }

    // ---- RelayAuthMode::from_env tests ----

    #[test]
    fn test_from_env_required() {
        assert_eq!(
            RelayAuthMode::from_env(Some("required".into())),
            RelayAuthMode::Required
        );
    }

    #[test]
    fn test_from_env_optional() {
        assert_eq!(
            RelayAuthMode::from_env(Some("optional".into())),
            RelayAuthMode::Optional
        );
    }

    #[test]
    fn test_from_env_off() {
        assert_eq!(
            RelayAuthMode::from_env(Some("off".into())),
            RelayAuthMode::Off
        );
    }

    #[test]
    fn test_from_env_none() {
        assert_eq!(RelayAuthMode::from_env(None), RelayAuthMode::Off);
    }

    #[test]
    fn test_from_env_whitespace_trimmed() {
        assert_eq!(
            RelayAuthMode::from_env(Some(" required ".into())),
            RelayAuthMode::Required
        );
    }

    #[test]
    fn test_from_env_case_insensitive() {
        assert_eq!(
            RelayAuthMode::from_env(Some("REQUIRED".into())),
            RelayAuthMode::Required
        );
    }

    // ---- RelayAuthMode::as_str tests ----

    #[test]
    fn test_as_str_off() {
        assert_eq!(RelayAuthMode::Off.as_str(), "off");
    }

    #[test]
    fn test_as_str_optional() {
        assert_eq!(RelayAuthMode::Optional.as_str(), "optional");
    }

    #[test]
    fn test_as_str_required() {
        assert_eq!(RelayAuthMode::Required.as_str(), "required");
    }

    // ---- RelayAuthMode::requires_auth tests ----

    #[test]
    fn test_requires_auth_off() {
        assert!(!RelayAuthMode::Off.requires_auth());
    }

    #[test]
    fn test_requires_auth_optional() {
        assert!(!RelayAuthMode::Optional.requires_auth());
    }

    #[test]
    fn test_requires_auth_required() {
        assert!(RelayAuthMode::Required.requires_auth());
    }

    // ---- SessionAuthState::as_str tests ----

    #[test]
    fn test_session_auth_state_legacy() {
        assert_eq!(SessionAuthState::Legacy.as_str(), "legacy");
    }

    #[test]
    fn test_session_auth_state_authenticated() {
        assert_eq!(SessionAuthState::Authenticated.as_str(), "authenticated");
    }

    // ---- RelayAuthVerifyError::ack_status tests ----

    #[test]
    fn test_ack_status_bad_format() {
        assert_eq!(
            RelayAuthVerifyError::BadFormat.ack_status(),
            AUTH_ACK_BAD_FORMAT
        );
    }

    #[test]
    fn test_ack_status_bad_signature() {
        assert_eq!(
            RelayAuthVerifyError::BadSignature.ack_status(),
            AUTH_ACK_BAD_SIGNATURE
        );
    }

    #[test]
    fn test_ack_status_expired() {
        assert_eq!(RelayAuthVerifyError::Expired.ack_status(), AUTH_ACK_EXPIRED);
    }

    #[test]
    fn test_ack_status_sid_mismatch() {
        assert_eq!(
            RelayAuthVerifyError::SidMismatch.ack_status(),
            AUTH_ACK_SID_MISMATCH
        );
    }

    #[test]
    fn test_ack_status_server_mismatch() {
        assert_eq!(
            RelayAuthVerifyError::ServerMismatch.ack_status(),
            AUTH_ACK_SERVER_MISMATCH
        );
    }

    // ---- decode_base64_flexible tests ----

    #[test]
    fn test_decode_base64_url_safe_no_pad() {
        let input = BASE64_URL_SAFE_NO_PAD.encode(b"hello");
        let result = decode_base64_flexible(&input);
        assert_eq!(result, Some(b"hello".to_vec()));
    }

    #[test]
    fn test_decode_base64_url_safe_padded() {
        let input = BASE64_URL_SAFE.encode(b"hello");
        let result = decode_base64_flexible(&input);
        assert_eq!(result, Some(b"hello".to_vec()));
    }

    #[test]
    fn test_decode_base64_standard() {
        let input = BASE64_STANDARD.encode(b"hello");
        let result = decode_base64_flexible(&input);
        assert_eq!(result, Some(b"hello".to_vec()));
    }

    #[test]
    fn test_decode_base64_invalid() {
        let result = decode_base64_flexible("!!!not-valid-base64!!!");
        assert_eq!(result, None);
    }

    #[test]
    fn test_decode_base64_empty() {
        let result = decode_base64_flexible("");
        assert_eq!(result, Some(vec![]));
    }

    // ---- verify_relay_ticket edge cases ----

    #[test]
    fn test_verify_ticket_empty_token() {
        let (_, auth_config) = test_auth_materials();
        let session_id = [0u8; SESSION_ID_LEN];
        let result = verify_relay_ticket("", session_id, &auth_config, 1_739_790_000);
        assert!(matches!(result, Err(RelayAuthVerifyError::BadFormat)));
    }

    #[test]
    fn test_verify_ticket_too_long() {
        let (_, auth_config) = test_auth_materials();
        let session_id = [0u8; SESSION_ID_LEN];
        let long_token = "a".repeat(MAX_AUTH_TOKEN_LEN + 1);
        let result = verify_relay_ticket(&long_token, session_id, &auth_config, 1_739_790_000);
        assert!(matches!(result, Err(RelayAuthVerifyError::BadFormat)));
    }

    #[test]
    fn test_verify_ticket_no_dot_separator() {
        let (_, auth_config) = test_auth_materials();
        let session_id = [0u8; SESSION_ID_LEN];
        let result = verify_relay_ticket("nodothere", session_id, &auth_config, 1_739_790_000);
        assert!(matches!(result, Err(RelayAuthVerifyError::BadFormat)));
    }

    #[test]
    fn test_verify_ticket_bad_base64_payload() {
        let (_, auth_config) = test_auth_materials();
        let session_id = [0u8; SESSION_ID_LEN];
        let sig_b64 = BASE64_URL_SAFE_NO_PAD.encode(&[0u8; 64]);
        let token = format!("!!!invalid!!!.{}", sig_b64);
        let result = verify_relay_ticket(&token, session_id, &auth_config, 1_739_790_000);
        assert!(matches!(result, Err(RelayAuthVerifyError::BadFormat)));
    }

    #[test]
    fn test_verify_ticket_bad_base64_signature() {
        let (_, auth_config) = test_auth_materials();
        let session_id = [0u8; SESSION_ID_LEN];
        let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(b"{}");
        let token = format!("{}.!!!invalid!!!", payload_b64);
        let result = verify_relay_ticket(&token, session_id, &auth_config, 1_739_790_000);
        assert!(matches!(result, Err(RelayAuthVerifyError::BadFormat)));
    }

    #[test]
    fn test_verify_ticket_signature_wrong_length() {
        let (_, auth_config) = test_auth_materials();
        let session_id = [0u8; SESSION_ID_LEN];
        let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(b"{}");
        let sig_b64 = BASE64_URL_SAFE_NO_PAD.encode(&[0u8; 32]); // 32 != 64
        let token = format!("{}.{}", payload_b64, sig_b64);
        let result = verify_relay_ticket(&token, session_id, &auth_config, 1_739_790_000);
        assert!(matches!(result, Err(RelayAuthVerifyError::BadFormat)));
    }

    #[test]
    fn test_verify_ticket_no_public_key() {
        let auth_config = RelayAuthConfig {
            mode: RelayAuthMode::Required,
            public_key: None,
            server_id: Some("us-east-nj".to_string()),
        };
        let session_id = [0u8; SESSION_ID_LEN];
        let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(b"{}");
        let sig_b64 = BASE64_URL_SAFE_NO_PAD.encode(&[0u8; 64]);
        let token = format!("{}.{}", payload_b64, sig_b64);
        let result = verify_relay_ticket(&token, session_id, &auth_config, 1_739_790_000);
        assert!(matches!(result, Err(RelayAuthVerifyError::BadFormat)));
    }

    #[test]
    fn test_verify_ticket_wrong_version() {
        let (key_pair, auth_config) = test_auth_materials();
        let session_id = [0u8; SESSION_ID_LEN];
        let sid = format!("{:016x}", u64::from_be_bytes(session_id));
        let now = 1_739_790_000_u64;
        let token = make_custom_ticket_token(
            &key_pair,
            serde_json::json!({
                "v": 2,
                "iss": "swifttunnel-web",
                "aud": "swifttunnel-relay",
                "sub": "user-1",
                "sid": sid,
                "srv": "us-east-nj",
                "iat": now,
                "exp": now + 300,
                "jti": "jti-1",
            }),
        );
        let result = verify_relay_ticket(&token, session_id, &auth_config, now);
        assert!(matches!(result, Err(RelayAuthVerifyError::BadFormat)));
    }

    #[test]
    fn test_verify_ticket_wrong_issuer() {
        let (key_pair, auth_config) = test_auth_materials();
        let session_id = [0u8; SESSION_ID_LEN];
        let sid = format!("{:016x}", u64::from_be_bytes(session_id));
        let now = 1_739_790_000_u64;
        let token = make_custom_ticket_token(
            &key_pair,
            serde_json::json!({
                "v": 1,
                "iss": "wrong-issuer",
                "aud": "swifttunnel-relay",
                "sub": "user-1",
                "sid": sid,
                "srv": "us-east-nj",
                "iat": now,
                "exp": now + 300,
                "jti": "jti-1",
            }),
        );
        let result = verify_relay_ticket(&token, session_id, &auth_config, now);
        assert!(matches!(result, Err(RelayAuthVerifyError::BadFormat)));
    }

    #[test]
    fn test_verify_ticket_wrong_audience() {
        let (key_pair, auth_config) = test_auth_materials();
        let session_id = [0u8; SESSION_ID_LEN];
        let sid = format!("{:016x}", u64::from_be_bytes(session_id));
        let now = 1_739_790_000_u64;
        let token = make_custom_ticket_token(
            &key_pair,
            serde_json::json!({
                "v": 1,
                "iss": "swifttunnel-web",
                "aud": "wrong-audience",
                "sub": "user-1",
                "sid": sid,
                "srv": "us-east-nj",
                "iat": now,
                "exp": now + 300,
                "jti": "jti-1",
            }),
        );
        let result = verify_relay_ticket(&token, session_id, &auth_config, now);
        assert!(matches!(result, Err(RelayAuthVerifyError::BadFormat)));
    }

    #[test]
    fn test_verify_ticket_empty_sub() {
        let (key_pair, auth_config) = test_auth_materials();
        let session_id = [0u8; SESSION_ID_LEN];
        let sid = format!("{:016x}", u64::from_be_bytes(session_id));
        let now = 1_739_790_000_u64;
        let token = make_custom_ticket_token(
            &key_pair,
            serde_json::json!({
                "v": 1,
                "iss": "swifttunnel-web",
                "aud": "swifttunnel-relay",
                "sub": "",
                "sid": sid,
                "srv": "us-east-nj",
                "iat": now,
                "exp": now + 300,
                "jti": "jti-1",
            }),
        );
        let result = verify_relay_ticket(&token, session_id, &auth_config, now);
        assert!(matches!(result, Err(RelayAuthVerifyError::BadFormat)));
    }

    #[test]
    fn test_verify_ticket_iat_at_exact_clock_skew_boundary_passes() {
        let (key_pair, auth_config) = test_auth_materials();
        let session_id = 0x0123_4567_89ab_cdef_u64.to_be_bytes();
        let now = 1_739_790_000_u64;
        let sid = format!("{:016x}", u64::from_be_bytes(session_id));
        // iat = now + AUTH_CLOCK_SKEW_SECS exactly should pass (not strictly greater)
        let iat = now + AUTH_CLOCK_SKEW_SECS;
        let token = make_ticket_token(&key_pair, &sid, "us-east-nj", iat, iat + 300);
        let result = verify_relay_ticket(&token, session_id, &auth_config, now);
        assert!(
            result.is_ok(),
            "iat at exact clock skew boundary should pass"
        );
    }

    #[test]
    fn test_verify_ticket_exp_at_exact_clock_skew_boundary_passes() {
        let (key_pair, auth_config) = test_auth_materials();
        let session_id = 0x0123_4567_89ab_cdef_u64.to_be_bytes();
        let sid = format!("{:016x}", u64::from_be_bytes(session_id));
        let iat = 1_739_789_000_u64;
        let exp = 1_739_789_500_u64;
        // now = exp + AUTH_CLOCK_SKEW_SECS exactly should pass
        let now = exp + AUTH_CLOCK_SKEW_SECS;
        let token = make_ticket_token(&key_pair, &sid, "us-east-nj", iat, exp);
        let result = verify_relay_ticket(&token, session_id, &auth_config, now);
        assert!(
            result.is_ok(),
            "exp at exact clock skew boundary should pass"
        );
    }

    // ---- parse_auth_hello_token edge cases ----

    #[test]
    fn test_parse_auth_hello_frame_too_short() {
        // Fewer than SESSION_ID_LEN + 3 = 11 bytes
        let frame = [0u8; 10];
        let result = parse_auth_hello_token(&frame, frame.len());
        assert!(matches!(result, Err(RelayAuthVerifyError::BadFormat)));
    }

    #[test]
    fn test_parse_auth_hello_token_len_zero() {
        let mut frame = vec![0u8; SESSION_ID_LEN + 3];
        frame[SESSION_ID_LEN] = AUTH_HELLO_FRAME_TYPE;
        // token_len = 0
        frame[SESSION_ID_LEN + 1] = 0;
        frame[SESSION_ID_LEN + 2] = 0;
        let result = parse_auth_hello_token(&frame, frame.len());
        assert!(matches!(result, Err(RelayAuthVerifyError::BadFormat)));
    }

    #[test]
    fn test_parse_auth_hello_token_len_exceeds_max() {
        let token_len = (MAX_AUTH_TOKEN_LEN + 1) as u16;
        let mut frame = vec![0u8; SESSION_ID_LEN + 3 + MAX_AUTH_TOKEN_LEN + 1];
        frame[SESSION_ID_LEN] = AUTH_HELLO_FRAME_TYPE;
        frame[SESSION_ID_LEN + 1] = (token_len >> 8) as u8;
        frame[SESSION_ID_LEN + 2] = (token_len & 0xFF) as u8;
        let result = parse_auth_hello_token(&frame, frame.len());
        assert!(matches!(result, Err(RelayAuthVerifyError::BadFormat)));
    }

    #[test]
    fn test_parse_auth_hello_payload_end_exceeds_frame_len() {
        let token = "abc";
        // Declare token_len as 10 but only provide 3 bytes
        let mut frame = vec![0u8; SESSION_ID_LEN + 3 + token.len()];
        frame[SESSION_ID_LEN] = AUTH_HELLO_FRAME_TYPE;
        frame[SESSION_ID_LEN + 1] = 0;
        frame[SESSION_ID_LEN + 2] = 10; // says 10 but frame only has 3 token bytes
        frame[SESSION_ID_LEN + 3..].copy_from_slice(token.as_bytes());
        let result = parse_auth_hello_token(&frame, frame.len());
        assert!(matches!(result, Err(RelayAuthVerifyError::BadFormat)));
    }

    #[test]
    fn test_parse_auth_hello_extra_trailing_bytes() {
        let token = "abc";
        // payload_end != len because we add extra trailing bytes
        let mut frame = vec![0u8; SESSION_ID_LEN + 3 + token.len() + 5];
        frame[SESSION_ID_LEN] = AUTH_HELLO_FRAME_TYPE;
        frame[SESSION_ID_LEN + 1] = 0;
        frame[SESSION_ID_LEN + 2] = token.len() as u8;
        frame[SESSION_ID_LEN + 3..SESSION_ID_LEN + 3 + token.len()]
            .copy_from_slice(token.as_bytes());
        let result = parse_auth_hello_token(&frame, frame.len());
        assert!(matches!(result, Err(RelayAuthVerifyError::BadFormat)));
    }

    #[test]
    fn test_parse_auth_hello_invalid_utf8() {
        let invalid_bytes: &[u8] = &[0xFF, 0xFE, 0xFD];
        let token_len = invalid_bytes.len() as u16;
        let mut frame = vec![0u8; SESSION_ID_LEN + 3 + invalid_bytes.len()];
        frame[SESSION_ID_LEN] = AUTH_HELLO_FRAME_TYPE;
        frame[SESSION_ID_LEN + 1] = (token_len >> 8) as u8;
        frame[SESSION_ID_LEN + 2] = (token_len & 0xFF) as u8;
        frame[SESSION_ID_LEN + 3..].copy_from_slice(invalid_bytes);
        let result = parse_auth_hello_token(&frame, frame.len());
        assert!(matches!(result, Err(RelayAuthVerifyError::BadFormat)));
    }

    // ---- is_transient_recv_error tests ----

    #[test]
    fn test_transient_recv_would_block() {
        let e = std::io::Error::new(ErrorKind::WouldBlock, "would block");
        assert!(is_transient_recv_error(&e));
    }

    #[test]
    fn test_transient_recv_timed_out() {
        let e = std::io::Error::new(ErrorKind::TimedOut, "timed out");
        assert!(is_transient_recv_error(&e));
    }

    #[test]
    fn test_transient_recv_interrupted() {
        let e = std::io::Error::new(ErrorKind::Interrupted, "interrupted");
        assert!(is_transient_recv_error(&e));
    }

    #[test]
    fn test_transient_recv_connection_reset() {
        let e = std::io::Error::new(ErrorKind::ConnectionReset, "connection reset");
        assert!(is_transient_recv_error(&e));
    }

    #[test]
    fn test_transient_recv_permission_denied_not_transient() {
        let e = std::io::Error::new(ErrorKind::PermissionDenied, "permission denied");
        assert!(!is_transient_recv_error(&e));
    }

    #[test]
    fn test_transient_recv_other_not_transient() {
        let e = std::io::Error::new(ErrorKind::Other, "other");
        assert!(!is_transient_recv_error(&e));
    }

    // ---- is_transient_send_error tests ----

    #[test]
    fn test_transient_send_would_block() {
        let e = std::io::Error::new(ErrorKind::WouldBlock, "would block");
        assert!(is_transient_send_error(&e));
    }

    #[test]
    fn test_transient_send_timed_out() {
        let e = std::io::Error::new(ErrorKind::TimedOut, "timed out");
        assert!(is_transient_send_error(&e));
    }

    #[test]
    fn test_transient_send_interrupted() {
        let e = std::io::Error::new(ErrorKind::Interrupted, "interrupted");
        assert!(is_transient_send_error(&e));
    }

    #[test]
    fn test_transient_send_connection_reset_not_transient() {
        let e = std::io::Error::new(ErrorKind::ConnectionReset, "connection reset");
        assert!(!is_transient_send_error(&e));
    }

    #[test]
    fn test_transient_send_other_not_transient() {
        let e = std::io::Error::new(ErrorKind::Other, "other");
        assert!(!is_transient_send_error(&e));
    }

    // ---- find_http_header_end tests ----

    #[test]
    fn test_find_http_header_end_found() {
        let buf = b"GET / HTTP/1.1\r\n\r\n";
        assert_eq!(find_http_header_end(buf), Some(18));
    }

    #[test]
    fn test_find_http_header_end_not_found() {
        let buf = b"GET / HTTP/1.1\r\n";
        assert_eq!(find_http_header_end(buf), None);
    }

    #[test]
    fn test_find_http_header_end_empty() {
        let buf: &[u8] = b"";
        assert_eq!(find_http_header_end(buf), None);
    }

    #[test]
    fn test_find_http_header_end_partial_crlf() {
        let buf = b"GET /\r\n";
        assert_eq!(find_http_header_end(buf), None);
    }

    // ---- escape_json tests ----

    #[test]
    fn test_escape_json_quote() {
        assert_eq!(escape_json("he\"llo"), "he\\\"llo");
    }

    #[test]
    fn test_escape_json_backslash() {
        assert_eq!(escape_json("he\\llo"), "he\\\\llo");
    }

    #[test]
    fn test_escape_json_newline() {
        assert_eq!(escape_json("he\nllo"), "he\\nllo");
    }

    #[test]
    fn test_escape_json_return() {
        assert_eq!(escape_json("he\rllo"), "he\\rllo");
    }

    #[test]
    fn test_escape_json_tab() {
        assert_eq!(escape_json("he\tllo"), "he\\tllo");
    }

    #[test]
    fn test_escape_json_normal_text() {
        assert_eq!(escape_json("hello world"), "hello world");
    }

    #[test]
    fn test_escape_json_empty() {
        assert_eq!(escape_json(""), "");
    }

    // ---- derive_user_id tests ----

    #[test]
    fn test_derive_user_id_known_input() {
        let session_id = [0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(derive_user_id(session_id), "session-0000000000000001");
    }

    #[test]
    fn test_derive_user_id_all_zeros() {
        let session_id = [0u8; SESSION_ID_LEN];
        assert_eq!(derive_user_id(session_id), "session-0000000000000000");
    }
}

#[cfg(test)]
mod packet_construction_tests {
    use super::*;

    // ---- parse_ip_packet_full additional cases ----

    #[test]
    fn test_parse_ip_too_short() {
        let packet = vec![0u8; 19]; // < 20 bytes
        assert!(parse_ip_packet_full(&packet).is_none());
    }

    #[test]
    fn test_parse_ip_wrong_version_v6() {
        let mut packet = vec![0u8; 32];
        // Version 6, IHL 5
        packet[0] = 0x65;
        packet[9] = 17;
        assert!(parse_ip_packet_full(&packet).is_none());
    }

    #[test]
    fn test_parse_ip_ihl_less_than_5() {
        let mut packet = vec![0u8; 32];
        // Version 4, IHL 4 (malformed: < minimum 5)
        packet[0] = 0x44;
        packet[9] = 17;
        assert!(parse_ip_packet_full(&packet).is_none());
    }

    #[test]
    fn test_parse_ip_ihl_with_options() {
        // IHL=6 means 24-byte IP header (with 4 bytes of IP options)
        // Need at least 24 (IP) + 8 (UDP) = 32 bytes
        let mut packet = vec![0u8; 40];
        // Version 4, IHL 6
        packet[0] = 0x46;
        packet[9] = 17; // UDP
                        // Source IP
        packet[12] = 192;
        packet[13] = 168;
        packet[14] = 1;
        packet[15] = 1;
        // Dest IP
        packet[16] = 10;
        packet[17] = 0;
        packet[18] = 0;
        packet[19] = 1;
        // UDP header starts at byte 24 (IHL=6, 6*4=24)
        // Source port = 5000
        packet[24] = 0x13;
        packet[25] = 0x88;
        // Dest port = 6000
        packet[26] = 0x17;
        packet[27] = 0x70;
        // Payload at byte 32
        packet[32..40].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

        let result = parse_ip_packet_full(&packet);
        assert!(result.is_some());
        match result.unwrap() {
            ParsedPacket::Udp {
                game_addr: addr,
                payload,
                original_info: info,
            } => {
                assert_eq!(addr.ip().to_string(), "10.0.0.1");
                assert_eq!(addr.port(), 6000);
                assert_eq!(info.src_ip.to_string(), "192.168.1.1");
                assert_eq!(info.src_port, 5000);
                assert_eq!(payload, &[1, 2, 3, 4, 5, 6, 7, 8]);
            }
            _ => panic!("Expected ParsedPacket::Udp"),
        }
    }

    #[test]
    fn test_parse_ip_tcp_too_short_rejected() {
        // 28 bytes total: 20 IP + 8 remaining, not enough for TCP min header (20)
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = 6; // TCP
        assert!(parse_ip_packet_full(&packet).is_none());
    }

    #[test]
    fn test_parse_ip_tcp_valid() {
        // 44 bytes = 20 IP + 20 TCP header + 4 payload
        let mut packet = vec![0u8; 44];
        packet[0] = 0x45;
        packet[9] = 6; // TCP
        packet[12] = 10;
        packet[13] = 0;
        packet[14] = 0;
        packet[15] = 5;
        packet[16] = 1;
        packet[17] = 2;
        packet[18] = 3;
        packet[19] = 4;
        // TCP src port = 54321 (0xD431)
        packet[20] = 0xD4;
        packet[21] = 0x31;
        // TCP dst port = 80 (0x0050)
        packet[22] = 0x00;
        packet[23] = 0x50;
        // Data offset = 5 (20 bytes) in upper nibble of byte 32
        packet[32] = 0x50;

        let result = parse_ip_packet_full(&packet);
        assert!(result.is_some());
        match result.unwrap() {
            ParsedPacket::Tcp {
                original_info: info,
                raw_ip_packet,
            } => {
                assert_eq!(info.src_ip.to_string(), "10.0.0.5");
                assert_eq!(info.src_port, 54321);
                assert_eq!(info.dst_ip.to_string(), "1.2.3.4");
                assert_eq!(info.dst_port, 80);
                assert_eq!(raw_ip_packet.len(), 44);
            }
            _ => panic!("Expected ParsedPacket::Tcp"),
        }
    }

    #[test]
    fn test_parse_ip_icmp_rejected() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = 1; // ICMP
        assert!(parse_ip_packet_full(&packet).is_none());
    }

    #[test]
    fn test_parse_ip_too_short_for_udp_header() {
        // Exactly 20 bytes = IP header only, no room for UDP header
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[9] = 17;
        assert!(parse_ip_packet_full(&packet).is_none());
    }

    #[test]
    fn test_parse_ip_zero_length_udp_payload() {
        // Exactly 28 bytes = 20 (IP) + 8 (UDP header), no payload
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = 17;
        packet[12] = 10;
        packet[13] = 0;
        packet[14] = 0;
        packet[15] = 5;
        packet[16] = 1;
        packet[17] = 2;
        packet[18] = 3;
        packet[19] = 4;
        packet[20] = 0x13;
        packet[21] = 0x88; // src port 5000
        packet[22] = 0x17;
        packet[23] = 0x70; // dst port 6000

        let result = parse_ip_packet_full(&packet);
        assert!(result.is_some());
        match result.unwrap() {
            ParsedPacket::Udp {
                game_addr: addr,
                payload,
                original_info: info,
            } => {
                assert_eq!(addr.port(), 6000);
                assert!(payload.is_empty());
                assert_eq!(info.src_port, 5000);
                assert_eq!(info.dst_port, 6000);
            }
            _ => panic!("Expected ParsedPacket::Udp"),
        }
    }

    #[test]
    fn test_parse_ip_full_payload_verification() {
        let mut packet = vec![0u8; 36];
        packet[0] = 0x45;
        packet[9] = 17;
        packet[12] = 172;
        packet[13] = 16;
        packet[14] = 0;
        packet[15] = 1; // src 172.16.0.1
        packet[16] = 8;
        packet[17] = 8;
        packet[18] = 8;
        packet[19] = 8; // dst 8.8.8.8
        packet[20] = 0x00;
        packet[21] = 0x35; // src port 53
        packet[22] = 0x1F;
        packet[23] = 0x90; // dst port 8080
                           // Payload bytes at 28..36
        packet[28..36].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0x00, 0x42]);

        let result = parse_ip_packet_full(&packet);
        assert!(result.is_some());
        match result.unwrap() {
            ParsedPacket::Udp {
                game_addr: addr,
                payload,
                original_info: info,
            } => {
                assert_eq!(addr.ip().to_string(), "8.8.8.8");
                assert_eq!(addr.port(), 8080);
                assert_eq!(info.src_ip.to_string(), "172.16.0.1");
                assert_eq!(info.src_port, 53);
                assert_eq!(info.dst_ip.to_string(), "8.8.8.8");
                assert_eq!(info.dst_port, 8080);
                assert_eq!(payload, &[0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0x00, 0x42]);
            }
            _ => panic!("Expected ParsedPacket::Udp"),
        }
    }

    // ---- build_response_ip_packet additional cases ----

    #[test]
    fn test_build_response_zero_length_payload() {
        let original = OriginalPacketInfo {
            src_ip: "10.0.0.1".parse().unwrap(),
            src_port: 1234,
            dst_ip: "1.2.3.4".parse().unwrap(),
            dst_port: 5678,
        };
        let packet = build_response_ip_packet(&[], original);
        // IP (20) + UDP (8) + payload (0) = 28
        assert_eq!(packet.len(), 28);
        // Verify IP version
        assert_eq!((packet[0] >> 4) & 0x0F, 4);
        // Verify protocol UDP
        assert_eq!(packet[9], 17);
    }

    #[test]
    fn test_build_response_normal_payload_field_check() {
        let payload = &[0xAA, 0xBB, 0xCC];
        let original = OriginalPacketInfo {
            src_ip: "192.168.1.100".parse().unwrap(),
            src_port: 40000,
            dst_ip: "93.184.216.34".parse().unwrap(),
            dst_port: 443,
        };
        let packet = build_response_ip_packet(payload, original);

        // Total length = 20 + 8 + 3 = 31
        assert_eq!(packet.len(), 31);
        let total_len_field = u16::from_be_bytes([packet[2], packet[3]]);
        assert_eq!(total_len_field, 31);

        // Source IP = original dst (game server)
        assert_eq!(&packet[12..16], &[93, 184, 216, 34]);
        // Dest IP = original src (client)
        assert_eq!(&packet[16..20], &[192, 168, 1, 100]);

        // Source port = original dst_port (443)
        let src_port = u16::from_be_bytes([packet[20], packet[21]]);
        assert_eq!(src_port, 443);
        // Dest port = original src_port (40000)
        let dst_port = u16::from_be_bytes([packet[22], packet[23]]);
        assert_eq!(dst_port, 40000);

        // UDP length field
        let udp_len_field = u16::from_be_bytes([packet[24], packet[25]]);
        assert_eq!(udp_len_field, 11); // 8 + 3

        // Payload
        assert_eq!(&packet[28..31], payload);
    }

    #[test]
    fn test_build_response_ip_checksum_validity() {
        let original = OriginalPacketInfo {
            src_ip: "10.0.0.5".parse().unwrap(),
            src_port: 54321,
            dst_ip: "1.2.3.4".parse().unwrap(),
            dst_port: 12345,
        };
        let packet = build_response_ip_packet(&[0x01, 0x02], original);

        // Compute checksum over the IP header (which already includes the checksum).
        // If the checksum was computed correctly, summing the full header should yield 0xFFFF
        // (or equivalently the ones-complement sum is 0).
        let mut sum: u32 = 0;
        for i in (0..20).step_by(2) {
            let word = ((packet[i] as u32) << 8) | (packet[i + 1] as u32);
            sum = sum.wrapping_add(word);
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        // After folding, ones-complement sum should be 0xFFFF
        assert_eq!(sum as u16, 0xFFFF);
    }

    #[test]
    fn test_build_response_address_port_swapping() {
        let original = OriginalPacketInfo {
            src_ip: "10.0.0.5".parse().unwrap(),
            src_port: 11111,
            dst_ip: "20.30.40.50".parse().unwrap(),
            dst_port: 22222,
        };
        let packet = build_response_ip_packet(&[0xFF], original);

        // In response, source = original dst, dest = original src
        assert_eq!(
            std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]).to_string(),
            "20.30.40.50"
        );
        assert_eq!(
            std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]).to_string(),
            "10.0.0.5"
        );
        assert_eq!(u16::from_be_bytes([packet[20], packet[21]]), 22222); // game port becomes src
        assert_eq!(u16::from_be_bytes([packet[22], packet[23]]), 11111); // client port becomes dst
    }

    // ---- calculate_ip_checksum tests ----

    #[test]
    fn test_ip_checksum_all_zeros() {
        let header = [0u8; 20];
        let checksum = calculate_ip_checksum(&header);
        // Ones complement of 0 is 0xFFFF
        assert_eq!(checksum, 0xFFFF);
    }

    #[test]
    fn test_ip_checksum_odd_length_header() {
        // Odd-length slice (unusual but the function should handle it)
        let header = [0x45, 0x00, 0x00, 0x1C, 0x00]; // 5 bytes
        let checksum = calculate_ip_checksum(&header);
        // Just verify it doesn't panic and produces a value
        assert_ne!(checksum, 0); // non-trivial input should produce non-zero complement
    }

    #[test]
    fn test_ip_checksum_self_check() {
        // Build a valid IP header, compute checksum, insert it, then verify
        let mut header = [
            0x45, 0x00, 0x00, 0x1C, // version/IHL, DSCP/ECN, total length
            0x00, 0x00, 0x40, 0x00, // ID, flags+fragment
            0x40, 0x11, 0x00, 0x00, // TTL, protocol(UDP), checksum(placeholder)
            0xC0, 0xA8, 0x01, 0x01, // src IP 192.168.1.1
            0x0A, 0x00, 0x00, 0x01, // dst IP 10.0.0.1
        ];
        let checksum = calculate_ip_checksum(&header);
        header[10] = (checksum >> 8) as u8;
        header[11] = (checksum & 0xFF) as u8;

        // Recompute over the full header including checksum
        let verify = calculate_ip_checksum(&header);
        // Should be 0 (or 0xFFFF depending on convention; RFC 1071 says
        // the ones-complement sum of the header including checksum = 0)
        // In our implementation !sum means the result is 0x0000 when header is valid
        assert!(
            verify == 0x0000 || verify == 0xFFFF,
            "Self-check should yield 0x0000 or 0xFFFF, got {:#06x}",
            verify
        );
    }

    #[test]
    fn test_ip_checksum_known_vector() {
        // Use the same test vector from the existing tests
        let header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        let checksum = calculate_ip_checksum(&header);
        assert_ne!(checksum, 0);
        // Verify the self-check: insert checksum and recompute
        let mut full_header = header;
        full_header[10] = (checksum >> 8) as u8;
        full_header[11] = (checksum & 0xFF) as u8;
        let verify = calculate_ip_checksum(&full_header);
        assert!(
            verify == 0x0000 || verify == 0xFFFF,
            "Self-check should yield 0x0000 or 0xFFFF, got {:#06x}",
            verify
        );
    }

    // ---- Roundtrip test ----

    #[test]
    fn test_roundtrip_build_then_parse() {
        let original = OriginalPacketInfo {
            src_ip: "10.0.0.5".parse().unwrap(),
            src_port: 54321,
            dst_ip: "1.2.3.4".parse().unwrap(),
            dst_port: 12345,
        };
        let payload = &[0xDE, 0xAD, 0xBE, 0xEF];
        let response_packet = build_response_ip_packet(payload, original);

        // Parse the built packet
        let parsed = parse_ip_packet_full(&response_packet);
        assert!(parsed.is_some());
        match parsed.unwrap() {
            ParsedPacket::Udp {
                game_addr: addr,
                payload: parsed_payload,
                original_info: info,
            } => {
                // In the response, src/dst are swapped from original
                // Source IP = original.dst_ip (game server)
                assert_eq!(info.src_ip.to_string(), "1.2.3.4");
                assert_eq!(info.src_port, 12345);
                // Dest IP = original.src_ip (client)
                assert_eq!(info.dst_ip.to_string(), "10.0.0.5");
                assert_eq!(info.dst_port, 54321);
                // SocketAddr should point to the packet's dest (the client)
                assert_eq!(addr.ip().to_string(), "10.0.0.5");
                assert_eq!(addr.port(), 54321);
                // Payload should survive roundtrip
                assert_eq!(parsed_payload, payload);
            }
            _ => panic!("Expected ParsedPacket::Udp"),
        }
    }
}

#[cfg(test)]
mod async_stats_http_tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn make_stats_context() -> Arc<StatsApiContext> {
        Arc::new(StatsApiContext {
            sessions: Arc::new(DashMap::new()),
            session_traffic: Arc::new(DashMap::new()),
            stats: Arc::new(Stats::new()),
            started_at: Instant::now(),
            rate_window: Mutex::new(StatsRateWindow::new()),
            connections_snapshot: RwLock::new(empty_connections_payload()),
        })
    }

    fn make_stats_context_with_sessions(
        entries: Vec<(
            [u8; SESSION_ID_LEN],
            SessionEntry,
            Option<Arc<SessionTraffic>>,
        )>,
    ) -> Arc<StatsApiContext> {
        let sessions = Arc::new(DashMap::new());
        let session_traffic = Arc::new(DashMap::new());
        let stats = Arc::new(Stats::new());
        for (sid, entry, traffic) in entries {
            sessions.insert(sid, entry);
            if let Some(t) = traffic {
                session_traffic.insert(sid, t);
            }
        }
        stats
            .active_sessions
            .store(sessions.len() as u64, Ordering::Relaxed);
        Arc::new(StatsApiContext {
            sessions,
            session_traffic,
            stats,
            started_at: Instant::now(),
            rate_window: Mutex::new(StatsRateWindow::new()),
            connections_snapshot: RwLock::new(empty_connections_payload()),
        })
    }

    // ---- render_stats_payload tests ----

    #[test]
    fn test_render_stats_empty_sessions() {
        let ctx = make_stats_context();
        let payload = render_stats_payload(&ctx);
        assert!(payload.contains("\"active_users\":0"));
        assert!(payload.contains("\"active_sessions\":0"));
        // Should be valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["active_users"], 0);
        assert_eq!(parsed["active_sessions"], 0);
    }

    #[test]
    fn test_render_stats_with_sessions_uses_atomic_counts() {
        let now_unix = unix_timestamp_secs();
        let sid1 = [0, 0, 0, 0, 0, 0, 0, 1];
        let sid2 = [0, 0, 0, 0, 0, 0, 0, 2];
        let sid3 = [0, 0, 0, 0, 0, 0, 0, 3];

        let ctx = make_stats_context_with_sessions(vec![
            (
                sid1,
                SessionEntry {
                    user_id: "user-aaa".to_string(),
                    auth_state: SessionAuthState::Authenticated,
                    client_addr: "127.0.0.1:1000".parse().unwrap(),
                    created_at_unix: now_unix,
                    last_activity: Instant::now(),
                    last_activity_unix: now_unix,
                },
                None,
            ),
            (
                sid2,
                SessionEntry {
                    user_id: "user-aaa".to_string(), // same user
                    auth_state: SessionAuthState::Authenticated,
                    client_addr: "127.0.0.1:2000".parse().unwrap(),
                    created_at_unix: now_unix,
                    last_activity: Instant::now(),
                    last_activity_unix: now_unix,
                },
                None,
            ),
            (
                sid3,
                SessionEntry {
                    user_id: "user-bbb".to_string(), // different user
                    auth_state: SessionAuthState::Legacy,
                    client_addr: "127.0.0.1:3000".parse().unwrap(),
                    created_at_unix: now_unix,
                    last_activity: Instant::now(),
                    last_activity_unix: now_unix,
                },
                None,
            ),
        ]);

        let payload = render_stats_payload(&ctx);
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        // /v1/stats intentionally uses the atomic session count instead of
        // scanning live session maps, so `active_users` mirrors sessions here.
        assert_eq!(parsed["active_users"], 3);
        // 3 sessions
        assert_eq!(parsed["active_sessions"], 3);
    }

    #[test]
    fn test_render_stats_uses_rolling_rate_window() {
        let ctx = make_stats_context();
        ctx.stats.bytes_in.store(5_000, Ordering::Relaxed);
        ctx.stats.bytes_out.store(8_000, Ordering::Relaxed);

        {
            let mut window = ctx.rate_window.lock().unwrap();
            window.last_sample_at = Some(Instant::now() - Duration::from_secs(2));
            window.last_bytes_in = 1_000;
            window.last_bytes_out = 2_000;
        }

        let payload = render_stats_payload(&ctx);
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let inbound_bps = parsed["inbound_bps"].as_u64().unwrap();
        let outbound_bps = parsed["outbound_bps"].as_u64().unwrap();

        assert!(inbound_bps >= 1_900 && inbound_bps <= 2_000);
        assert!(outbound_bps >= 2_900 && outbound_bps <= 3_000);
    }

    // ---- render_connections_payload tests ----

    #[test]
    fn test_render_connections_empty() {
        let ctx = make_stats_context();
        let payload = render_connections_payload(&ctx);
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert!(parsed["connections"].is_array());
        assert_eq!(parsed["connections"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_render_connections_single() {
        let now_unix = unix_timestamp_secs();
        let sid = [0, 0, 0, 0, 0, 0, 0, 42];
        let traffic = Arc::new(SessionTraffic::new(now_unix));
        traffic.bytes_in.store(1000, Ordering::Relaxed);
        traffic.bytes_out.store(2000, Ordering::Relaxed);

        let ctx = make_stats_context_with_sessions(vec![(
            sid,
            SessionEntry {
                user_id: "test-user".to_string(),
                auth_state: SessionAuthState::Authenticated,
                client_addr: "1.2.3.4:5678".parse().unwrap(),
                created_at_unix: now_unix,
                last_activity: Instant::now(),
                last_activity_unix: now_unix,
            },
            Some(traffic),
        )]);

        let payload = render_connections_payload(&ctx);
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let conns = parsed["connections"].as_array().unwrap();
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0]["user_id"], "test-user");
        assert_eq!(conns[0]["auth_state"], "authenticated");
        assert_eq!(conns[0]["bytes_in"], 1000);
        assert_eq!(conns[0]["bytes_out"], 2000);
        assert_eq!(conns[0]["client_endpoint"], "1.2.3.4:5678");
    }

    #[test]
    fn test_render_connections_sorted_by_last_activity_desc() {
        let now_unix = unix_timestamp_secs();
        let sid1 = [0, 0, 0, 0, 0, 0, 0, 1];
        let sid2 = [0, 0, 0, 0, 0, 0, 0, 2];

        let ctx = make_stats_context_with_sessions(vec![
            (
                sid1,
                SessionEntry {
                    user_id: "older".to_string(),
                    auth_state: SessionAuthState::Legacy,
                    client_addr: "1.1.1.1:1000".parse().unwrap(),
                    created_at_unix: now_unix - 100,
                    last_activity: Instant::now(),
                    last_activity_unix: now_unix - 100,
                },
                None,
            ),
            (
                sid2,
                SessionEntry {
                    user_id: "newer".to_string(),
                    auth_state: SessionAuthState::Legacy,
                    client_addr: "2.2.2.2:2000".parse().unwrap(),
                    created_at_unix: now_unix,
                    last_activity: Instant::now(),
                    last_activity_unix: now_unix,
                },
                None,
            ),
        ]);

        let payload = render_connections_payload(&ctx);
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let conns = parsed["connections"].as_array().unwrap();
        assert_eq!(conns.len(), 2);
        // "newer" should come first (sorted by last_activity desc)
        assert_eq!(conns[0]["user_id"], "newer");
        assert_eq!(conns[1]["user_id"], "older");
    }

    #[test]
    fn test_render_connections_json_escaping() {
        let now_unix = unix_timestamp_secs();
        let sid = [0, 0, 0, 0, 0, 0, 0, 1];

        let ctx = make_stats_context_with_sessions(vec![(
            sid,
            SessionEntry {
                user_id: "user\"with\\special\nchars".to_string(),
                auth_state: SessionAuthState::Legacy,
                client_addr: "1.1.1.1:1000".parse().unwrap(),
                created_at_unix: now_unix,
                last_activity: Instant::now(),
                last_activity_unix: now_unix,
            },
            None,
        )]);

        let payload = render_connections_payload(&ctx);
        // The raw JSON string should have escaped characters
        assert!(payload.contains("user\\\"with\\\\special\\nchars"));
        // And it should be parseable as valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let conns = parsed["connections"].as_array().unwrap();
        assert_eq!(conns.len(), 1);
        assert_eq!(
            conns[0]["user_id"].as_str().unwrap(),
            "user\"with\\special\nchars"
        );
    }

    // ---- handle_stats_http_client tests ----

    async fn send_http_request(
        token: &str,
        context: Arc<StatsApiContext>,
        request: &str,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let request_owned = request.to_string();
        let token_owned = token.to_string();

        let client_task = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream.write_all(request_owned.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            response
        });

        let (server_stream, _) = listener.accept().await.unwrap();
        let _ = handle_stats_http_client(server_stream, &token_owned, context).await;
        client_task.await.unwrap()
    }

    #[tokio::test]
    async fn test_http_get_stats_with_correct_token() {
        let ctx = make_stats_context();
        let response = send_http_request(
            "test-token",
            ctx,
            "GET /v1/stats HTTP/1.1\r\nAuthorization: Bearer test-token\r\n\r\n",
        )
        .await;
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("active_users"));
        assert!(response.contains("active_sessions"));
    }

    #[tokio::test]
    async fn test_http_get_connections_with_correct_token() {
        let ctx = make_stats_context();
        let response = send_http_request(
            "test-token",
            ctx,
            "GET /v1/connections HTTP/1.1\r\nAuthorization: Bearer test-token\r\n\r\n",
        )
        .await;
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("connections"));
    }

    #[tokio::test]
    async fn test_http_no_auth_header() {
        let ctx = make_stats_context();
        let response = send_http_request("test-token", ctx, "GET /v1/stats HTTP/1.1\r\n\r\n").await;
        assert!(response.contains("HTTP/1.1 401 Unauthorized"));
    }

    #[tokio::test]
    async fn test_http_wrong_token() {
        let ctx = make_stats_context();
        let response = send_http_request(
            "test-token",
            ctx,
            "GET /v1/stats HTTP/1.1\r\nAuthorization: Bearer wrong-token\r\n\r\n",
        )
        .await;
        assert!(response.contains("HTTP/1.1 401 Unauthorized"));
    }

    #[tokio::test]
    async fn test_http_post_method_not_allowed() {
        let ctx = make_stats_context();
        let response = send_http_request(
            "test-token",
            ctx,
            "POST /v1/stats HTTP/1.1\r\nAuthorization: Bearer test-token\r\n\r\n",
        )
        .await;
        assert!(response.contains("HTTP/1.1 405 Method Not Allowed"));
    }

    #[tokio::test]
    async fn test_http_unknown_path() {
        let ctx = make_stats_context();
        let response = send_http_request(
            "test-token",
            ctx,
            "GET /v1/unknown HTTP/1.1\r\nAuthorization: Bearer test-token\r\n\r\n",
        )
        .await;
        assert!(response.contains("HTTP/1.1 404 Not Found"));
    }

    #[tokio::test]
    async fn test_http_empty_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ctx = make_stats_context();

        let client_task = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            // Send nothing, just close
            stream.shutdown().await.unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            response
        });

        let (server_stream, _) = listener.accept().await.unwrap();
        let _ = handle_stats_http_client(server_stream, "test-token", ctx).await;
        let response = client_task.await.unwrap();
        // Empty request should result in connection close with no response or a 400
        // Based on the code, total_read == 0 returns Ok(()) with no response written
        assert!(response.is_empty() || response.contains("400"));
    }

    #[tokio::test]
    async fn test_http_oversized_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ctx = make_stats_context();

        let client_task = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            // Send a request larger than MAX_HTTP_REQUEST_SIZE (8192)
            // Use a huge header to exceed the limit.
            let mut request = String::from("GET /v1/stats HTTP/1.1\r\n");
            // Add a header that pushes us past MAX_HTTP_REQUEST_SIZE without \r\n\r\n terminator
            request.push_str(&format!("X-Padding: {}\r\n", "A".repeat(8200)));
            // The server may close the connection before we finish writing,
            // so ignore write/shutdown errors.
            let _ = stream.write_all(request.as_bytes()).await;
            let _ = stream.shutdown().await;
            let mut response = Vec::new();
            // read_to_end may also get ConnectionReset on some platforms
            let _ = stream.read_to_end(&mut response).await;
            String::from_utf8_lossy(&response).to_string()
        });

        let (server_stream, _) = listener.accept().await.unwrap();
        let _ = handle_stats_http_client(server_stream, "test-token", ctx).await;
        let response = client_task.await.unwrap();
        assert!(response.contains("431"));
    }
}
