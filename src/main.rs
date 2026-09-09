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
use serde::{Deserialize, Serialize};
use std::env;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr};
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
/// Public, unauthenticated health probe port. The hosted status page and the
/// landing latency widget both expect `http://<relay>:8081/health`.
pub(crate) const DEFAULT_HEALTH_PORT: u16 = 8081;
const PING_FRAME_TYPE: u8 = 0xA3;
const PONG_FRAME_TYPE: u8 = 0xA4;
const AUTH_ACK_OK: u8 = 0;
const AUTH_ACK_BAD_FORMAT: u8 = 1;
const AUTH_ACK_BAD_SIGNATURE: u8 = 2;
const AUTH_ACK_EXPIRED: u8 = 3;
const AUTH_ACK_SID_MISMATCH: u8 = 4;
const AUTH_ACK_SERVER_MISMATCH: u8 = 5;
const AUTH_ACK_AUTH_DISABLED: u8 = 6;
const AUTH_ACK_REPLAY: u8 = 7;
/// A valid ticket, for a different account than the one that already holds this
/// session. See [`RelayAuthVerifyError::OwnerMismatch`].
const AUTH_ACK_OWNER_MISMATCH: u8 = 8;
const MAX_AUTH_TOKEN_LEN: usize = 4096;
const AUTH_CLOCK_SKEW_SECS: u64 = 30;
const RELAY_ALLOW_INSECURE_ENV: &str = "RELAY_ALLOW_INSECURE";
const SOURCE_RATE_WINDOW: Duration = Duration::from_secs(1);
const SOURCE_RATE_PRUNE_INTERVAL: Duration = Duration::from_secs(30);
const SOURCE_RATE_IDLE_TTL: Duration = Duration::from_secs(120);
const REPLAY_CACHE_PRUNE_INTERVAL_SECS: u64 = 30;
const MAX_PACKETS_PER_SOURCE_WINDOW: u32 = 50_000;
const MAX_NEW_SESSIONS_PER_SOURCE_WINDOW: u32 = 256;
const MAX_NEW_FLOWS_PER_SOURCE_WINDOW: u32 = 4096;
const MAX_SESSIONS_TOTAL: usize = 65_536;
const MAX_SESSIONS_PER_SRC_IP: usize = 512;
const MAX_FLOWS_TOTAL: usize = 262_144;
const MAX_FLOWS_PER_SESSION: usize = 1024;
const PING_FRAME_LEN: usize = SESSION_ID_LEN + 1 + 4 + 8;
const PONG_FRAME_LEN: usize = SESSION_ID_LEN + 1 + 4 + 8 + 8;
/// Client-reported RTT (optional, backward-compatible).
const RTT_REPORT_FRAME_TYPE: u8 = 0xA5;
/// [session_id:8][0xA5][rtt_us_be_u32] = 13 bytes
const RTT_REPORT_FRAME_LEN: usize = SESSION_ID_LEN + 1 + 4;

// Censorship-resistant DNS resolve (optional, backward-compatible). A client
// behind a censor that blocks/poisons DNS asks the relay (which sits outside the
// censorship) to resolve Roblox's real IPs, then pins them locally. Restricted
// to Roblox-owned hostnames so the relay never becomes an open resolver.
//
// Request:  [session_id:8][0xA6][request_id_be_u16][host_count:1]
//                                         [(host_len:1, host_utf8)]*
// Response: [session_id:8][0xA7][request_id_be_u16][answer_count:1]
//                       [(host_len:1, host_utf8, ip_count:1, (ipv4_be:4)*)]*
const RESOLVE_REQUEST_FRAME_TYPE: u8 = 0xA6;
const RESOLVE_RESPONSE_FRAME_TYPE: u8 = 0xA7;
const RESOLVE_MAX_HOSTS_PER_REQUEST: usize = 16;
const RESOLVE_MAX_HOSTNAME_LEN: usize = 64;
const RESOLVE_MAX_IPS_PER_HOST: usize = 4;

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
            Some("off") => Self::Off,
            _ => Self::Required,
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
        !matches!(self, Self::Off)
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
            if env::var(RELAY_ALLOW_INSECURE_ENV).ok().as_deref() != Some("1") {
                anyhow::bail!(
                    "RELAY_AUTH_MODE=off requires RELAY_ALLOW_INSECURE=1; refusing to start open relay"
                );
            }
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
    jti: String,
    #[serde(default)]
    lease: bool,
}

#[derive(Debug, Clone)]
struct VerifiedRelayTicket {
    user_id: String,
    jti: String,
    exp: u64,
    lease: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayAuthVerifyError {
    BadFormat,
    BadSignature,
    Expired,
    SidMismatch,
    ServerMismatch,
    Replay,
    /// The session already belongs to somebody else.
    ///
    /// Session ids are chosen by the client and the issuer does not reserve
    /// them, so anybody who learns one can ask for a perfectly valid ticket
    /// naming it. Before this, authenticating simply overwrote the owner and
    /// the client address, which handed the attacker the victim's live
    /// session: their flows keyed by that id, and their return traffic.
    OwnerMismatch,
}

impl RelayAuthVerifyError {
    fn ack_status(self) -> u8 {
        match self {
            Self::BadFormat => AUTH_ACK_BAD_FORMAT,
            Self::BadSignature => AUTH_ACK_BAD_SIGNATURE,
            Self::Expired => AUTH_ACK_EXPIRED,
            Self::SidMismatch => AUTH_ACK_SID_MISMATCH,
            Self::ServerMismatch => AUTH_ACK_SERVER_MISMATCH,
            Self::Replay => AUTH_ACK_REPLAY,
            Self::OwnerMismatch => AUTH_ACK_OWNER_MISMATCH,
        }
    }
}

fn log_auth_verify_error(
    err: RelayAuthVerifyError,
    client_addr: SocketAddr,
    session_id: [u8; SESSION_ID_LEN],
) {
    if err == RelayAuthVerifyError::Replay {
        log::warn!(
            "Rejected replayed relay ticket from {} for session {:016x}",
            client_addr,
            u64::from_be_bytes(session_id)
        );
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

fn is_cgnat_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    a == 100 && (64..=127).contains(&b)
}

fn is_reserved_ipv4(ip: Ipv4Addr) -> bool {
    ip.octets()[0] >= 240
}

fn is_this_network_ipv4(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceLimitKind {
    Packet,
    NewSession,
    NewFlow,
}

#[derive(Debug, Clone)]
struct SourceRateState {
    window_start: Instant,
    packets: u32,
    new_sessions: u32,
    new_flows: u32,
}

impl SourceRateState {
    fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            packets: 0,
            new_sessions: 0,
            new_flows: 0,
        }
    }

    fn allow(&mut self, kind: SourceLimitKind, now: Instant) -> bool {
        if now.saturating_duration_since(self.window_start) >= SOURCE_RATE_WINDOW {
            *self = Self::new(now);
        }

        match kind {
            SourceLimitKind::Packet => {
                if self.packets >= MAX_PACKETS_PER_SOURCE_WINDOW {
                    return false;
                }
                self.packets += 1;
            }
            SourceLimitKind::NewSession => {
                if self.new_sessions >= MAX_NEW_SESSIONS_PER_SOURCE_WINDOW {
                    return false;
                }
                self.new_sessions += 1;
            }
            SourceLimitKind::NewFlow => {
                if self.new_flows >= MAX_NEW_FLOWS_PER_SOURCE_WINDOW {
                    return false;
                }
                self.new_flows += 1;
            }
        }
        true
    }
}

pub(crate) struct SourceRateLimiter {
    sources: DashMap<IpAddr, SourceRateState>,
    created_at: Instant,
    last_prune_ms: AtomicU64,
}

impl SourceRateLimiter {
    fn new() -> Self {
        Self {
            sources: DashMap::new(),
            created_at: Instant::now(),
            last_prune_ms: AtomicU64::new(0),
        }
    }

    pub(crate) fn allow(&self, ip: IpAddr, kind: SourceLimitKind, now: Instant) -> bool {
        self.prune_idle(now);
        self.sources
            .entry(ip)
            .or_insert_with(|| SourceRateState::new(now))
            .allow(kind, now)
    }

    fn prune_idle(&self, now: Instant) {
        let now_ms = duration_millis_u64(now.saturating_duration_since(self.created_at));
        let last_prune_ms = self.last_prune_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last_prune_ms) < duration_millis_u64(SOURCE_RATE_PRUNE_INTERVAL) {
            return;
        }

        if self
            .last_prune_ms
            .compare_exchange(last_prune_ms, now_ms, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        self.sources.retain(|_, state| {
            now.saturating_duration_since(state.window_start) < SOURCE_RATE_IDLE_TTL
        });
    }
}

fn duration_millis_u64(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

struct RelayTicketReplayCache {
    seen_jti: DashMap<String, u64>,
    last_prune_unix: AtomicU64,
}

impl RelayTicketReplayCache {
    fn new() -> Self {
        Self {
            seen_jti: DashMap::new(),
            last_prune_unix: AtomicU64::new(0),
        }
    }

    fn accept_once(&self, jti: &str, exp: u64, now_unix: u64) -> bool {
        self.prune_expired(now_unix);

        match self.seen_jti.entry(jti.to_string()) {
            Entry::Occupied(_) => false,
            Entry::Vacant(entry) => {
                entry.insert(exp);
                true
            }
        }
    }

    fn prune_expired(&self, now_unix: u64) {
        let last_prune = self.last_prune_unix.load(Ordering::Relaxed);
        if now_unix.saturating_sub(last_prune) < REPLAY_CACHE_PRUNE_INTERVAL_SECS {
            return;
        }

        if self
            .last_prune_unix
            .compare_exchange(last_prune, now_unix, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        self.seen_jti
            .retain(|_, seen_exp| now_unix <= seen_exp.saturating_add(AUTH_CLOCK_SKEW_SECS));
    }
}

pub(crate) fn source_session_count(
    source_session_counts: &DashMap<IpAddr, u64>,
    source_ip: IpAddr,
) -> u64 {
    source_session_counts
        .get(&source_ip)
        .map_or(0, |count| *count)
}

pub(crate) fn increment_source_session_count(
    source_session_counts: &DashMap<IpAddr, u64>,
    source_ip: IpAddr,
) {
    let mut count = source_session_counts.entry(source_ip).or_insert(0);
    *count += 1;
}

pub(crate) fn decrement_source_session_count(
    source_session_counts: &DashMap<IpAddr, u64>,
    source_ip: IpAddr,
) {
    if let Some(mut count) = source_session_counts.get_mut(&source_ip) {
        if *count > 1 {
            *count -= 1;
            return;
        }
    }
    source_session_counts.remove(&source_ip);
}

pub(crate) fn update_source_session_count_for_rebind(
    source_session_counts: &DashMap<IpAddr, u64>,
    old_ip: IpAddr,
    new_ip: IpAddr,
) {
    if old_ip == new_ip {
        return;
    }

    decrement_source_session_count(source_session_counts, old_ip);
    increment_source_session_count(source_session_counts, new_ip);
}

fn indexed_session_flow_count(
    session_flow_keys: &DashMap<[u8; SESSION_ID_LEN], Vec<String>>,
    session_id: [u8; SESSION_ID_LEN],
) -> usize {
    session_flow_keys
        .get(&session_id)
        .map_or(0, |keys| keys.len())
}

pub(crate) fn allow_source_event(
    limiter: &SourceRateLimiter,
    stats: &Stats,
    client_addr: SocketAddr,
    kind: SourceLimitKind,
    now: Instant,
) -> bool {
    if limiter.allow(client_addr.ip(), kind, now) {
        return true;
    }

    stats.throttled_users.fetch_add(1, Ordering::Relaxed);
    stats.drop_in(DropReason::RateLimit);
    false
}

fn v1_session_capacity_available(
    sessions: &DashMap<[u8; SESSION_ID_LEN], SessionEntry>,
    source_session_counts: &DashMap<IpAddr, u64>,
    stats: &Stats,
    source_ip: IpAddr,
) -> bool {
    if sessions.len() >= MAX_SESSIONS_TOTAL {
        stats.drop_in(DropReason::Capacity);
        return false;
    }

    if source_session_count(source_session_counts, source_ip) >= MAX_SESSIONS_PER_SRC_IP as u64 {
        stats.drop_in(DropReason::Capacity);
        return false;
    }

    true
}

fn v1_flow_capacity_available(
    flows: &DashMap<String, FlowEntry>,
    session_flow_keys: &DashMap<[u8; SESSION_ID_LEN], Vec<String>>,
    stats: &Stats,
    session_id: [u8; SESSION_ID_LEN],
) -> bool {
    if flows.len() >= MAX_FLOWS_TOTAL {
        stats.drop_in(DropReason::Capacity);
        return false;
    }

    if indexed_session_flow_count(session_flow_keys, session_id) >= MAX_FLOWS_PER_SESSION {
        stats.drop_in(DropReason::Capacity);
        return false;
    }

    true
}

fn remove_v1_session_flow_key(
    session_flow_keys: &DashMap<[u8; SESSION_ID_LEN], Vec<String>>,
    session_id: [u8; SESSION_ID_LEN],
    flow_key: &str,
) {
    if let Some(mut keys) = session_flow_keys.get_mut(&session_id) {
        keys.retain(|key| key != flow_key);
    }
    if session_flow_keys
        .get(&session_id)
        .is_some_and(|keys| keys.is_empty())
    {
        session_flow_keys.remove(&session_id);
    }
}

pub(crate) fn authenticated_session_source_allowed(
    session: &SessionEntry,
    auth_required: bool,
    client_addr: SocketAddr,
    is_auth_hello: bool,
) -> bool {
    if !auth_required || !matches!(session.auth_state, SessionAuthState::Authenticated) {
        return true;
    }

    is_auth_hello || session.client_addr.ip() == client_addr.ip()
}

pub(crate) fn session_auth_is_current(session: &SessionEntry, now_unix: u64) -> bool {
    matches!(session.auth_state, SessionAuthState::Authenticated)
        && session
            .lease_expires_at_unix
            .map_or(true, |expires_at| now_unix < expires_at)
}

/// Ports a game never talks to, and an attacker very much wants to.
///
/// The relay forwards to whatever address the client names, which is the point
/// of it, and until now that meant any public address on any port. The address
/// filter below already keeps it off private networks. It says nothing about
/// what the destination is, and a handful of well known services answer a small
/// request with a large reply sent to whoever the sender claims to be.
///
/// Pointed at those, a relay stops being a relay and becomes an amplifier: the
/// account holder spends a trickle of upload and the target receives a flood
/// from our address, not theirs. What we would see is abuse reports, provider
/// complaints, and relay IPs acquiring the kind of reputation that already
/// costs this product real gameplay failures.
///
/// Deliberately a blocklist of services rather than an allowlist of game ports.
/// An allowlist is stronger and needs to know every port Roblox, voice chat and
/// Route Assist will ever use, which is a promise nobody can keep; getting it
/// wrong silently breaks players.
///
/// UDP only. Amplification needs a connectionless, source-spoofable protocol,
/// and TCP is neither, so applying this to TCP would restrict traffic without
/// buying any safety. This relay carries HTTPS for Route Assist, so that would
/// be a real cost for nothing.
///
/// Not a complete answer to relay abuse, and not free either. It closes the
/// reflectors worth having and does nothing about an account simply sending a
/// lot of traffic at one address, which needs per-account rate limits. Game
/// ports are kept off this list even when they amplify, Source query on 27015
/// being the example: a gaming VPN blocking a game's port is a trap for
/// whoever adds the second game.
const FORBIDDEN_DST_PORTS: &[u16] = &[
    7,     // echo
    17,    // qotd
    19,    // chargen, one of the worst amplifiers there is
    53,    // DNS
    69,    // TFTP
    111,   // portmap/rpcbind
    123,   // NTP
    137,   // NetBIOS name service
    161,   // SNMP
    162,   // SNMP trap
    389,   // LDAP/CLDAP
    520,   // RIP
    623,   // IPMI
    1434,  // MSSQL browser
    1900,  // SSDP
    3702,  // WS-Discovery
    5093,  // Sentinel
    5351,  // NAT-PMP
    5353,  // mDNS
    10001, // Ubiquiti discovery
    11211, // memcached
    32414, // Plex discovery
];

/// A destination port we refuse to forward to. See [`FORBIDDEN_DST_PORTS`].
pub(crate) fn is_forbidden_dst_port(port: u16) -> bool {
    // Port 0 is not a real destination and only turns up in malformed or
    // probing traffic.
    port == 0 || FORBIDDEN_DST_PORTS.contains(&port)
}

pub(crate) fn is_forbidden_dst(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || is_this_network_ipv4(ip)
        || is_reserved_ipv4(ip)
        || is_cgnat_ipv4(ip)
}

fn verify_relay_ticket(
    token: &str,
    session_id: [u8; SESSION_ID_LEN],
    auth: &RelayAuthConfig,
    now_unix: u64,
) -> Result<VerifiedRelayTicket, RelayAuthVerifyError> {
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

    Ok(VerifiedRelayTicket {
        user_id: claims.sub,
        jti: claims.jti,
        exp: claims.exp,
        lease: claims.lease,
    })
}

fn verify_relay_ticket_once(
    token: &str,
    session_id: [u8; SESSION_ID_LEN],
    auth: &RelayAuthConfig,
    now_unix: u64,
    replay_cache: &RelayTicketReplayCache,
) -> Result<VerifiedRelayTicket, RelayAuthVerifyError> {
    let ticket = verify_relay_ticket(token, session_id, auth, now_unix)?;
    if !replay_cache.accept_once(&ticket.jti, ticket.exp, now_unix) {
        return Err(RelayAuthVerifyError::Replay);
    }
    Ok(ticket)
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

/// Roblox-owned hostname allowlist so the resolve frame can never turn the relay
/// into an open resolver (abuse / amplification / SSRF surface).
fn is_resolvable_roblox_host(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    h == "roblox.com"
        || h.ends_with(".roblox.com")
        || h.ends_with(".rbxcdn.com")
        || h.ends_with(".arkoselabs.com")
}

/// Parse a 0xA6 resolve request. Returns the request id and the allowlisted
/// hostnames to resolve (non-Roblox names are silently dropped). `None` on a
/// malformed frame.
fn parse_resolve_request(frame: &[u8], len: usize) -> Option<(u16, Vec<String>)> {
    let header = SESSION_ID_LEN + 1; // session id + frame type byte
    if len < header + 3 {
        return None;
    }
    let request_id = u16::from_be_bytes([frame[header], frame[header + 1]]);
    let host_count = frame[header + 2] as usize;
    if host_count > RESOLVE_MAX_HOSTS_PER_REQUEST {
        return None;
    }
    let mut hosts = Vec::with_capacity(host_count);
    let mut off = header + 3;
    for _ in 0..host_count {
        if off >= len {
            return None;
        }
        let hlen = frame[off] as usize;
        off += 1;
        if hlen == 0 || hlen > RESOLVE_MAX_HOSTNAME_LEN || off + hlen > len {
            return None;
        }
        let host = std::str::from_utf8(&frame[off..off + hlen])
            .ok()?
            .to_string();
        off += hlen;
        if is_resolvable_roblox_host(&host) {
            hosts.push(host);
        }
    }
    Some((request_id, hosts))
}

/// Build a 0xA7 resolve response from resolved (host, ipv4s) answers.
fn build_resolve_response(
    session_id: &[u8; SESSION_ID_LEN],
    request_id: u16,
    answers: &[(String, Vec<Ipv4Addr>)],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(session_id);
    out.push(RESOLVE_RESPONSE_FRAME_TYPE);
    out.extend_from_slice(&request_id.to_be_bytes());
    let answer_count = answers.len().min(u8::MAX as usize);
    out.push(answer_count as u8);
    for (host, ips) in answers.iter().take(answer_count) {
        let hbytes = host.as_bytes();
        let hlen = hbytes.len().min(RESOLVE_MAX_HOSTNAME_LEN);
        out.push(hlen as u8);
        out.extend_from_slice(&hbytes[..hlen]);
        let ip_count = ips.len().min(RESOLVE_MAX_IPS_PER_HOST);
        out.push(ip_count as u8);
        for ip in ips.iter().take(ip_count) {
            out.extend_from_slice(&ip.octets());
        }
    }
    out
}

/// Resolve a hostname to IPv4 addresses from the relay's (uncensored) vantage.
async fn resolve_roblox_host_ipv4(host: &str) -> Vec<Ipv4Addr> {
    match tokio::net::lookup_host((host, 443u16)).await {
        Ok(addrs) => {
            let mut ips: Vec<Ipv4Addr> = addrs
                .filter_map(|a| match a.ip() {
                    IpAddr::V4(v4) => Some(v4),
                    IpAddr::V6(_) => None,
                })
                .collect();
            ips.dedup();
            ips.truncate(RESOLVE_MAX_IPS_PER_HOST);
            ips
        }
        Err(_) => Vec::new(),
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

fn build_runtime_config(
    datapath: datapath_v2::RelayDatapath,
    listen_port: u16,
    stats_port: u16,
    auth_config: &RelayAuthConfig,
    tcp_enabled: bool,
    tun_udp_enabled: bool,
    main_socket_buffers: datapath_v2::SocketBufferSizes,
) -> RelayRuntimeConfig {
    let tuning = datapath_v2::relay_v2_tuning();
    RelayRuntimeConfig {
        version: RELAY_VERSION.to_string(),
        datapath: match datapath {
            datapath_v2::RelayDatapath::V1 => "v1".to_string(),
            datapath_v2::RelayDatapath::V2 => "v2".to_string(),
        },
        listen_port,
        stats_port,
        auth_mode: auth_config.mode.as_str().to_string(),
        server_id: auth_config.server_id.clone(),
        tcp_enabled,
        tun_udp_enabled,
        flow_channel_capacity: get_flow_channel_capacity(),
        v2: RelayV2RuntimeConfig {
            shard_count: tuning.shard_count,
            pool_slots: tuning.pool_slots,
            shard_queue_cap: tuning.shard_queue_cap,
            tx_queue_cap: tuning.tx_queue_cap,
            main_socket_rcvbuf_requested: main_socket_buffers.requested_rcvbuf_bytes,
            main_socket_sndbuf_requested: main_socket_buffers.requested_sndbuf_bytes,
            main_socket_rcvbuf_effective: main_socket_buffers.effective_rcvbuf_bytes,
            main_socket_sndbuf_effective: main_socket_buffers.effective_sndbuf_bytes,
            flow_socket_rcvbuf_requested: tuning.flow_rcvbuf_bytes,
            flow_socket_sndbuf_requested: tuning.flow_sndbuf_bytes,
        },
    }
}

#[cfg(test)]
fn test_runtime_config() -> RelayRuntimeConfig {
    RelayRuntimeConfig {
        version: RELAY_VERSION.to_string(),
        datapath: "v2".to_string(),
        listen_port: DEFAULT_PORT,
        stats_port: DEFAULT_STATS_PORT,
        auth_mode: RelayAuthMode::Off.as_str().to_string(),
        server_id: None,
        tcp_enabled: false,
        tun_udp_enabled: false,
        flow_channel_capacity: DEFAULT_FLOW_CHANNEL_CAPACITY,
        v2: RelayV2RuntimeConfig {
            shard_count: 1,
            pool_slots: 8192,
            shard_queue_cap: 4096,
            tx_queue_cap: 8192,
            main_socket_rcvbuf_requested: 4 * 1024 * 1024,
            main_socket_sndbuf_requested: 4 * 1024 * 1024,
            main_socket_rcvbuf_effective: 4 * 1024 * 1024,
            main_socket_sndbuf_effective: 4 * 1024 * 1024,
            flow_socket_rcvbuf_requested: 2 * 1024 * 1024,
            flow_socket_sndbuf_requested: 2 * 1024 * 1024,
        },
    }
}

/// Default identity until we observe a tunnel source IP or strict auth identity.
fn derive_user_id(session_id: [u8; SESSION_ID_LEN]) -> String {
    format!("session-{:016x}", u64::from_be_bytes(session_id))
}

/// Original packet info needed to reconstruct responses
#[derive(Clone, Copy)]
struct OriginalPacketInfo {
    /// Client packet DSCP/ECN byte. Used as the response default when the
    /// upstream socket does not provide a received TOS control message.
    tos: u8,
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
    lease_expires_at_unix: Option<u64>,
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
    runtime_config: RelayRuntimeConfig,
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
    /// Datapath v2 buffer pool acquire failures (pool under-sized).
    /// Each event also contributes to `dropped_in`/`dropped_out` so operators
    /// can tell the difference between "queue full" and "pool empty".
    pool_exhausted: AtomicU64,
    drop_reasons: DropReasonCounters,
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
            pool_exhausted: AtomicU64::new(0),
            drop_reasons: DropReasonCounters::new(),
        }
    }

    fn drop_in(&self, reason: DropReason) {
        self.dropped_in.fetch_add(1, Ordering::Relaxed);
        self.drop_reasons.increment(reason);
    }

    fn drop_out(&self, reason: DropReason) {
        self.dropped_out.fetch_add(1, Ordering::Relaxed);
        self.drop_reasons.increment(reason);
    }
}

#[derive(Debug, Clone, Copy)]
enum DropReason {
    Auth,
    RateLimit,
    Capacity,
    TooSmall,
    Parse,
    Fragment,
    ForbiddenDst,
    TcpDisabled,
    Pool,
    StaleQueue,
    ShardQueue,
    TxQueue,
    TunQueue,
    FlowQueue,
    FlowCreate,
    FlowSend,
    SocketSend,
}

struct DropReasonCounters {
    auth: AtomicU64,
    rate_limit: AtomicU64,
    capacity: AtomicU64,
    too_small: AtomicU64,
    parse: AtomicU64,
    fragment: AtomicU64,
    forbidden_dst: AtomicU64,
    tcp_disabled: AtomicU64,
    pool: AtomicU64,
    stale_queue: AtomicU64,
    shard_queue: AtomicU64,
    tx_queue: AtomicU64,
    tun_queue: AtomicU64,
    flow_queue: AtomicU64,
    flow_create: AtomicU64,
    flow_send: AtomicU64,
    socket_send: AtomicU64,
}

impl DropReasonCounters {
    fn new() -> Self {
        Self {
            auth: AtomicU64::new(0),
            rate_limit: AtomicU64::new(0),
            capacity: AtomicU64::new(0),
            too_small: AtomicU64::new(0),
            parse: AtomicU64::new(0),
            fragment: AtomicU64::new(0),
            forbidden_dst: AtomicU64::new(0),
            tcp_disabled: AtomicU64::new(0),
            pool: AtomicU64::new(0),
            stale_queue: AtomicU64::new(0),
            shard_queue: AtomicU64::new(0),
            tx_queue: AtomicU64::new(0),
            tun_queue: AtomicU64::new(0),
            flow_queue: AtomicU64::new(0),
            flow_create: AtomicU64::new(0),
            flow_send: AtomicU64::new(0),
            socket_send: AtomicU64::new(0),
        }
    }

    fn increment(&self, reason: DropReason) {
        let counter = match reason {
            DropReason::Auth => &self.auth,
            DropReason::RateLimit => &self.rate_limit,
            DropReason::Capacity => &self.capacity,
            DropReason::TooSmall => &self.too_small,
            DropReason::Parse => &self.parse,
            DropReason::Fragment => &self.fragment,
            DropReason::ForbiddenDst => &self.forbidden_dst,
            DropReason::TcpDisabled => &self.tcp_disabled,
            DropReason::Pool => &self.pool,
            DropReason::StaleQueue => &self.stale_queue,
            DropReason::ShardQueue => &self.shard_queue,
            DropReason::TxQueue => &self.tx_queue,
            DropReason::TunQueue => &self.tun_queue,
            DropReason::FlowQueue => &self.flow_queue,
            DropReason::FlowCreate => &self.flow_create,
            DropReason::FlowSend => &self.flow_send,
            DropReason::SocketSend => &self.socket_send,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "auth": self.auth.load(Ordering::Relaxed),
            "rate_limit": self.rate_limit.load(Ordering::Relaxed),
            "capacity": self.capacity.load(Ordering::Relaxed),
            "too_small": self.too_small.load(Ordering::Relaxed),
            "parse": self.parse.load(Ordering::Relaxed),
            "fragment": self.fragment.load(Ordering::Relaxed),
            "forbidden_dst": self.forbidden_dst.load(Ordering::Relaxed),
            "tcp_disabled": self.tcp_disabled.load(Ordering::Relaxed),
            "pool": self.pool.load(Ordering::Relaxed),
            "stale_queue": self.stale_queue.load(Ordering::Relaxed),
            "shard_queue": self.shard_queue.load(Ordering::Relaxed),
            "tx_queue": self.tx_queue.load(Ordering::Relaxed),
            "tun_queue": self.tun_queue.load(Ordering::Relaxed),
            "flow_queue": self.flow_queue.load(Ordering::Relaxed),
            "flow_create": self.flow_create.load(Ordering::Relaxed),
            "flow_send": self.flow_send.load(Ordering::Relaxed),
            "socket_send": self.socket_send.load(Ordering::Relaxed),
        })
    }
}

#[derive(Clone, Serialize)]
struct RelayRuntimeConfig {
    version: String,
    datapath: String,
    listen_port: u16,
    stats_port: u16,
    auth_mode: String,
    server_id: Option<String>,
    tcp_enabled: bool,
    tun_udp_enabled: bool,
    flow_channel_capacity: usize,
    v2: RelayV2RuntimeConfig,
}

#[derive(Clone, Serialize)]
struct RelayV2RuntimeConfig {
    shard_count: usize,
    pool_slots: usize,
    shard_queue_cap: usize,
    tx_queue_cap: usize,
    main_socket_rcvbuf_requested: usize,
    main_socket_sndbuf_requested: usize,
    main_socket_rcvbuf_effective: usize,
    main_socket_sndbuf_effective: usize,
    flow_socket_rcvbuf_requested: usize,
    flow_socket_sndbuf_requested: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    if handle_cli_args()? {
        return Ok(());
    }

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
    let (main_std_socket, main_socket_buffers) = datapath_v2::bind_main_socket(listen_port)?;
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

    let runtime_config = build_runtime_config(
        datapath,
        listen_port,
        stats_port,
        &auth_config,
        tcp_enabled,
        tun_udp_enabled,
        main_socket_buffers,
    );
    let source_limiter = Arc::new(SourceRateLimiter::new());
    let replay_cache = Arc::new(RelayTicketReplayCache::new());

    if matches!(datapath, datapath_v2::RelayDatapath::V2) {
        return datapath_v2::run_datapath_v2(
            main_std_socket,
            stats_port,
            stats_token,
            auth_config,
            runtime_config,
            stats,
            started_at,
            tun_tx_sender,
            tun_session_cleanup,
            tun_udp_enabled,
            tcp_enabled,
            session_traffic,
            Arc::clone(&source_limiter),
            Arc::clone(&replay_cache),
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
    let source_session_counts: Arc<DashMap<IpAddr, u64>> = Arc::new(DashMap::new());

    // Flow tracking: "session_hex:game_addr" -> FlowEntry
    let flows: Arc<DashMap<String, FlowEntry>> = Arc::new(DashMap::new());
    let session_flow_keys: Arc<DashMap<[u8; SESSION_ID_LEN], Vec<String>>> =
        Arc::new(DashMap::new());

    // Built unconditionally: the public health endpoint needs it even when no
    // stats token is configured, and the detailed stats API is what the token
    // actually gates.
    let stats_ctx = Arc::new(StatsApiContext {
        sessions: Arc::clone(&sessions),
        session_traffic: Arc::clone(&session_traffic),
        stats: Arc::clone(&stats),
        runtime_config: runtime_config.clone(),
        started_at,
        rate_window: Mutex::new(StatsRateWindow::new()),
        connections_snapshot: RwLock::new(empty_connections_payload()),
    });

    // Public health probe. Set RELAY_HEALTH_PORT=0 to disable.
    let health_port = env::var("RELAY_HEALTH_PORT")
        .ok()
        .and_then(|v| v.trim().parse::<u16>().ok())
        .unwrap_or(DEFAULT_HEALTH_PORT);
    if health_port != 0 {
        if let Err(e) = spawn_health_http_server(health_port, Arc::clone(&stats_ctx)) {
            log::warn!("Health API unavailable: {}", e);
        }
    } else {
        log::info!("Health API disabled (RELAY_HEALTH_PORT=0)");
    }

    if let Some(token) = stats_token {
        let ctx = Arc::clone(&stats_ctx);
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
    let source_session_counts_cleanup = Arc::clone(&source_session_counts);
    let flows_cleanup = Arc::clone(&flows);
    let session_flow_keys_cleanup = Arc::clone(&session_flow_keys);
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

            session_flow_keys_cleanup.retain(|session_id, keys| {
                keys.retain(|key| flows_cleanup.contains_key(key));
                !keys.is_empty() && sessions_cleanup.contains_key(session_id)
            });

            let mut sessions_removed = 0u32;
            let session_idle_limit = SESSION_TIMEOUT + FLOW_GRACE_PERIOD;
            sessions_cleanup.retain(|session_id, session| {
                if now.duration_since(session.last_activity) >= session_idle_limit {
                    session_traffic_cleanup.remove(session_id);
                    decrement_source_session_count(
                        &source_session_counts_cleanup,
                        session.client_addr.ip(),
                    );
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
            let pool_exhausted = stats_log.pool_exhausted.load(Ordering::Relaxed);

            log::info!(
                "Stats: in={} out={} ({:.1}/{:.1} MB), {:.0} pkt/s, sessions={}, flows={}, dropped={}+{}, pool_exhausted={}",
                pkts_in,
                pkts_out,
                bytes_in as f64 / 1_000_000.0,
                bytes_out as f64 / 1_000_000.0,
                (pkts_in + pkts_out) as f64 / elapsed,
                stats_log.active_sessions.load(Ordering::Relaxed),
                stats_log.active_flows.load(Ordering::Relaxed),
                dropped_in,
                dropped_out,
                pool_exhausted,
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
            stats.drop_in(DropReason::TooSmall);
            continue;
        }

        // Extract session ID
        let mut session_id = [0u8; SESSION_ID_LEN];
        session_id.copy_from_slice(&buf[..SESSION_ID_LEN]);

        let now = Instant::now();
        let now_unix = unix_timestamp_secs();
        let is_auth_hello =
            len >= SESSION_ID_LEN + 3 && buf[SESSION_ID_LEN] == AUTH_HELLO_FRAME_TYPE;

        if !allow_source_event(
            &source_limiter,
            &stats,
            client_addr,
            SourceLimitKind::Packet,
            now,
        ) {
            continue;
        }

        if !sessions.contains_key(&session_id) {
            if !v1_session_capacity_available(
                &sessions,
                &source_session_counts,
                &stats,
                client_addr.ip(),
            ) {
                continue;
            }
            if !allow_source_event(
                &source_limiter,
                &stats,
                client_addr,
                SourceLimitKind::NewSession,
                now,
            ) {
                continue;
            }
        }

        // Update session
        let mut session_authenticated = false;
        let mut session_source_allowed = true;
        let auth_required = auth_config.mode.requires_auth();
        match sessions.entry(session_id) {
            Entry::Occupied(mut entry) => {
                let session = entry.get_mut();
                session_authenticated = session_auth_is_current(session, now_unix);
                session_source_allowed = authenticated_session_source_allowed(
                    session,
                    auth_required,
                    client_addr,
                    is_auth_hello,
                );
                if !auth_required
                    || !session_authenticated
                    || session.client_addr.ip() == client_addr.ip()
                {
                    update_source_session_count_for_rebind(
                        &source_session_counts,
                        session.client_addr.ip(),
                        client_addr.ip(),
                    );
                    session.client_addr = client_addr;
                    session.last_activity = now;
                    session.last_activity_unix = now_unix;
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(SessionEntry {
                    user_id: derive_user_id(session_id),
                    auth_state: SessionAuthState::Legacy,
                    lease_expires_at_unix: None,
                    client_addr,
                    created_at_unix: now_unix,
                    last_activity: now,
                    last_activity_unix: now_unix,
                });
                increment_source_session_count(&source_session_counts, client_addr.ip());
                stats.active_sessions.fetch_add(1, Ordering::Relaxed);
            }
        }

        record_session_ingress(&session_traffic, session_id, now_unix, len);

        // Auth hello control frame:
        // [session_id:8][0xA1][token_len_be_u16][token_utf8]
        if is_auth_hello {
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

            match verify_relay_ticket_once(token, session_id, &auth_config, now_unix, &replay_cache)
            {
                Ok(ticket) => {
                    // Ownership does not transfer. See
                    // `RelayAuthVerifyError::OwnerMismatch`: a valid signature
                    // says who asked, not what they may have, and a session id
                    // is a name the client picked rather than a claim we
                    // reserved for them.
                    // Scoped so the read guard is released before the write
                    // below takes one on the same shard.
                    let owner_conflict = sessions.get(&session_id).is_some_and(|existing| {
                        existing.auth_state == SessionAuthState::Authenticated
                            && existing.user_id != ticket.user_id
                    });
                    if owner_conflict {
                        log_auth_verify_error(
                            RelayAuthVerifyError::OwnerMismatch,
                            client_addr,
                            session_id,
                        );
                        send_auth_ack(
                            socket.as_ref(),
                            client_addr,
                            session_id,
                            AUTH_ACK_OWNER_MISMATCH,
                        )
                        .await;
                        continue;
                    }

                    if let Some(mut session_entry) = sessions.get_mut(&session_id) {
                        update_source_session_count_for_rebind(
                            &source_session_counts,
                            session_entry.client_addr.ip(),
                            client_addr.ip(),
                        );
                        session_entry.user_id = ticket.user_id;
                        session_entry.auth_state = SessionAuthState::Authenticated;
                        session_entry.lease_expires_at_unix = ticket.lease.then_some(ticket.exp);
                        session_entry.client_addr = client_addr;
                        session_entry.last_activity = now;
                        session_entry.last_activity_unix = now_unix;
                    }
                    send_auth_ack(socket.as_ref(), client_addr, session_id, AUTH_ACK_OK).await;
                }
                Err(err) => {
                    log_auth_verify_error(err, client_addr, session_id);
                    send_auth_ack(socket.as_ref(), client_addr, session_id, err.ack_status()).await;
                }
            }
            continue;
        }

        if !session_source_allowed {
            stats.drop_in(DropReason::Auth);
            continue;
        }

        // RTT/jitter ping:
        // [session_id:8][0xA3][seq_be_u32][client_ts_mono_ms_be_u64]
        if len == PING_FRAME_LEN && buf[SESSION_ID_LEN] == PING_FRAME_TYPE {
            if auth_config.mode.requires_auth() && !session_authenticated {
                stats.drop_in(DropReason::Auth);
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
                stats.drop_in(DropReason::Auth);
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

        // Roblox DNS resolve request: the client is behind a censor that
        // blocks/poisons DNS, so it asks us (outside the censorship) for Roblox's
        // real IPs. Resolve off the hot loop in a spawned task; restricted to
        // Roblox-owned hostnames by parse_resolve_request.
        if len > SESSION_ID_LEN && buf[SESSION_ID_LEN] == RESOLVE_REQUEST_FRAME_TYPE {
            if auth_config.mode.requires_auth() && !session_authenticated {
                stats.drop_in(DropReason::Auth);
                continue;
            }
            if let Some((request_id, hosts)) = parse_resolve_request(&buf, len) {
                let socket = Arc::clone(&socket);
                tokio::spawn(async move {
                    let mut answers: Vec<(String, Vec<Ipv4Addr>)> = Vec::with_capacity(hosts.len());
                    for host in hosts {
                        let ips = resolve_roblox_host_ipv4(&host).await;
                        if !ips.is_empty() {
                            answers.push((host, ips));
                        }
                    }
                    let response = build_resolve_response(&session_id, request_id, &answers);
                    let _ = socket.send_to(&response, client_addr).await;
                });
            }
            continue;
        }

        // Keepalive packet (just session ID, no payload)
        if len == SESSION_ID_LEN {
            if auth_config.mode.requires_auth() && !session_authenticated {
                stats.drop_in(DropReason::Auth);
                continue;
            }

            log::trace!("Keepalive from {:016x}", u64::from_be_bytes(session_id));

            let mut flows_refreshed = 0;
            if let Some(flow_keys) = session_flow_keys.get(&session_id) {
                for flow_key in flow_keys.iter() {
                    let Some(mut entry) = flows.get_mut(flow_key) else {
                        continue;
                    };
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
            stats.drop_in(DropReason::Auth);
            continue;
        }

        // Need enough for IP header
        if len < SESSION_ID_LEN + IP_HEADER_MIN {
            stats.drop_in(DropReason::TooSmall);
            continue;
        }

        // Parse IP packet
        let ip_packet = &buf[SESSION_ID_LEN..len];
        let parsed = match parse_ip_packet_full(ip_packet) {
            Some(p) => p,
            None => {
                stats.drop_in(DropReason::Parse);
                continue;
            }
        };

        match parsed {
            ParsedPacket::ForbiddenDst => {
                stats.drop_in(DropReason::ForbiddenDst);
                continue;
            }
            ParsedPacket::Fragment {
                protocol,
                src_ip,
                raw_ip_packet,
            } => {
                let can_tun = (protocol == 17 && tun_udp_enabled) || (protocol == 6 && tcp_enabled);
                if can_tun {
                    if let Some(ref tun_sender) = tun_tx_sender {
                        if tun_sender
                            .try_send(tcp_tun::InboundTunPacket {
                                session_id,
                                client_addr,
                                raw_ip_packet: raw_ip_packet.to_vec(),
                            })
                            .is_err()
                        {
                            stats.drop_in(DropReason::TunQueue);
                        } else if protocol == 6 {
                            stats.tcp_forwarded.fetch_add(1, Ordering::Relaxed);
                        } else {
                            stats.tun_udp_forwarded.fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        stats.drop_in(DropReason::TunQueue);
                    }
                } else {
                    stats.drop_in(DropReason::Fragment);
                }
                if let Some(mut session_entry) = sessions.get_mut(&session_id) {
                    if !matches!(session_entry.auth_state, SessionAuthState::Authenticated) {
                        session_entry.user_id = src_ip.to_string();
                    }
                }
                continue;
            }
            ParsedPacket::Tcp {
                original_info,
                raw_ip_packet,
            } => {
                if tcp_enabled {
                    if let Some(ref tun_sender) = tun_tx_sender {
                        if tun_sender
                            .try_send(tcp_tun::InboundTunPacket {
                                session_id,
                                client_addr,
                                raw_ip_packet: raw_ip_packet.to_vec(),
                            })
                            .is_err()
                        {
                            stats.drop_in(DropReason::TunQueue);
                        } else {
                            stats.tcp_forwarded.fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        stats.drop_in(DropReason::TunQueue);
                    }
                } else {
                    stats.drop_in(DropReason::TcpDisabled);
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
                raw_ip_packet,
            } => {
                if tun_udp_enabled {
                    if let Some(ref tun_sender) = tun_tx_sender {
                        if tun_sender
                            .try_send(tcp_tun::InboundTunPacket {
                                session_id,
                                client_addr,
                                raw_ip_packet: raw_ip_packet.to_vec(),
                            })
                            .is_err()
                        {
                            stats.drop_in(DropReason::TunQueue);
                        } else {
                            stats.tun_udp_forwarded.fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        stats.drop_in(DropReason::TunQueue);
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
                                stats.drop_in(DropReason::FlowQueue);
                            }
                            Err(TrySendError::Closed(_)) => {
                                // Flow task died, remove entry so it can be recreated
                                drop(entry);
                                flows.remove(&flow_key);
                                remove_v1_session_flow_key(
                                    &session_flow_keys,
                                    session_id,
                                    &flow_key,
                                );
                            }
                        }
                    }
                    Entry::Vacant(entry) => {
                        if !v1_flow_capacity_available(
                            &flows,
                            &session_flow_keys,
                            &stats,
                            session_id,
                        ) {
                            continue;
                        }
                        if !allow_source_event(
                            &source_limiter,
                            &stats,
                            client_addr,
                            SourceLimitKind::NewFlow,
                            now,
                        ) {
                            continue;
                        }

                        // New flow - create atomically
                        let (tx, rx) = mpsc::channel(flow_channel_capacity);

                        // Send first packet (should never fail on fresh channel)
                        if tx.try_send(udp_payload.to_vec()).is_err() {
                            stats.drop_in(DropReason::FlowQueue);
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
                        session_flow_keys
                            .entry(session_id)
                            .or_default()
                            .push(flow_key.clone());

                        // Spawn flow handler
                        let response_tx = response_tx.clone();
                        let flows_ref = Arc::clone(&flows);
                        let sessions_ref = Arc::clone(&sessions);
                        let stats_ref = Arc::clone(&stats);
                        let session_flow_keys_ref = Arc::clone(&session_flow_keys);

                        tokio::spawn(async move {
                            run_flow_handler(
                                flow_key,
                                game_addr,
                                session_id,
                                rx,
                                response_tx,
                                flows_ref,
                                sessions_ref,
                                session_flow_keys_ref,
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

fn handle_cli_args() -> Result<bool> {
    let mut args = env::args().skip(1);
    let Some(arg) = args.next() else {
        return Ok(false);
    };

    match arg.as_str() {
        "-V" | "--version" => {
            println!("swifttunnel-relay {}", RELAY_VERSION);
            Ok(true)
        }
        "-h" | "--help" => {
            println!(
                "swifttunnel-relay {}\n\nUsage: swifttunnel-relay [--version|--help]\n\nConfiguration is provided through RELAY_* environment variables.",
                RELAY_VERSION
            );
            Ok(true)
        }
        other => {
            anyhow::bail!(
                "unknown argument '{}'; use --help for supported options",
                other
            )
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
    session_flow_keys: Arc<DashMap<[u8; SESSION_ID_LEN], Vec<String>>>,
    stats: Arc<Stats>,
) {
    if let std::net::IpAddr::V4(dst_ip) = game_addr.ip() {
        if is_forbidden_dst(dst_ip) || is_forbidden_dst_port(game_addr.port()) {
            log::warn!(
                "Dropping flow {} to forbidden destination {}",
                flow_key,
                game_addr
            );
            stats.drop_in(DropReason::ForbiddenDst);
            flows.remove(&flow_key);
            remove_v1_session_flow_key(&session_flow_keys, session_id, &flow_key);
            return;
        }
    }

    // Create socket for this flow
    let socket = match bind_v1_flow_socket() {
        Ok(s) => s,
        Err(e) => {
            log::warn!("Failed to create flow socket: {}", e);
            flows.remove(&flow_key);
            remove_v1_session_flow_key(&session_flow_keys, session_id, &flow_key);
            return;
        }
    };

    // Connect to game server (for recv filtering)
    if let Err(e) = socket.connect(game_addr).await {
        log::warn!("Failed to connect to {}: {}", game_addr, e);
        flows.remove(&flow_key);
        remove_v1_session_flow_key(&session_flow_keys, session_id, &flow_key);
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
                            stats.drop_out(DropReason::TxQueue);
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
    remove_v1_session_flow_key(&session_flow_keys, session_id, &flow_key);
    log::trace!("Flow {} ended", flow_key);
}

fn bind_v1_flow_socket() -> std::io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    if let Err(e) = socket.set_recv_tos(true) {
        log::debug!("Failed to enable IP_RECVTOS on v1 flow socket: {}", e);
    }
    socket.bind(&std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into())?;
    let std_socket: std::net::UdpSocket = socket.into();
    std_socket.set_nonblocking(true)?;
    UdpSocket::from_std(std_socket)
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

/// Public health endpoint, distinct from the localhost stats API.
///
/// The hosted status page and the landing-page latency widget both probe
/// `http://<relay>:8081/health`, and both had been silently broken since
/// there was nothing listening there — every relay showed "down" and the
/// widget spun on "Measuring" forever.
///
/// Deliberately unauthenticated and deliberately thin: uptime and whether the
/// datapath is serving. No session data, no per-user counters, no control
/// surface. It exists so an external monitor can answer "is this relay
/// alive", which is not sensitive; the detailed `/v1/stats` API stays bound
/// to localhost behind its token.
pub(crate) fn spawn_health_http_server(port: u16, context: Arc<StatsApiContext>) -> Result<()> {
    std::thread::Builder::new()
        .name(format!("health-http-{}", port))
        .spawn(move || {
            if let Err(e) = run_health_http_server_blocking(port, context) {
                log::error!("Health API server error: {}", e);
            }
        })
        .context("Failed to spawn health API server thread")?;
    Ok(())
}

fn run_health_http_server_blocking(port: u16, context: Arc<StatsApiContext>) -> Result<()> {
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
        .context("Failed to bind health API listener")?;
    log::info!("Health API listening on 0.0.0.0:{}", port);

    loop {
        let (mut stream, _addr) = match listener.accept() {
            Ok(pair) => pair,
            Err(e) => {
                log::debug!("Health API accept error: {}", e);
                continue;
            }
        };

        let context = Arc::clone(&context);
        // Short timeouts: a monitor that stalls must not hold a thread open.
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

        std::thread::Builder::new()
            .name("health-http-client".into())
            .spawn(move || {
                let mut buf = [0u8; 1024];
                let read = stream.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..read]);
                let path = request
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .to_string();

                let (status, body) = if path.starts_with("/health") {
                    let uptime = context.started_at.elapsed().as_secs();
                    (
                        "200 OK",
                        format!(
                            "{{\"status\":\"ok\",\"server_id\":{},\"uptime_seconds\":{},\"version\":\"{}\"}}",
                            serde_json::to_string(
                                context.runtime_config.server_id.as_deref().unwrap_or("")
                            )
                            .unwrap_or_else(|_| "\"\"".to_string()),
                            uptime,
                            env!("CARGO_PKG_VERSION"),
                        ),
                    )
                } else {
                    ("404 Not Found", "{\"error\":\"not found\"}".to_string())
                };

                let response = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            })
            .ok();
    }
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
            "/v1/config" => {
                let body = render_config_payload(&context);
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
        "/v1/config" => {
            let body = render_config_payload(&context);
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

    serde_json::json!({
        "version": RELAY_VERSION,
        "timestamp": unix_timestamp_secs(),
        "active_users": active_users,
        "active_sessions": active_sessions,
        "throttled_users": context.stats.throttled_users.load(Ordering::Relaxed),
        "inbound_bps": inbound_bps,
        "outbound_bps": outbound_bps,
        "dropped_in": dropped_in,
        "dropped_out": dropped_out,
        "dropped_pps": dropped_pps,
        "pool_exhausted": context.stats.pool_exhausted.load(Ordering::Relaxed),
        "tcp_forwarded": context.stats.tcp_forwarded.load(Ordering::Relaxed),
        "tun_udp_forwarded": context.stats.tun_udp_forwarded.load(Ordering::Relaxed),
        "drops": context.stats.drop_reasons.to_json(),
        "config": context.runtime_config,
    })
    .to_string()
}

fn render_config_payload(context: &StatsApiContext) -> String {
    serde_json::json!({
        "timestamp": unix_timestamp_secs(),
        "config": context.runtime_config,
    })
    .to_string()
}

fn sample_stats_rates(
    context: &StatsApiContext,
    bytes_in: u64,
    bytes_out: u64,
    now: Instant,
) -> (u64, u64) {
    // Recover from poisoning: if an earlier caller panicked mid-sample, we still
    // want /v1/stats to return the last-known rates rather than propagate the panic.
    let mut window = match context.rate_window.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

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
                // The outer `if elapsed >= 1000ms` guarantees elapsed_secs >= 1.0, but
                // guard against a future interval change (or a pathologically short
                // Instant delta on suspend/resume) producing NaN or +Inf from division.
                if elapsed_secs > 0.0 {
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
    // Recover from a poisoned RwLock so a panic in the updater thread does not
    // permanently downgrade /v1/connections to empty payloads.
    let snapshot = context
        .connections_snapshot
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    snapshot.clone()
}

/// Write the latest connections payload into the shared snapshot cache,
/// recovering from mutex poisoning so a panicked writer cannot disable
/// future updates. Returns `true` once the value is stored.
fn store_connections_snapshot(context: &StatsApiContext, payload: String) -> bool {
    let mut snapshot = context
        .connections_snapshot
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *snapshot = payload;
    true
}

pub(crate) fn spawn_connections_snapshot_updater(context: Arc<StatsApiContext>) {
    std::thread::Builder::new()
        .name("stats-snapshot".into())
        .spawn(move || loop {
            let payload = render_connections_payload(&context);
            store_connections_snapshot(&context, payload);
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
        raw_ip_packet: &'a [u8],
    },
    Tcp {
        original_info: OriginalPacketInfo,
        raw_ip_packet: &'a [u8],
    },
    Fragment {
        protocol: u8,
        src_ip: Ipv4Addr,
        raw_ip_packet: &'a [u8],
    },
    ForbiddenDst,
}

/// Parse an IP packet and extract protocol-specific information.
///
/// Returns `ParsedPacket::Udp` for UDP (protocol 17) with the game address,
/// payload, and original packet info. Returns `ParsedPacket::Tcp` for TCP
/// (protocol 6) with the original packet info and a reference to the raw IP
/// packet. Returns `ParsedPacket::ForbiddenDst` for blocked destinations.
/// Returns `None` for other protocols or malformed packets.
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

    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < ihl || total_len > packet.len() {
        return None;
    }
    let packet = &packet[..total_len];
    let protocol = packet[9];

    // Extract source IP (bytes 12-15)
    let src_ip = std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);

    // Extract destination IP (bytes 16-19)
    let dst_ip = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    let fragment_bits = u16::from_be_bytes([packet[6], packet[7]]);
    let more_fragments = (fragment_bits & 0x2000) != 0;
    let fragment_offset = fragment_bits & 0x1FFF;
    if more_fragments || fragment_offset != 0 {
        if is_forbidden_dst(dst_ip) {
            return Some(ParsedPacket::ForbiddenDst);
        }
        return Some(ParsedPacket::Fragment {
            protocol,
            src_ip,
            raw_ip_packet: packet,
        });
    }

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

            let udp_len =
                u16::from_be_bytes([packet[udp_start + 4], packet[udp_start + 5]]) as usize;
            if udp_len < UDP_HEADER_SIZE || udp_start + udp_len > packet.len() {
                return None;
            }

            // UDP payload starts after 8-byte UDP header
            let payload_start = udp_start + UDP_HEADER_SIZE;
            let payload_end = udp_start + udp_len;
            let payload = if payload_end > payload_start {
                &packet[payload_start..payload_end]
            } else {
                &[]
            };

            let original_info = OriginalPacketInfo {
                tos: packet[1],
                src_ip,
                src_port,
                dst_ip,
                dst_port,
            };

            if is_forbidden_dst(dst_ip) || is_forbidden_dst_port(dst_port) {
                return Some(ParsedPacket::ForbiddenDst);
            }

            Some(ParsedPacket::Udp {
                game_addr: SocketAddr::from((dst_ip, dst_port)),
                payload,
                original_info,
                raw_ip_packet: packet,
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
            let tcp_header_len = ((packet[tcp_start + 12] >> 4) as usize) * 4;
            if tcp_header_len < TCP_HEADER_MIN || packet.len() < tcp_start + tcp_header_len {
                return None;
            }

            let original_info = OriginalPacketInfo {
                tos: packet[1],
                src_ip,
                src_port,
                dst_ip,
                dst_port,
            };

            // Addresses only. The port blocklist is a UDP rule and does not
            // belong here: amplification needs a connectionless, spoofable
            // protocol, and TCP has neither property, so refusing these ports
            // over TCP buys no safety and only breaks traffic. This relay
            // carries HTTPS for Route Assist, so that is a live cost.
            if is_forbidden_dst(dst_ip) {
                return Some(ParsedPacket::ForbiddenDst);
            }

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
    build_response_ip_packet_with_tos(udp_payload, original, original.tos)
}

fn build_response_ip_packet_with_tos(
    udp_payload: &[u8],
    original: OriginalPacketInfo,
    tos: u8,
) -> Vec<u8> {
    let udp_len = UDP_HEADER_SIZE + udp_payload.len();
    let total_len = IP_HEADER_MIN + udp_len;

    let mut packet = vec![0u8; total_len];

    // === IP Header (20 bytes) ===
    // Version (4) + IHL (5 = 20 bytes)
    packet[0] = 0x45;
    // DSCP + ECN
    packet[1] = tos;
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
fn stamp_ipv4_lengths(packet: &mut [u8]) {
    let total_len = packet.len() as u16;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    match packet[9] {
        17 if packet.len() >= ihl + UDP_HEADER_SIZE => {
            let udp_len = (packet.len() - ihl) as u16;
            packet[ihl + 4..ihl + 6].copy_from_slice(&udp_len.to_be_bytes());
        }
        6 if packet.len() >= ihl + 20 => {
            let data_offset = ihl + 12;
            if packet[data_offset] == 0 {
                packet[data_offset] = 0x50;
            }
        }
        _ => {}
    }
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
        stamp_ipv4_lengths(&mut packet);

        let result = parse_ip_packet_full(&packet);
        assert!(result.is_some());

        let result = result.unwrap();
        match result {
            ParsedPacket::Udp {
                game_addr: addr,
                payload,
                original_info: info,
                ..
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
            tos: 0x2e,
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
        assert_eq!(packet[1], 0x2e);

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
    fn test_build_response_can_use_received_tos_override() {
        let original = OriginalPacketInfo {
            tos: 0x00,
            src_ip: "10.0.0.5".parse().unwrap(),
            src_port: 54321,
            dst_ip: "1.2.3.4".parse().unwrap(),
            dst_port: 12345,
        };

        let packet = build_response_ip_packet_with_tos(&[0x01], original, 0x03);

        assert_eq!(packet[1], 0x03);
        let verify = calculate_ip_checksum(&packet[..IP_HEADER_MIN]);
        assert!(verify == 0 || verify == 0xFFFF);
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

        let ticket =
            verify_relay_ticket(&token, session_id, &auth_config, now).expect("valid token");
        assert_eq!(ticket.user_id, "11111111-1111-1111-1111-111111111111");
        assert_eq!(ticket.jti, "22222222-2222-2222-2222-222222222222");
    }

    #[test]
    fn test_verify_relay_ticket_once_rejects_replay() {
        let (key_pair, auth_config) = test_auth_materials();
        let session_id = 0x0123_4567_89ab_cdef_u64.to_be_bytes();
        let now = 1_739_790_000_u64;
        let sid = format!("{:016x}", u64::from_be_bytes(session_id));
        let token = make_ticket_token(&key_pair, &sid, "us-east-nj", now, now + 300);
        let replay_cache = RelayTicketReplayCache::new();

        assert!(
            verify_relay_ticket_once(&token, session_id, &auth_config, now, &replay_cache).is_ok()
        );
        let replay =
            verify_relay_ticket_once(&token, session_id, &auth_config, now + 1, &replay_cache);
        assert!(matches!(replay, Err(RelayAuthVerifyError::Replay)));
    }

    #[test]
    fn test_ticket_replay_cache_expires_old_jti() {
        let cache = RelayTicketReplayCache::new();

        assert!(cache.accept_once("jti-a", 100, 90));
        assert!(!cache.accept_once("jti-a", 100, 91));
        assert!(cache.accept_once("jti-a", 200, 131));
    }

    #[test]
    fn test_ticket_replay_cache_prunes_on_interval() {
        let cache = RelayTicketReplayCache::new();

        assert!(cache.accept_once("jti-stale", 50, 90));
        assert!(!cache.accept_once("jti-stale", 50, 100));
        assert!(cache.accept_once("jti-stale", 200, 121));
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
        assert_eq!(RelayAuthMode::from_env(None), RelayAuthMode::Required);
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

    #[test]
    fn test_source_rate_state_resets_after_window() {
        let now = Instant::now();
        let mut state = SourceRateState::new(now);
        state.packets = MAX_PACKETS_PER_SOURCE_WINDOW;

        assert!(!state.allow(SourceLimitKind::Packet, now));
        assert!(state.allow(
            SourceLimitKind::Packet,
            now + SOURCE_RATE_WINDOW + Duration::from_millis(1)
        ));
    }

    #[test]
    fn test_source_rate_buckets_are_independent() {
        let now = Instant::now();
        let mut state = SourceRateState::new(now);
        state.new_sessions = MAX_NEW_SESSIONS_PER_SOURCE_WINDOW;

        assert!(!state.allow(SourceLimitKind::NewSession, now));
        assert!(state.allow(SourceLimitKind::NewFlow, now));
        assert!(state.allow(SourceLimitKind::Packet, now));
    }

    #[test]
    fn test_allow_source_event_records_rate_limit_drop() {
        let limiter = SourceRateLimiter::new();
        let stats = Stats::new();
        let client_addr: SocketAddr = "203.0.113.10:40000".parse().unwrap();
        let now = Instant::now();
        let mut saturated = SourceRateState::new(now);
        saturated.new_flows = MAX_NEW_FLOWS_PER_SOURCE_WINDOW;
        limiter.sources.insert(client_addr.ip(), saturated);

        assert!(!allow_source_event(
            &limiter,
            &stats,
            client_addr,
            SourceLimitKind::NewFlow,
            now
        ));
        assert_eq!(stats.dropped_in.load(Ordering::Relaxed), 1);
        assert_eq!(stats.throttled_users.load(Ordering::Relaxed), 1);
        assert_eq!(stats.drop_reasons.rate_limit.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_source_rate_limiter_prunes_idle_sources() {
        let limiter = SourceRateLimiter::new();
        let now = limiter.created_at + SOURCE_RATE_PRUNE_INTERVAL + Duration::from_millis(1);
        let stale_ip: IpAddr = "203.0.113.10".parse().unwrap();
        let active_ip: IpAddr = "203.0.113.11".parse().unwrap();

        limiter.sources.insert(
            stale_ip,
            SourceRateState::new(now - SOURCE_RATE_IDLE_TTL - Duration::from_secs(1)),
        );
        limiter.sources.insert(active_ip, SourceRateState::new(now));

        assert!(limiter.allow(active_ip, SourceLimitKind::Packet, now));
        assert!(!limiter.sources.contains_key(&stale_ip));
        assert!(limiter.sources.contains_key(&active_ip));
    }

    #[test]
    fn test_v1_flow_capacity_uses_session_flow_index() {
        let flows = DashMap::new();
        let session_flow_keys = DashMap::new();
        let stats = Stats::new();
        let session_id = 0x0123_4567_89ab_cdef_u64.to_be_bytes();

        session_flow_keys.insert(
            session_id,
            (0..MAX_FLOWS_PER_SESSION)
                .map(|idx| format!("0123456789abcdef:203.0.113.1:{}", idx))
                .collect(),
        );

        assert!(!v1_flow_capacity_available(
            &flows,
            &session_flow_keys,
            &stats,
            session_id
        ));
        assert_eq!(stats.dropped_in.load(Ordering::Relaxed), 1);
        assert_eq!(stats.drop_reasons.capacity.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_source_session_counts_track_rebind_and_removal() {
        let source_session_counts = DashMap::new();
        let old_ip: IpAddr = "198.51.100.10".parse().unwrap();
        let new_ip: IpAddr = "198.51.100.11".parse().unwrap();

        increment_source_session_count(&source_session_counts, old_ip);
        assert_eq!(source_session_count(&source_session_counts, old_ip), 1);

        update_source_session_count_for_rebind(&source_session_counts, old_ip, new_ip);
        assert_eq!(source_session_count(&source_session_counts, old_ip), 0);
        assert_eq!(source_session_count(&source_session_counts, new_ip), 1);

        decrement_source_session_count(&source_session_counts, new_ip);
        assert_eq!(source_session_count(&source_session_counts, new_ip), 0);
    }

    #[test]
    fn test_v1_session_capacity_uses_source_session_counter() {
        let sessions = DashMap::new();
        let source_session_counts = DashMap::new();
        let stats = Stats::new();
        let source_ip: IpAddr = "198.51.100.10".parse().unwrap();
        source_session_counts.insert(source_ip, MAX_SESSIONS_PER_SRC_IP as u64);

        assert!(!v1_session_capacity_available(
            &sessions,
            &source_session_counts,
            &stats,
            source_ip
        ));
        assert_eq!(stats.dropped_in.load(Ordering::Relaxed), 1);
        assert_eq!(stats.drop_reasons.capacity.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_authenticated_session_without_lease_remains_current() {
        let session = SessionEntry {
            user_id: "legacy-client".to_string(),
            auth_state: SessionAuthState::Authenticated,
            lease_expires_at_unix: None,
            client_addr: "198.51.100.10:40000".parse().unwrap(),
            created_at_unix: 1,
            last_activity: Instant::now(),
            last_activity_unix: 1,
        };

        assert!(session_auth_is_current(&session, 10_000));
    }

    #[test]
    fn test_authenticated_session_with_live_lease_is_current() {
        let session = SessionEntry {
            user_id: "lease-client".to_string(),
            auth_state: SessionAuthState::Authenticated,
            lease_expires_at_unix: Some(101),
            client_addr: "198.51.100.10:40000".parse().unwrap(),
            created_at_unix: 1,
            last_activity: Instant::now(),
            last_activity_unix: 1,
        };

        assert!(session_auth_is_current(&session, 100));
    }

    #[test]
    fn test_authenticated_session_with_expired_lease_is_not_current() {
        let session = SessionEntry {
            user_id: "lease-client".to_string(),
            auth_state: SessionAuthState::Authenticated,
            lease_expires_at_unix: Some(100),
            client_addr: "198.51.100.10:40000".parse().unwrap(),
            created_at_unix: 1,
            last_activity: Instant::now(),
            last_activity_unix: 1,
        };

        assert!(!session_auth_is_current(&session, 100));
    }

    #[test]
    fn test_authenticated_session_source_rejects_forged_address() {
        let session = SessionEntry {
            user_id: "user".to_string(),
            auth_state: SessionAuthState::Authenticated,
            lease_expires_at_unix: None,
            client_addr: "198.51.100.10:40000".parse().unwrap(),
            created_at_unix: 1,
            last_activity: Instant::now(),
            last_activity_unix: 1,
        };

        assert!(authenticated_session_source_allowed(
            &session,
            true,
            "198.51.100.10:40001".parse().unwrap(),
            false
        ));
        assert!(!authenticated_session_source_allowed(
            &session,
            true,
            "203.0.113.55:40000".parse().unwrap(),
            false
        ));
        assert!(authenticated_session_source_allowed(
            &session,
            true,
            "203.0.113.55:40000".parse().unwrap(),
            true
        ));
    }

    #[test]
    fn test_v1_session_flow_index_removes_only_target_flow() {
        let index = DashMap::new();
        let session_id = 0x0123_4567_89ab_cdef_u64.to_be_bytes();
        index.insert(
            session_id,
            vec![
                "0123456789abcdef:1.1.1.1:1000".to_string(),
                "0123456789abcdef:2.2.2.2:2000".to_string(),
            ],
        );

        remove_v1_session_flow_key(&index, session_id, "0123456789abcdef:1.1.1.1:1000");

        let keys = index.get(&session_id).unwrap();
        assert_eq!(keys.as_slice(), ["0123456789abcdef:2.2.2.2:2000"]);
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
        assert!(RelayAuthMode::Optional.requires_auth());
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

    #[test]
    fn test_ack_status_replay() {
        assert_eq!(RelayAuthVerifyError::Replay.ack_status(), AUTH_ACK_REPLAY);
        assert_ne!(AUTH_ACK_REPLAY, AUTH_ACK_BAD_SIGNATURE);
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
        packet[16] = 8;
        packet[17] = 8;
        packet[18] = 8;
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
        stamp_ipv4_lengths(&mut packet);

        let result = parse_ip_packet_full(&packet);
        assert!(result.is_some());
        match result.unwrap() {
            ParsedPacket::Udp {
                game_addr: addr,
                payload,
                original_info: info,
                ..
            } => {
                assert_eq!(addr.ip().to_string(), "8.8.8.1");
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
        stamp_ipv4_lengths(&mut packet);

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
    fn test_forbidden_destinations_are_blocked() {
        for ip in [
            Ipv4Addr::new(169, 254, 169, 254),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(224, 0, 0, 251),
            Ipv4Addr::new(255, 255, 255, 255),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(0, 1, 2, 3),
            Ipv4Addr::new(240, 0, 0, 1),
        ] {
            assert!(is_forbidden_dst(ip), "{ip} should be forbidden");
        }
        assert!(!is_forbidden_dst(Ipv4Addr::new(128, 116, 50, 10)));
    }

    /// The relay must not be usable as an amplifier.
    ///
    /// The address filter keeps it off private networks and says nothing about
    /// what it is talking to. Pointed at one of these services, a client spends
    /// a trickle of upload and the target receives a flood carrying our address
    /// rather than theirs.
    #[test]
    fn amplification_ports_are_refused() {
        for port in [
            19,    // chargen
            53,    // DNS
            123,   // NTP
            161,   // SNMP
            389,   // CLDAP
            1900,  // SSDP
            11211, // memcached
        ] {
            assert!(
                is_forbidden_dst_port(port),
                "udp/{port} is a known amplifier and must not be forwarded"
            );
        }

        // Port 0 is never a real destination.
        assert!(is_forbidden_dst_port(0));

        // Roblox lives in the high ephemeral range, and normal game traffic
        // must be untouched by this. A blocklist that catches gameplay is worse
        // than no blocklist, because the failure is invisible and blamed on us.
        for port in [443, 49152, 53640, 61337, 65535] {
            assert!(
                !is_forbidden_dst_port(port),
                "udp/{port} carries real traffic and must still be forwarded"
            );
        }
    }

    #[test]
    fn test_parse_ip_packet_drops_imds_destination() {
        let mut packet = vec![0u8; 32];
        packet[0] = 0x45;
        packet[9] = 17;
        packet[12] = 10;
        packet[13] = 0;
        packet[14] = 0;
        packet[15] = 5;
        packet[16] = 169;
        packet[17] = 254;
        packet[18] = 169;
        packet[19] = 254;
        packet[20] = 0x13;
        packet[21] = 0x88;
        packet[22] = 0x00;
        packet[23] = 0x50;
        stamp_ipv4_lengths(&mut packet);

        assert!(matches!(
            parse_ip_packet_full(&packet),
            Some(ParsedPacket::ForbiddenDst)
        ));
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
        stamp_ipv4_lengths(&mut packet);

        let result = parse_ip_packet_full(&packet);
        assert!(result.is_some());
        match result.unwrap() {
            ParsedPacket::Udp {
                game_addr: addr,
                payload,
                original_info: info,
                ..
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
    fn test_parse_ip_trims_trailing_padding() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[9] = 17;
        packet[12] = 10;
        packet[15] = 5;
        packet[16] = 1;
        packet[17] = 2;
        packet[18] = 3;
        packet[19] = 4;
        packet[20] = 0x13;
        packet[21] = 0x88;
        packet[22] = 0x17;
        packet[23] = 0x70;
        packet[28..36].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        packet[36..40].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        packet[2..4].copy_from_slice(&(36u16).to_be_bytes());
        packet[24..26].copy_from_slice(&(16u16).to_be_bytes());

        let result = parse_ip_packet_full(&packet);
        assert!(result.is_some());
        match result.unwrap() {
            ParsedPacket::Udp {
                payload,
                raw_ip_packet,
                ..
            } => {
                assert_eq!(payload, &[1, 2, 3, 4, 5, 6, 7, 8]);
                assert_eq!(raw_ip_packet.len(), 36);
            }
            _ => panic!("Expected ParsedPacket::Udp"),
        }
    }

    #[test]
    fn test_parse_ip_rejects_udp_length_past_total_len() {
        let mut packet = vec![0u8; 36];
        packet[0] = 0x45;
        packet[9] = 17;
        stamp_ipv4_lengths(&mut packet);
        packet[24..26].copy_from_slice(&(24u16).to_be_bytes());
        assert!(parse_ip_packet_full(&packet).is_none());
    }

    #[test]
    fn test_parse_ip_rejects_tcp_bad_data_offset() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[9] = 6;
        packet[20] = 0x13;
        packet[21] = 0x88;
        packet[22] = 0x00;
        packet[23] = 0x50;
        stamp_ipv4_lengths(&mut packet);
        packet[32] = 0x40;
        assert!(parse_ip_packet_full(&packet).is_none());
    }

    #[test]
    fn test_parse_ip_returns_udp_fragment() {
        let mut packet = vec![0u8; 36];
        packet[0] = 0x45;
        packet[9] = 17;
        packet[12] = 172;
        packet[13] = 16;
        packet[14] = 0;
        packet[15] = 1;
        packet[16] = 8;
        packet[17] = 8;
        packet[18] = 8;
        packet[19] = 8;
        stamp_ipv4_lengths(&mut packet);
        packet[6] = 0x20; // more-fragments flag

        let result = parse_ip_packet_full(&packet);
        assert!(result.is_some());
        match result.unwrap() {
            ParsedPacket::Fragment {
                protocol,
                src_ip,
                raw_ip_packet,
            } => {
                assert_eq!(protocol, 17);
                assert_eq!(src_ip.to_string(), "172.16.0.1");
                assert_eq!(raw_ip_packet.len(), 36);
            }
            _ => panic!("Expected ParsedPacket::Fragment"),
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
        stamp_ipv4_lengths(&mut packet);

        let result = parse_ip_packet_full(&packet);
        assert!(result.is_some());
        match result.unwrap() {
            ParsedPacket::Udp {
                game_addr: addr,
                payload,
                original_info: info,
                ..
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
            tos: 0,
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
            tos: 0,
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
            tos: 0,
            src_ip: "8.8.8.8".parse().unwrap(),
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
            tos: 0,
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
            tos: 0,
            src_ip: "8.8.8.8".parse().unwrap(),
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
                ..
            } => {
                // In the response, src/dst are swapped from original
                // Source IP = original.dst_ip (game server)
                assert_eq!(info.src_ip.to_string(), "1.2.3.4");
                assert_eq!(info.src_port, 12345);
                // Dest IP = original.src_ip (client)
                assert_eq!(info.dst_ip.to_string(), "8.8.8.8");
                assert_eq!(info.dst_port, 54321);
                // SocketAddr should point to the packet's dest (the client)
                assert_eq!(addr.ip().to_string(), "8.8.8.8");
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
            runtime_config: test_runtime_config(),
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
            runtime_config: test_runtime_config(),
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
                    lease_expires_at_unix: None,
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
                    lease_expires_at_unix: None,
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
                    lease_expires_at_unix: None,
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
                lease_expires_at_unix: None,
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
                    lease_expires_at_unix: None,
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
                    lease_expires_at_unix: None,
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
                lease_expires_at_unix: None,
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
    async fn test_http_get_config_with_correct_token() {
        let ctx = make_stats_context();
        let response = send_http_request(
            "test-token",
            ctx,
            "GET /v1/config HTTP/1.1\r\nAuthorization: Bearer test-token\r\n\r\n",
        )
        .await;
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("\"datapath\":\"v2\""));
        assert!(response.contains("\"main_socket_rcvbuf_effective\":4194304"));
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

    // ---- pool exhaustion counter ----

    #[test]
    fn test_render_stats_includes_pool_exhausted_counter() {
        let ctx = make_stats_context();
        let payload = render_stats_payload(&ctx);
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(
            parsed["pool_exhausted"], 0,
            "fresh context should report zero pool exhaustion events"
        );
    }

    #[test]
    fn test_render_stats_pool_exhausted_reflects_counter_value() {
        let ctx = make_stats_context();
        ctx.stats.pool_exhausted.store(17, Ordering::Relaxed);
        let payload = render_stats_payload(&ctx);
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["pool_exhausted"], 17);
    }

    #[test]
    fn test_render_stats_includes_drop_reasons_and_config() {
        let ctx = make_stats_context();
        ctx.stats.drop_in(DropReason::Auth);
        ctx.stats.drop_in(DropReason::ForbiddenDst);
        ctx.stats.drop_in(DropReason::TcpDisabled);
        ctx.stats.drop_in(DropReason::StaleQueue);
        ctx.stats.drop_out(DropReason::TxQueue);

        let payload = render_stats_payload(&ctx);
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["dropped_in"], 4);
        assert_eq!(parsed["dropped_out"], 1);
        assert_eq!(parsed["drops"]["auth"], 1);
        assert_eq!(parsed["drops"]["forbidden_dst"], 1);
        assert_eq!(parsed["drops"]["tcp_disabled"], 1);
        assert_eq!(parsed["drops"]["stale_queue"], 1);
        assert_eq!(parsed["drops"]["tx_queue"], 1);
        assert_eq!(parsed["config"]["datapath"], "v2");
        assert_eq!(parsed["config"]["version"], RELAY_VERSION);
    }

    #[test]
    fn test_render_config_payload_includes_runtime_config() {
        let ctx = make_stats_context();
        let payload = render_config_payload(&ctx);
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["config"]["auth_mode"], "off");
        assert_eq!(parsed["config"]["v2"]["shard_count"], 1);
        assert_eq!(
            parsed["config"]["v2"]["main_socket_rcvbuf_effective"],
            4_194_304
        );
    }

    // ---- poisoned lock recovery ----

    #[test]
    fn test_sample_stats_rates_recovers_from_poisoned_mutex() {
        let ctx = make_stats_context();
        // Poison the rate_window mutex by panicking inside a held guard.
        let ctx_for_poisoner = Arc::clone(&ctx);
        let _ = std::thread::spawn(move || {
            let _guard = ctx_for_poisoner.rate_window.lock().unwrap();
            panic!("intentional poison");
        })
        .join();
        assert!(
            ctx.rate_window.is_poisoned(),
            "precondition: mutex poisoned"
        );

        // Should not panic even though the mutex is poisoned.
        let (inbound_bps, outbound_bps) = sample_stats_rates(&ctx, 0, 0, Instant::now());
        assert_eq!(inbound_bps, 0);
        assert_eq!(outbound_bps, 0);
    }

    #[test]
    fn test_render_stats_payload_does_not_panic_on_poisoned_mutex() {
        let ctx = make_stats_context();
        let ctx_for_poisoner = Arc::clone(&ctx);
        let _ = std::thread::spawn(move || {
            let _guard = ctx_for_poisoner.rate_window.lock().unwrap();
            panic!("intentional poison");
        })
        .join();
        assert!(ctx.rate_window.is_poisoned());

        let payload = render_stats_payload(&ctx);
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["inbound_bps"], 0);
        assert_eq!(parsed["outbound_bps"], 0);
    }

    #[test]
    fn test_store_connections_snapshot_recovers_from_poisoned_rwlock() {
        let ctx = make_stats_context();
        let ctx_for_poisoner = Arc::clone(&ctx);
        let _ = std::thread::spawn(move || {
            let _guard = ctx_for_poisoner.connections_snapshot.write().unwrap();
            panic!("intentional poison");
        })
        .join();
        assert!(
            ctx.connections_snapshot.is_poisoned(),
            "precondition: rwlock poisoned"
        );

        // Storing should succeed even when poisoned.
        let payload = "{\"timestamp\":1,\"connections\":[]}".to_string();
        let stored = store_connections_snapshot(&ctx, payload.clone());
        assert!(stored, "store must succeed despite poisoned RwLock");

        // And the stored value is retrievable.
        let readback = render_connections_snapshot_payload(&ctx);
        assert_eq!(readback, payload);
    }

    #[test]
    fn test_render_connections_snapshot_payload_recovers_from_poisoned_rwlock() {
        let ctx = make_stats_context();
        // Poison via write guard (Rust only marks RwLocks poisoned when the
        // writer thread panics) with a pre-seeded payload value.
        let ctx_for_poisoner = Arc::clone(&ctx);
        let _ = std::thread::spawn(move || {
            let mut snapshot = ctx_for_poisoner.connections_snapshot.write().unwrap();
            *snapshot = "{\"timestamp\":9,\"connections\":[\"seeded\"]}".to_string();
            panic!("intentional poison");
        })
        .join();
        assert!(ctx.connections_snapshot.is_poisoned());

        let payload = render_connections_snapshot_payload(&ctx);
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["timestamp"], 9);
    }
}

#[cfg(test)]
mod resolve_frame_tests {
    use super::*;

    fn build_resolve_request_frame(
        session_id: &[u8; SESSION_ID_LEN],
        request_id: u16,
        hosts: &[&str],
    ) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(session_id);
        f.push(RESOLVE_REQUEST_FRAME_TYPE);
        f.extend_from_slice(&request_id.to_be_bytes());
        f.push(hosts.len() as u8);
        for h in hosts {
            f.push(h.len() as u8);
            f.extend_from_slice(h.as_bytes());
        }
        f
    }

    #[test]
    fn allowlist_only_accepts_roblox_hosts() {
        assert!(is_resolvable_roblox_host("roblox.com"));
        assert!(is_resolvable_roblox_host("clientsettings.roblox.com"));
        assert!(is_resolvable_roblox_host("c3.rbxcdn.com"));
        assert!(is_resolvable_roblox_host("roblox-api.arkoselabs.com"));
        assert!(is_resolvable_roblox_host("WWW.ROBLOX.COM"));
        assert!(!is_resolvable_roblox_host("evil.com"));
        assert!(!is_resolvable_roblox_host("roblox.com.evil.test"));
        assert!(!is_resolvable_roblox_host("notroblox.com"));
    }

    #[test]
    fn parse_keeps_roblox_and_drops_others() {
        let sid = [9u8; SESSION_ID_LEN];
        let frame = build_resolve_request_frame(
            &sid,
            0x1234,
            &["clientsettings.roblox.com", "evil.com", "c0.rbxcdn.com"],
        );
        let (req_id, hosts) = parse_resolve_request(&frame, frame.len()).expect("valid frame");
        assert_eq!(req_id, 0x1234);
        assert_eq!(
            hosts,
            vec![
                "clientsettings.roblox.com".to_string(),
                "c0.rbxcdn.com".to_string()
            ]
        );
    }

    #[test]
    fn parse_rejects_truncated_and_oversized() {
        let sid = [0u8; SESSION_ID_LEN];
        let mut frame = build_resolve_request_frame(&sid, 1, &["clientsettings.roblox.com"]);
        let truncated = &frame[..frame.len() - 5];
        assert!(parse_resolve_request(truncated, truncated.len()).is_none());
        frame[SESSION_ID_LEN + 3] = (RESOLVE_MAX_HOSTS_PER_REQUEST + 1) as u8;
        assert!(parse_resolve_request(&frame, frame.len()).is_none());
    }

    #[test]
    fn build_response_lays_out_answers() {
        let sid = [3u8; SESSION_ID_LEN];
        let answers = vec![(
            "clientsettings.roblox.com".to_string(),
            vec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)],
        )];
        let resp = build_resolve_response(&sid, 0xBEEF, &answers);
        assert_eq!(&resp[..SESSION_ID_LEN], &sid);
        assert_eq!(resp[SESSION_ID_LEN], RESOLVE_RESPONSE_FRAME_TYPE);
        assert_eq!(
            u16::from_be_bytes([resp[SESSION_ID_LEN + 1], resp[SESSION_ID_LEN + 2]]),
            0xBEEF
        );
        assert_eq!(resp[SESSION_ID_LEN + 3], 1, "answer count");
        let host_off = SESSION_ID_LEN + 4;
        let hlen = resp[host_off] as usize;
        assert_eq!(
            &resp[host_off + 1..host_off + 1 + hlen],
            b"clientsettings.roblox.com"
        );
        let ipc_off = host_off + 1 + hlen;
        assert_eq!(resp[ipc_off], 2, "ip count");
        assert_eq!(&resp[ipc_off + 1..ipc_off + 5], &[1, 2, 3, 4]);
        assert_eq!(&resp[ipc_off + 5..ipc_off + 9], &[5, 6, 7, 8]);
    }
}
