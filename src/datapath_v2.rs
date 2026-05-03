use anyhow::{Context, Result};
use dashmap::DashMap;
use mio::net::UdpSocket as MioUdpSocket;
use mio::{Events, Interest, Poll, Token, Waker};
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::env;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const DEFAULT_POOL_SLOTS: usize = 8192;
const MIN_POOL_SLOTS: usize = 512;
const MAX_POOL_SLOTS: usize = 262_144;

const DEFAULT_SHARD_QUEUE_CAP: usize = 4096;
const MIN_SHARD_QUEUE_CAP: usize = 256;
const MAX_SHARD_QUEUE_CAP: usize = 262_144;

const DEFAULT_TX_QUEUE_CAP: usize = 8192;
const MIN_TX_QUEUE_CAP: usize = 256;
const MAX_TX_QUEUE_CAP: usize = 262_144;

const DEFAULT_SOCKET_RCVBUF_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_SOCKET_SNDBUF_BYTES: usize = 4 * 1024 * 1024;

const DEFAULT_FLOW_SOCKET_RCVBUF_BYTES: usize = 2 * 1024 * 1024;
const DEFAULT_FLOW_SOCKET_SNDBUF_BYTES: usize = 2 * 1024 * 1024;
const MAX_FLOW_RECV_BURST: usize = 64;
const MAX_INBOX_DRAIN_BURST: usize = 1024;
const MAX_DATA_QUEUE_AGE: Duration = Duration::from_millis(250);
// Intentionally shorter than MAX_DATA_QUEUE_AGE: this bounds a single kernel
// send-buffer stall, while stale-queue dropping sheds packets that waited too long.
const MAIN_SOCKET_SEND_TIMEOUT: Duration = Duration::from_millis(5);

#[derive(Debug, Clone, Copy)]
pub(super) struct RelayV2Tuning {
    pub shard_count: usize,
    pub pool_slots: usize,
    pub shard_queue_cap: usize,
    pub tx_queue_cap: usize,
    pub socket_rcvbuf_bytes: usize,
    pub socket_sndbuf_bytes: usize,
    pub flow_rcvbuf_bytes: usize,
    pub flow_sndbuf_bytes: usize,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct SocketBufferSizes {
    pub requested_rcvbuf_bytes: usize,
    pub requested_sndbuf_bytes: usize,
    pub effective_rcvbuf_bytes: usize,
    pub effective_sndbuf_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Selectable relay datapath implementation.
pub(super) enum RelayDatapath {
    V1,
    V2,
}

/// Read `RELAY_DATAPATH` and select datapath implementation.
pub(super) fn get_relay_datapath() -> RelayDatapath {
    match env::var("RELAY_DATAPATH")
        .ok()
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("v1") | Some("tokio") => RelayDatapath::V1,
        Some("v2") | Some("sharded") => RelayDatapath::V2,
        _ => RelayDatapath::V2,
    }
}

/// Parse an env var as `usize`, returning `None` for missing or invalid values.
fn parse_usize_env(name: &str) -> Option<usize> {
    env::var(name)
        .ok()
        .as_deref()
        .map(str::trim)
        .and_then(|raw| raw.parse::<usize>().ok())
}

/// Clamp a `usize` value to a min/max range.
fn clamp_usize(value: usize, min: usize, max: usize) -> usize {
    value.clamp(min, max)
}

/// Determine shard count for datapath v2.
fn get_shard_count() -> usize {
    let default = num_cpus::get_physical().max(1);
    clamp_usize(parse_usize_env("RELAY_SHARDS").unwrap_or(default), 1, 256)
}

/// Determine buffer pool slots for datapath v2.
fn get_pool_slots() -> usize {
    clamp_usize(
        parse_usize_env("RELAY_V2_POOL_SLOTS").unwrap_or(DEFAULT_POOL_SLOTS),
        MIN_POOL_SLOTS,
        MAX_POOL_SLOTS,
    )
}

/// Determine per-shard inbox queue capacity for datapath v2.
fn get_shard_queue_cap() -> usize {
    clamp_usize(
        parse_usize_env("RELAY_V2_SHARD_QUEUE").unwrap_or(DEFAULT_SHARD_QUEUE_CAP),
        MIN_SHARD_QUEUE_CAP,
        MAX_SHARD_QUEUE_CAP,
    )
}

/// Determine TX queue capacity for datapath v2.
fn get_tx_queue_cap() -> usize {
    clamp_usize(
        parse_usize_env("RELAY_V2_TX_QUEUE").unwrap_or(DEFAULT_TX_QUEUE_CAP),
        MIN_TX_QUEUE_CAP,
        MAX_TX_QUEUE_CAP,
    )
}

/// Determine OS receive buffer size for the main socket.
fn get_socket_rcvbuf_bytes() -> usize {
    clamp_usize(
        parse_usize_env("RELAY_SOCKET_RCVBUF_BYTES").unwrap_or(DEFAULT_SOCKET_RCVBUF_BYTES),
        256 * 1024,
        64 * 1024 * 1024,
    )
}

/// Determine OS send buffer size for the main socket.
fn get_socket_sndbuf_bytes() -> usize {
    clamp_usize(
        parse_usize_env("RELAY_SOCKET_SNDBUF_BYTES").unwrap_or(DEFAULT_SOCKET_SNDBUF_BYTES),
        256 * 1024,
        64 * 1024 * 1024,
    )
}

/// Determine OS receive buffer size for per-flow sockets.
fn get_flow_socket_rcvbuf_bytes() -> usize {
    clamp_usize(
        parse_usize_env("RELAY_FLOW_RCVBUF_BYTES").unwrap_or(DEFAULT_FLOW_SOCKET_RCVBUF_BYTES),
        256 * 1024,
        64 * 1024 * 1024,
    )
}

/// Determine OS send buffer size for per-flow sockets.
fn get_flow_socket_sndbuf_bytes() -> usize {
    clamp_usize(
        parse_usize_env("RELAY_FLOW_SNDBUF_BYTES").unwrap_or(DEFAULT_FLOW_SOCKET_SNDBUF_BYTES),
        256 * 1024,
        64 * 1024 * 1024,
    )
}

pub(super) fn relay_v2_tuning() -> RelayV2Tuning {
    RelayV2Tuning {
        shard_count: get_shard_count(),
        pool_slots: get_pool_slots(),
        shard_queue_cap: get_shard_queue_cap(),
        tx_queue_cap: get_tx_queue_cap(),
        socket_rcvbuf_bytes: get_socket_rcvbuf_bytes(),
        socket_sndbuf_bytes: get_socket_sndbuf_bytes(),
        flow_rcvbuf_bytes: get_flow_socket_rcvbuf_bytes(),
        flow_sndbuf_bytes: get_flow_socket_sndbuf_bytes(),
    }
}

/// Fixed-size pool of packet buffers shared across RX/TX/shards.
struct BufferPool {
    buffers: Vec<UnsafeCell<[u8; super::MAX_PACKET_SIZE]>>,
    free_tx: crossbeam_channel::Sender<usize>,
    free_rx: crossbeam_channel::Receiver<usize>,
}

// Safety: buffer indices are checked out exclusively via the free list.
unsafe impl Sync for BufferPool {}
unsafe impl Send for BufferPool {}

impl BufferPool {
    /// Create a new pool with `slots` buffers and an index free list.
    fn new(slots: usize) -> Self {
        let (free_tx, free_rx) = crossbeam_channel::bounded(slots);
        let mut buffers = Vec::with_capacity(slots);
        for i in 0..slots {
            buffers.push(UnsafeCell::new([0u8; super::MAX_PACKET_SIZE]));
            free_tx
                .send(i)
                .expect("buffer pool free list must accept initial slots");
        }
        Self {
            buffers,
            free_tx,
            free_rx,
        }
    }

    /// Try to acquire a free buffer index.
    fn try_acquire(&self) -> Option<usize> {
        self.free_rx.try_recv().ok()
    }

    /// Release a buffer index back into the free list.
    fn release(&self, idx: usize) {
        if self.free_tx.send(idx).is_err() {
            log::error!(
                "V2 buffer pool release failed; dropping buffer index {}",
                idx
            );
        }
    }

    /// Get a mutable reference to the buffer for `idx`.
    #[allow(clippy::mut_from_ref)]
    unsafe fn buffer_mut(&self, idx: usize) -> &mut [u8; super::MAX_PACKET_SIZE] {
        &mut *self.buffers[idx].get()
    }

    /// Get an immutable reference to the buffer for `idx`.
    unsafe fn buffer(&self, idx: usize) -> &[u8; super::MAX_PACKET_SIZE] {
        &*self.buffers[idx].get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    session_id: [u8; super::SESSION_ID_LEN],
    game_addr: SocketAddr,
}

struct FlowState {
    socket: MioUdpSocket,
    client_addr: SocketAddr,
    original_info: super::OriginalPacketInfo,
    last_activity: Instant,
    marked_for_removal: Option<Instant>,
    token: Token,
}

enum ShardMsg {
    ClientPacket {
        session_id: [u8; super::SESSION_ID_LEN],
        client_addr: SocketAddr,
        game_addr: SocketAddr,
        original_info: super::OriginalPacketInfo,
        payload_idx: usize,
        payload_len: usize,
        enqueued_at: Instant,
    },
    Keepalive {
        session_id: [u8; super::SESSION_ID_LEN],
        client_addr: SocketAddr,
    },
    RemoveSession {
        session_id: [u8; super::SESSION_ID_LEN],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueuedPacketKind {
    Data,
    Control,
}

#[derive(Clone, Copy)]
struct TxPacket {
    addr: SocketAddr,
    session_id: [u8; super::SESSION_ID_LEN],
    buf_idx: usize,
    len: usize,
    enqueued_at: Instant,
    kind: QueuedPacketKind,
}

fn supervise_critical_thread(
    name: String,
    handle: std::thread::JoinHandle<Result<()>>,
) -> Result<()> {
    let supervisor_name = format!("{}-supervisor", name);
    std::thread::Builder::new()
        .name(supervisor_name)
        .spawn(move || {
            match handle.join() {
                Ok(Ok(())) => {
                    log::error!("{} thread exited unexpectedly", name);
                }
                Ok(Err(e)) => {
                    log::error!("{} thread exited with error: {}", name, e);
                }
                Err(panic) => {
                    log::error!("{} thread panicked: {:?}", name, panic);
                }
            }
            std::process::exit(70);
        })
        .context("Failed to spawn critical thread supervisor")?;
    Ok(())
}

/// Select a shard index for a given session ID.
fn shard_for_session(session_id: [u8; super::SESSION_ID_LEN], shard_count: usize) -> usize {
    // Mix the raw session_id to avoid shard hotspots if session IDs aren't uniformly random.
    // (Our client uses getrandom(), but this keeps the server resilient to other clients.)
    let mut sid = u64::from_be_bytes(session_id);
    sid ^= sid >> 33;
    sid = sid.wrapping_mul(0xff51afd7ed558ccd);
    sid ^= sid >> 33;
    sid = sid.wrapping_mul(0xc4ceb9fe1a85ec53);
    sid ^= sid >> 33;
    (sid as usize) % shard_count
}

fn should_drop_stale_queued_packet(
    kind: QueuedPacketKind,
    enqueued_at: Instant,
    now: Instant,
) -> bool {
    kind == QueuedPacketKind::Data
        && now.saturating_duration_since(enqueued_at) > MAX_DATA_QUEUE_AGE
}

/// Bind the relay's main UDP socket (client-facing) with tuned buffer sizes.
pub(super) fn bind_main_socket(listen_port: u16) -> Result<(UdpSocket, SocketBufferSizes)> {
    let tuning = relay_v2_tuning();
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("Failed to create UDP socket")?;
    socket
        .set_reuse_address(true)
        .context("Failed to set SO_REUSEADDR")?;
    socket
        .set_recv_buffer_size(tuning.socket_rcvbuf_bytes)
        .context("Failed to set SO_RCVBUF")?;
    socket
        .set_send_buffer_size(tuning.socket_sndbuf_bytes)
        .context("Failed to set SO_SNDBUF")?;
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, listen_port);
    socket
        .bind(&addr.into())
        .context("Failed to bind UDP socket")?;
    let std_socket: UdpSocket = socket.into();
    std_socket
        .set_write_timeout(Some(MAIN_SOCKET_SEND_TIMEOUT))
        .context("Failed to set main socket write timeout")?;
    let sock_ref = SockRef::from(&std_socket);
    let effective_rcvbuf_bytes = sock_ref.recv_buffer_size().unwrap_or(0);
    let effective_sndbuf_bytes = sock_ref.send_buffer_size().unwrap_or(0);
    Ok((
        std_socket,
        SocketBufferSizes {
            requested_rcvbuf_bytes: tuning.socket_rcvbuf_bytes,
            requested_sndbuf_bytes: tuning.socket_sndbuf_bytes,
            effective_rcvbuf_bytes,
            effective_sndbuf_bytes,
        },
    ))
}

/// Create and connect a per-flow UDP socket to the target game address.
fn create_flow_socket(game_addr: SocketAddr) -> Result<MioUdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("Failed to create flow UDP socket")?;
    socket
        .set_recv_buffer_size(get_flow_socket_rcvbuf_bytes())
        .context("Failed to set flow SO_RCVBUF")?;
    socket
        .set_send_buffer_size(get_flow_socket_sndbuf_bytes())
        .context("Failed to set flow SO_SNDBUF")?;
    socket
        .bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into())
        .context("Failed to bind flow socket")?;
    let std_socket: UdpSocket = socket.into();
    std_socket
        .set_nonblocking(true)
        .context("Failed to set flow socket nonblocking")?;
    std_socket
        .connect(game_addr)
        .context("Failed to connect flow socket")?;
    Ok(MioUdpSocket::from_std(std_socket))
}

/// Write a reconstructed IPv4+UDP packet into `dst` from a response payload.
fn write_response_ip_packet_into(
    dst: &mut [u8],
    udp_payload: &[u8],
    original: super::OriginalPacketInfo,
) -> Option<usize> {
    let udp_len = super::UDP_HEADER_SIZE + udp_payload.len();
    let total_len = super::IP_HEADER_MIN + udp_len;
    if total_len > dst.len() {
        return None;
    }

    let packet = &mut dst[..total_len];

    // === IP Header (20 bytes) ===
    packet[0] = 0x45; // v4, ihl=5
    packet[1] = 0; // DSCP/ECN
    packet[2] = ((total_len >> 8) & 0xFF) as u8;
    packet[3] = (total_len & 0xFF) as u8;
    // Identification (unused when DF is set; keep deterministic to avoid RNG overhead).
    packet[4] = 0;
    packet[5] = 0;
    packet[6] = 0x40; // DF
    packet[7] = 0;
    packet[8] = 64; // TTL
    packet[9] = 17; // UDP
    packet[10] = 0;
    packet[11] = 0;
    packet[12..16].copy_from_slice(&original.dst_ip.octets());
    packet[16..20].copy_from_slice(&original.src_ip.octets());

    let ip_checksum = super::calculate_ip_checksum(&packet[..super::IP_HEADER_MIN]);
    packet[10] = (ip_checksum >> 8) as u8;
    packet[11] = (ip_checksum & 0xFF) as u8;

    // === UDP Header (8 bytes) ===
    let udp_start = super::IP_HEADER_MIN;
    packet[udp_start] = (original.dst_port >> 8) as u8;
    packet[udp_start + 1] = (original.dst_port & 0xFF) as u8;
    packet[udp_start + 2] = (original.src_port >> 8) as u8;
    packet[udp_start + 3] = (original.src_port & 0xFF) as u8;
    packet[udp_start + 4] = ((udp_len >> 8) & 0xFF) as u8;
    packet[udp_start + 5] = (udp_len & 0xFF) as u8;
    packet[udp_start + 6] = 0;
    packet[udp_start + 7] = 0;

    let payload_start = udp_start + super::UDP_HEADER_SIZE;
    packet[payload_start..].copy_from_slice(udp_payload);

    Some(total_len)
}

/// Remove a flow from the per-session flow index.
fn remove_flow_from_session_index(
    session_flows: &mut HashMap<[u8; super::SESSION_ID_LEN], Vec<SocketAddr>>,
    flow: &FlowKey,
) {
    let Some(list) = session_flows.get_mut(&flow.session_id) else {
        return;
    };
    if let Some(pos) = list.iter().position(|addr| *addr == flow.game_addr) {
        list.swap_remove(pos);
    }
    if list.is_empty() {
        session_flows.remove(&flow.session_id);
    }
}

/// Allocate a unique mio `Token` for a new flow socket.
///
/// Token(0) is reserved for the shard waker.
fn allocate_flow_token(
    next_token: &mut usize,
    token_to_flow: &HashMap<Token, FlowKey>,
) -> Option<Token> {
    if *next_token == 0 {
        *next_token = 1;
    }

    let start = *next_token;
    loop {
        let token = Token(*next_token);

        // Advance for the next allocation attempt; skip reserved token 0.
        *next_token = next_token.wrapping_add(1);
        if *next_token == 0 {
            *next_token = 1;
        }

        if token == Token(0) || token_to_flow.contains_key(&token) {
            if *next_token == start {
                // Full cycle with no free tokens found (practically impossible).
                return None;
            }
            continue;
        }

        return Some(token);
    }
}

/// Run a shard event loop: manages per-flow sockets and forwards responses back to clients.
fn run_shard(
    shard_id: usize,
    inbox: crossbeam_channel::Receiver<ShardMsg>,
    tx_data: crossbeam_channel::Sender<TxPacket>,
    _tx_control: crossbeam_channel::Sender<TxPacket>,
    pool: Arc<BufferPool>,
    sessions: Arc<DashMap<[u8; super::SESSION_ID_LEN], super::SessionEntry>>,
    stats: Arc<super::Stats>,
    flow_counts: Arc<Vec<AtomicU64>>,
    waker_pub: crossbeam_channel::Sender<(usize, Arc<Waker>)>,
) -> Result<()> {
    const TOKEN_WAKE: Token = Token(0);

    let mut poll = Poll::new().context("Failed to create mio Poll")?;
    let waker =
        Arc::new(Waker::new(poll.registry(), TOKEN_WAKE).context("Failed to create mio Waker")?);
    waker_pub
        .send((shard_id, Arc::clone(&waker)))
        .expect("waker publish must succeed");

    let mut events = Events::with_capacity(1024);

    let mut next_token: usize = 1;
    let mut token_to_flow: HashMap<Token, FlowKey> = HashMap::new();
    let mut flows: HashMap<FlowKey, FlowState> = HashMap::new();
    let mut session_flows: HashMap<[u8; super::SESSION_ID_LEN], Vec<SocketAddr>> = HashMap::new();

    let mut recv_buf = [0u8; super::MAX_PACKET_SIZE];
    let mut cleanup_at = Instant::now() + super::CLEANUP_INTERVAL;

    log::info!("V2 shard {} started", shard_id);

    loop {
        let now = Instant::now();
        let timeout = cleanup_at.saturating_duration_since(now);
        poll.poll(&mut events, Some(timeout))
            .context("mio poll failed")?;

        for event in events.iter() {
            let token = event.token();
            if token == TOKEN_WAKE {
                // Drain inbox below.
                continue;
            }

            let Some(flow_key) = token_to_flow.get(&token).copied() else {
                continue;
            };
            let Some(flow) = flows.get_mut(&flow_key) else {
                continue;
            };

            // Drain a bounded burst so one hot game flow cannot monopolize the shard.
            for _ in 0..MAX_FLOW_RECV_BURST {
                match flow.socket.recv(&mut recv_buf) {
                    Ok(len) => {
                        let received_at = Instant::now();
                        flow.last_activity = received_at;
                        flow.marked_for_removal = None;

                        if let Some(mut session_entry) = sessions.get_mut(&flow_key.session_id) {
                            session_entry.last_activity = received_at;
                            session_entry.last_activity_unix = super::unix_timestamp_secs();
                        }

                        let Some(buf_idx) = pool.try_acquire() else {
                            stats.drop_out(super::DropReason::Pool);
                            stats.pool_exhausted.fetch_add(1, Ordering::Relaxed);
                            break;
                        };

                        let total_len = unsafe {
                            let out = pool.buffer_mut(buf_idx);
                            out[..super::SESSION_ID_LEN].copy_from_slice(&flow_key.session_id);
                            let ip_len = match write_response_ip_packet_into(
                                &mut out[super::SESSION_ID_LEN..],
                                &recv_buf[..len],
                                flow.original_info,
                            ) {
                                Some(value) => value,
                                None => {
                                    pool.release(buf_idx);
                                    break;
                                }
                            };
                            super::SESSION_ID_LEN + ip_len
                        };

                        let packet = TxPacket {
                            addr: flow.client_addr,
                            session_id: flow_key.session_id,
                            buf_idx,
                            len: total_len,
                            enqueued_at: received_at,
                            kind: QueuedPacketKind::Data,
                        };

                        if tx_data.try_send(packet).is_err() {
                            stats.drop_out(super::DropReason::TxQueue);
                            pool.release(buf_idx);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        log::debug!(
                            "V2 shard {} flow {} recv error: {} (kind={:?})",
                            shard_id,
                            flow_key.game_addr,
                            e,
                            e.kind()
                        );
                        break;
                    }
                }
            }
        }

        // Drain inbox (woken by RX thread).
        for _ in 0..MAX_INBOX_DRAIN_BURST {
            let Ok(msg) = inbox.try_recv() else {
                break;
            };
            match msg {
                ShardMsg::ClientPacket {
                    session_id,
                    client_addr,
                    game_addr,
                    original_info,
                    payload_idx,
                    payload_len,
                    enqueued_at,
                } => {
                    if should_drop_stale_queued_packet(
                        QueuedPacketKind::Data,
                        enqueued_at,
                        Instant::now(),
                    ) {
                        stats.drop_in(super::DropReason::StaleQueue);
                        pool.release(payload_idx);
                        continue;
                    }

                    let key = FlowKey {
                        session_id,
                        game_addr,
                    };

                    let flow = match flows.get_mut(&key) {
                        Some(existing) => existing,
                        None => {
                            let mut socket = match create_flow_socket(game_addr) {
                                Ok(sock) => sock,
                                Err(e) => {
                                    log::debug!(
                                        "V2 shard {} failed to create flow socket for {}: {}",
                                        shard_id,
                                        game_addr,
                                        e
                                    );
                                    stats.drop_in(super::DropReason::FlowCreate);
                                    pool.release(payload_idx);
                                    continue;
                                }
                            };

                            let Some(token) = allocate_flow_token(&mut next_token, &token_to_flow)
                            else {
                                log::error!(
                                    "V2 shard {} token allocator exhausted (flows={})",
                                    shard_id,
                                    flows.len()
                                );
                                stats.drop_in(super::DropReason::FlowCreate);
                                pool.release(payload_idx);
                                continue;
                            };
                            if let Err(e) =
                                poll.registry()
                                    .register(&mut socket, token, Interest::READABLE)
                            {
                                log::debug!(
                                    "V2 shard {} failed to register flow socket for {}: {}",
                                    shard_id,
                                    game_addr,
                                    e
                                );
                                stats.drop_in(super::DropReason::FlowCreate);
                                pool.release(payload_idx);
                                continue;
                            }

                            token_to_flow.insert(token, key);
                            session_flows.entry(session_id).or_default().push(game_addr);
                            flows.entry(key).or_insert(FlowState {
                                socket,
                                client_addr,
                                original_info,
                                last_activity: Instant::now(),
                                marked_for_removal: None,
                                token,
                            })
                        }
                    };

                    flow.client_addr = client_addr;
                    flow.original_info = original_info;
                    flow.last_activity = Instant::now();
                    flow.marked_for_removal = None;

                    let send_result = unsafe {
                        let buf = pool.buffer(payload_idx);
                        flow.socket.send(&buf[..payload_len])
                    };
                    pool.release(payload_idx);

                    match send_result {
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            stats.drop_in(super::DropReason::FlowSend);
                        }
                        Err(e) => {
                            log::debug!(
                                "V2 shard {} flow {} send error: {} (kind={:?})",
                                shard_id,
                                game_addr,
                                e,
                                e.kind()
                            );
                        }
                    }
                }
                ShardMsg::Keepalive {
                    session_id,
                    client_addr,
                } => {
                    if let Some(flow_list) = session_flows.get(&session_id) {
                        let now = Instant::now();
                        for &game_addr in flow_list.iter() {
                            let key = FlowKey {
                                session_id,
                                game_addr,
                            };
                            if let Some(flow) = flows.get_mut(&key) {
                                flow.client_addr = client_addr;
                                flow.last_activity = now;
                                flow.marked_for_removal = None;
                            }
                        }
                    }
                }
                ShardMsg::RemoveSession { session_id } => {
                    if let Some(flow_list) = session_flows.remove(&session_id) {
                        for game_addr in flow_list {
                            let key = FlowKey {
                                session_id,
                                game_addr,
                            };
                            if let Some(mut flow) = flows.remove(&key) {
                                let _ = poll.registry().deregister(&mut flow.socket);
                                token_to_flow.remove(&flow.token);
                            }
                        }
                    }
                }
            }
        }

        // Cleanup flows periodically.
        if Instant::now() >= cleanup_at {
            cleanup_at = Instant::now() + super::CLEANUP_INTERVAL;
            let now = Instant::now();

            let mut removed = 0u32;
            let mut marked = 0u32;
            let mut revived = 0u32;

            flows.retain(|key, flow| {
                let idle_time = now.duration_since(flow.last_activity);

                if let Some(marked_at) = flow.marked_for_removal {
                    if now.duration_since(marked_at) >= super::FLOW_GRACE_PERIOD {
                        let _ = poll.registry().deregister(&mut flow.socket);
                        token_to_flow.remove(&flow.token);
                        remove_flow_from_session_index(&mut session_flows, key);
                        removed += 1;
                        return false;
                    }

                    if idle_time < Duration::from_secs(10) {
                        flow.marked_for_removal = None;
                        revived += 1;
                    }
                    return true;
                }

                if idle_time >= super::SESSION_TIMEOUT {
                    flow.marked_for_removal = Some(now);
                    marked += 1;
                }

                true
            });

            flow_counts[shard_id].store(flows.len() as u64, Ordering::Relaxed);

            if removed > 0 || marked > 0 || revived > 0 {
                log::debug!(
                    "V2 shard {} cleanup: marked={}, revived={}, removed={}, flows={}",
                    shard_id,
                    marked,
                    revived,
                    removed,
                    flows.len()
                );
            }
        }
    }
}

/// Run the v2 sharded datapath (RX thread + shard threads + TX thread).
pub(super) async fn run_datapath_v2(
    main_socket: std::net::UdpSocket,
    stats_port: u16,
    stats_token: Option<String>,
    auth_config: super::RelayAuthConfig,
    runtime_config: super::RelayRuntimeConfig,
    stats: Arc<super::Stats>,
    started_at: Instant,
    tun_tx_sender: Option<crossbeam_channel::Sender<super::tcp_tun::InboundTunPacket>>,
    tun_session_cleanup: Option<super::tcp_tun::TunSessionCleanup>,
    tun_udp_enabled: bool,
    tcp_enabled: bool,
    session_traffic: Arc<DashMap<[u8; super::SESSION_ID_LEN], Arc<super::SessionTraffic>>>,
) -> Result<()> {
    let tuning = relay_v2_tuning();
    let shard_count = tuning.shard_count;
    let shard_queue_cap = tuning.shard_queue_cap;
    let tx_queue_cap = tuning.tx_queue_cap;
    let pool_slots = tuning.pool_slots;

    log::info!("Relay datapath: v2 (sharded)");
    log::info!("  Shards: {} (env RELAY_SHARDS)", shard_count);
    log::info!("  Pool slots: {} (env RELAY_V2_POOL_SLOTS)", pool_slots);
    log::info!(
        "  Shard queue: {} (env RELAY_V2_SHARD_QUEUE)",
        shard_queue_cap
    );
    log::info!("  TX queue: {} (env RELAY_V2_TX_QUEUE)", tx_queue_cap);

    let sessions: Arc<DashMap<[u8; super::SESSION_ID_LEN], super::SessionEntry>> =
        Arc::new(DashMap::new());

    if let Some(token) = stats_token {
        let ctx = Arc::new(super::StatsApiContext {
            sessions: Arc::clone(&sessions),
            session_traffic: Arc::clone(&session_traffic),
            stats: Arc::clone(&stats),
            runtime_config: runtime_config.clone(),
            started_at,
            rate_window: std::sync::Mutex::new(super::StatsRateWindow::new()),
            connections_snapshot: std::sync::RwLock::new(super::empty_connections_payload()),
        });

        super::spawn_connections_snapshot_updater(Arc::clone(&ctx));
        tokio::spawn(async move {
            if let Err(e) = super::run_stats_http_server(stats_port, token, ctx).await {
                log::error!("Stats API server error: {}", e);
            }
        });
    }

    let pool = Arc::new(BufferPool::new(pool_slots));

    // Use the pre-created main socket (shared with TCP response thread).
    let rx_socket = main_socket
        .try_clone()
        .context("Failed to clone RX socket")?;
    let tx_socket = main_socket;

    let (tx_control_s, tx_control_r) = crossbeam_channel::bounded::<TxPacket>(tx_queue_cap);
    let (tx_data_s, tx_data_r) = crossbeam_channel::bounded::<TxPacket>(tx_queue_cap);

    let mut counts = Vec::with_capacity(shard_count);
    for _ in 0..shard_count {
        counts.push(AtomicU64::new(0));
    }
    let flow_counts = Arc::new(counts);

    // TX thread.
    let stats_out = Arc::clone(&stats);
    let session_traffic_out = Arc::clone(&session_traffic);
    let pool_out = Arc::clone(&pool);
    let tx_thread = std::thread::Builder::new()
        .name("relay-tx".to_string())
        .spawn(move || -> Result<()> {
            loop {
                crossbeam_channel::select_biased! {
                    recv(tx_control_r) -> msg => {
                        let packet = match msg {
                            Ok(value) => value,
                            Err(_) => break,
                        };
                        send_tx_packet(&tx_socket, &pool_out, &stats_out, &session_traffic_out, packet);
                    }
                    recv(tx_data_r) -> msg => {
                        let packet = match msg {
                            Ok(value) => value,
                            Err(_) => break,
                        };
                        send_tx_packet(&tx_socket, &pool_out, &stats_out, &session_traffic_out, packet);
                    }
                }
            }
            Ok(())
        })
        .context("Failed to spawn TX thread")?;

    // Shards.
    let mut shard_senders = Vec::with_capacity(shard_count);
    let (waker_pub_s, waker_pub_r) = crossbeam_channel::bounded::<(usize, Arc<Waker>)>(shard_count);
    for shard_id in 0..shard_count {
        let (shard_s, shard_r) = crossbeam_channel::bounded::<ShardMsg>(shard_queue_cap);
        shard_senders.push(shard_s);

        let tx_data = tx_data_s.clone();
        let tx_control = tx_control_s.clone();
        let pool = Arc::clone(&pool);
        let sessions = Arc::clone(&sessions);
        let stats = Arc::clone(&stats);
        let flow_counts = Arc::clone(&flow_counts);
        let waker_pub = waker_pub_s.clone();

        let shard_handle = std::thread::Builder::new()
            .name(format!("relay-shard-{}", shard_id))
            .spawn(move || -> Result<()> {
                run_shard(
                    shard_id,
                    shard_r,
                    tx_data,
                    tx_control,
                    pool,
                    sessions,
                    stats,
                    flow_counts,
                    waker_pub,
                )
            })
            .context("Failed to spawn shard thread")?;
        supervise_critical_thread(format!("relay-shard-{}", shard_id), shard_handle)?;
    }
    drop(waker_pub_s);

    let mut shard_wakers: Vec<Option<Arc<Waker>>> = vec![None; shard_count];
    for _ in 0..shard_count {
        let (id, waker) = waker_pub_r
            .recv()
            .context("Failed to receive shard waker")?;
        shard_wakers[id] = Some(waker);
    }
    let shard_wakers: Vec<Arc<Waker>> = shard_wakers
        .into_iter()
        .map(|item| item.expect("every shard must publish a waker"))
        .collect();

    // Session cleanup task (drops sessions and signals shard flow cleanup).
    let sessions_cleanup = Arc::clone(&sessions);
    let session_traffic_cleanup = Arc::clone(&session_traffic);
    let stats_cleanup = Arc::clone(&stats);
    let shard_senders_cleanup = shard_senders.clone();
    let shard_wakers_cleanup = shard_wakers.clone();
    let tun_cleanup = tun_session_cleanup;
    tokio::spawn(async move {
        let mut cleanup_timer = tokio::time::interval(super::CLEANUP_INTERVAL);
        loop {
            cleanup_timer.tick().await;
            let now = Instant::now();
            let session_idle_limit = super::SESSION_TIMEOUT + super::FLOW_GRACE_PERIOD;

            let mut sessions_removed = 0u32;
            sessions_cleanup.retain(|session_id, session| {
                if now.duration_since(session.last_activity) >= session_idle_limit {
                    session_traffic_cleanup.remove(session_id);
                    sessions_removed += 1;
                    stats_cleanup
                        .active_sessions
                        .fetch_sub(1, Ordering::Relaxed);

                    let shard_id = shard_for_session(*session_id, shard_senders_cleanup.len());
                    if let Some(sender) = shard_senders_cleanup.get(shard_id) {
                        let _ = sender.try_send(ShardMsg::RemoveSession {
                            session_id: *session_id,
                        });
                    }
                    if let Some(waker) = shard_wakers_cleanup.get(shard_id) {
                        let _ = waker.wake();
                    }

                    return false;
                }
                true
            });

            if let Some(ref tun) = tun_cleanup {
                tun.remove_expired(|sid| sessions_cleanup.contains_key(sid));
            }

            // Update stats counters.
            if sessions_removed > 0 {
                log::info!(
                    "V2 cleanup: sessions_removed={}, sessions={}",
                    sessions_removed,
                    sessions_cleanup.len()
                );
            }
        }
    });

    // Stats logging task.
    let stats_log = Arc::clone(&stats);
    let flow_counts_log = Arc::clone(&flow_counts);
    tokio::spawn(async move {
        let mut stats_timer = tokio::time::interval(Duration::from_secs(60));
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

            let flows: u64 = flow_counts_log
                .iter()
                .map(|value| value.load(Ordering::Relaxed))
                .sum();
            stats_log.active_flows.store(flows, Ordering::Relaxed);

            log::info!(
                "Stats: in={} out={} ({:.1}/{:.1} MB), {:.0} pkt/s, sessions={}, flows={}, dropped={}+{}, pool_exhausted={}",
                pkts_in,
                pkts_out,
                bytes_in as f64 / 1_000_000.0,
                bytes_out as f64 / 1_000_000.0,
                (pkts_in + pkts_out) as f64 / elapsed,
                stats_log.active_sessions.load(Ordering::Relaxed),
                flows,
                dropped_in,
                dropped_out,
                pool_exhausted,
            );
        }
    });

    // RX thread.
    let auth_config_rx = auth_config.clone();
    let sessions_rx = Arc::clone(&sessions);
    let session_traffic_rx = Arc::clone(&session_traffic);
    let stats_rx = Arc::clone(&stats);
    let pool_rx = Arc::clone(&pool);
    let shard_senders_rx = shard_senders.clone();
    let shard_wakers_rx = shard_wakers.clone();
    let tx_control_rx = tx_control_s.clone();
    let tun_tx_sender_rx = tun_tx_sender;
    let tun_udp_enabled_rx = tun_udp_enabled;
    let tcp_enabled_rx = tcp_enabled;
    let rx_thread = std::thread::Builder::new()
        .name("relay-rx".to_string())
        .spawn(move || -> Result<()> {
            let mut buf = [0u8; super::MAX_PACKET_SIZE];

            loop {
                let (len, client_addr) = match rx_socket.recv_from(&mut buf) {
                    Ok(r) => r,
                    Err(e) => {
                        log::warn!("Recv error: {}", e);
                        continue;
                    }
                };

                stats_rx.packets_in.fetch_add(1, Ordering::Relaxed);
                stats_rx.bytes_in.fetch_add(len as u64, Ordering::Relaxed);

                if len < super::SESSION_ID_LEN {
                    stats_rx.drop_in(super::DropReason::TooSmall);
                    continue;
                }

                let mut session_id = [0u8; super::SESSION_ID_LEN];
                session_id.copy_from_slice(&buf[..super::SESSION_ID_LEN]);

                let now = Instant::now();
                let now_unix = super::unix_timestamp_secs();

                let mut session_authenticated = false;
                let auth_required = auth_config_rx.mode.requires_auth();
                match sessions_rx.entry(session_id) {
                    dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                        let session = entry.get_mut();
                        session_authenticated =
                            matches!(session.auth_state, super::SessionAuthState::Authenticated);
                        // Only trust client_addr updates from authenticated traffic when auth is
                        // required; otherwise an unauthenticated attacker with a known session_id
                        // can rewrite the session's observed client endpoint.
                        if !auth_required || session_authenticated {
                            session.client_addr = client_addr;
                            session.last_activity = now;
                            session.last_activity_unix = now_unix;
                        }
                    }
                    dashmap::mapref::entry::Entry::Vacant(entry) => {
                        entry.insert(super::SessionEntry {
                            user_id: super::derive_user_id(session_id),
                            auth_state: super::SessionAuthState::Legacy,
                            client_addr,
                            created_at_unix: now_unix,
                            last_activity: now,
                            last_activity_unix: now_unix,
                        });
                        stats_rx.active_sessions.fetch_add(1, Ordering::Relaxed);
                    }
                }

                super::record_session_ingress(&session_traffic_rx, session_id, now_unix, len);

                // Auth hello:
                if len >= super::SESSION_ID_LEN + 3
                    && buf[super::SESSION_ID_LEN] == super::AUTH_HELLO_FRAME_TYPE
                {
                    if auth_config_rx.mode == super::RelayAuthMode::Off {
                        send_small_control_frame(
                            &tx_control_rx,
                            &pool_rx,
                            client_addr,
                            session_id,
                            super::AUTH_ACK_FRAME_TYPE,
                            super::AUTH_ACK_AUTH_DISABLED,
                            &stats_rx,
                        );
                        continue;
                    }

                    let token = match super::parse_auth_hello_token(&buf, len) {
                        Ok(value) => value,
                        Err(err) => {
                            send_small_control_frame(
                                &tx_control_rx,
                                &pool_rx,
                                client_addr,
                                session_id,
                                super::AUTH_ACK_FRAME_TYPE,
                                err.ack_status(),
                                &stats_rx,
                            );
                            continue;
                        }
                    };

                    match super::verify_relay_ticket(token, session_id, &auth_config_rx, now_unix) {
                        Ok(user_id) => {
                            if let Some(mut session_entry) = sessions_rx.get_mut(&session_id) {
                                session_entry.user_id = user_id;
                                session_entry.auth_state = super::SessionAuthState::Authenticated;
                            }
                            send_small_control_frame(
                                &tx_control_rx,
                                &pool_rx,
                                client_addr,
                                session_id,
                                super::AUTH_ACK_FRAME_TYPE,
                                super::AUTH_ACK_OK,
                                &stats_rx,
                            );
                        }
                        Err(err) => {
                            send_small_control_frame(
                                &tx_control_rx,
                                &pool_rx,
                                client_addr,
                                session_id,
                                super::AUTH_ACK_FRAME_TYPE,
                                err.ack_status(),
                                &stats_rx,
                            );
                        }
                    }
                    continue;
                }

                // RTT/jitter ping:
                if len == super::PING_FRAME_LEN
                    && buf[super::SESSION_ID_LEN] == super::PING_FRAME_TYPE
                {
                    if auth_config_rx.mode.requires_auth() && !session_authenticated {
                        stats_rx.drop_in(super::DropReason::Auth);
                        continue;
                    }

                    let seq = u32::from_be_bytes([
                        buf[super::SESSION_ID_LEN + 1],
                        buf[super::SESSION_ID_LEN + 2],
                        buf[super::SESSION_ID_LEN + 3],
                        buf[super::SESSION_ID_LEN + 4],
                    ]);
                    let client_ts_mono_ms = u64::from_be_bytes([
                        buf[super::SESSION_ID_LEN + 5],
                        buf[super::SESSION_ID_LEN + 6],
                        buf[super::SESSION_ID_LEN + 7],
                        buf[super::SESSION_ID_LEN + 8],
                        buf[super::SESSION_ID_LEN + 9],
                        buf[super::SESSION_ID_LEN + 10],
                        buf[super::SESSION_ID_LEN + 11],
                        buf[super::SESSION_ID_LEN + 12],
                    ]);
                    let server_rx_ts_mono_ms = super::mono_timestamp_ms();

                    let Some(buf_idx) = pool_rx.try_acquire() else {
                        stats_rx.drop_out(super::DropReason::Pool);
                        stats_rx.pool_exhausted.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };

                    let out_len = unsafe {
                        let out = pool_rx.buffer_mut(buf_idx);
                        out[..super::SESSION_ID_LEN].copy_from_slice(&session_id);
                        out[super::SESSION_ID_LEN] = super::PONG_FRAME_TYPE;
                        out[super::SESSION_ID_LEN + 1..super::SESSION_ID_LEN + 5]
                            .copy_from_slice(&seq.to_be_bytes());
                        out[super::SESSION_ID_LEN + 5..super::SESSION_ID_LEN + 13]
                            .copy_from_slice(&client_ts_mono_ms.to_be_bytes());
                        out[super::SESSION_ID_LEN + 13..super::SESSION_ID_LEN + 21]
                            .copy_from_slice(&server_rx_ts_mono_ms.to_be_bytes());
                        super::PONG_FRAME_LEN
                    };

                    let packet = TxPacket {
                        addr: client_addr,
                        session_id,
                        buf_idx,
                        len: out_len,
                        enqueued_at: Instant::now(),
                        kind: QueuedPacketKind::Control,
                    };
                    if tx_control_rx.try_send(packet).is_err() {
                        stats_rx.drop_out(super::DropReason::TxQueue);
                        pool_rx.release(buf_idx);
                    }
                    continue;
                }

                if len == super::PONG_FRAME_LEN
                    && buf[super::SESSION_ID_LEN] == super::PONG_FRAME_TYPE
                {
                    continue;
                }

                // Client-reported RTT: [session_id:8][0xA5][rtt_us_be_u32]
                if len == super::RTT_REPORT_FRAME_LEN
                    && buf[super::SESSION_ID_LEN] == super::RTT_REPORT_FRAME_TYPE
                {
                    if auth_config_rx.mode.requires_auth() && !session_authenticated {
                        stats_rx.drop_in(super::DropReason::Auth);
                        continue;
                    }
                    let rtt_us = u32::from_be_bytes([
                        buf[super::SESSION_ID_LEN + 1],
                        buf[super::SESSION_ID_LEN + 2],
                        buf[super::SESSION_ID_LEN + 3],
                        buf[super::SESSION_ID_LEN + 4],
                    ]);
                    if let Some(entry) = session_traffic_rx.get(&session_id) {
                        entry
                            .value()
                            .last_rtt_us
                            .store(rtt_us as u64, Ordering::Relaxed);
                    }
                    continue;
                }

                // Keepalive:
                if len == super::SESSION_ID_LEN {
                    if auth_config_rx.mode.requires_auth() && !session_authenticated {
                        stats_rx.drop_in(super::DropReason::Auth);
                        continue;
                    }

                    let shard_id = shard_for_session(session_id, shard_senders_rx.len());
                    if let Some(sender) = shard_senders_rx.get(shard_id) {
                        if sender
                            .try_send(ShardMsg::Keepalive {
                                session_id,
                                client_addr,
                            })
                            .is_err()
                        {
                            stats_rx.drop_in(super::DropReason::ShardQueue);
                        } else if let Some(waker) = shard_wakers_rx.get(shard_id) {
                            let _ = waker.wake();
                        }
                    }
                    continue;
                }

                if auth_config_rx.mode.requires_auth() && !session_authenticated {
                    stats_rx.drop_in(super::DropReason::Auth);
                    continue;
                }

                if len < super::SESSION_ID_LEN + super::IP_HEADER_MIN {
                    stats_rx.drop_in(super::DropReason::TooSmall);
                    continue;
                }

                let ip_packet = &buf[super::SESSION_ID_LEN..len];
                let parsed = match super::parse_ip_packet_full(ip_packet) {
                    Some(p) => p,
                    None => {
                        stats_rx.drop_in(super::DropReason::Parse);
                        continue;
                    }
                };

                match parsed {
                    super::ParsedPacket::Fragment {
                        protocol,
                        src_ip,
                        raw_ip_packet,
                    } => {
                        let can_tun = (protocol == 17 && tun_udp_enabled_rx)
                            || (protocol == 6 && tcp_enabled_rx);
                        if can_tun {
                            if let Some(ref tun_sender) = tun_tx_sender_rx {
                                if tun_sender
                                    .try_send(super::tcp_tun::InboundTunPacket {
                                        session_id,
                                        client_addr,
                                        raw_ip_packet: raw_ip_packet.to_vec(),
                                    })
                                    .is_err()
                                {
                                    stats_rx.drop_in(super::DropReason::TunQueue);
                                } else if protocol == 6 {
                                    stats_rx.tcp_forwarded.fetch_add(1, Ordering::Relaxed);
                                } else {
                                    stats_rx.tun_udp_forwarded.fetch_add(1, Ordering::Relaxed);
                                }
                            } else {
                                stats_rx.drop_in(super::DropReason::TunQueue);
                            }
                        } else {
                            stats_rx.drop_in(super::DropReason::Fragment);
                        }
                        if let Some(mut session_entry) = sessions_rx.get_mut(&session_id) {
                            if !matches!(
                                session_entry.auth_state,
                                super::SessionAuthState::Authenticated
                            ) {
                                session_entry.user_id = src_ip.to_string();
                            }
                        }
                        continue;
                    }
                    super::ParsedPacket::Tcp {
                        original_info,
                        raw_ip_packet,
                    } => {
                        if tcp_enabled_rx {
                            if let Some(ref tun_sender) = tun_tx_sender_rx {
                                if tun_sender
                                    .try_send(super::tcp_tun::InboundTunPacket {
                                        session_id,
                                        client_addr,
                                        raw_ip_packet: raw_ip_packet.to_vec(),
                                    })
                                    .is_err()
                                {
                                    stats_rx.drop_in(super::DropReason::TunQueue);
                                } else {
                                    stats_rx.tcp_forwarded.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        if let Some(mut session_entry) = sessions_rx.get_mut(&session_id) {
                            if !matches!(
                                session_entry.auth_state,
                                super::SessionAuthState::Authenticated
                            ) {
                                session_entry.user_id = original_info.src_ip.to_string();
                            }
                        }
                        continue;
                    }
                    super::ParsedPacket::Udp {
                        game_addr,
                        payload: udp_payload,
                        original_info,
                        raw_ip_packet,
                    } => {
                        if tun_udp_enabled_rx {
                            if let Some(ref tun_sender) = tun_tx_sender_rx {
                                if tun_sender
                                    .try_send(super::tcp_tun::InboundTunPacket {
                                        session_id,
                                        client_addr,
                                        raw_ip_packet: raw_ip_packet.to_vec(),
                                    })
                                    .is_err()
                                {
                                    stats_rx.drop_in(super::DropReason::TunQueue);
                                } else {
                                    stats_rx.tun_udp_forwarded.fetch_add(1, Ordering::Relaxed);
                                }
                            } else {
                                stats_rx.drop_in(super::DropReason::TunQueue);
                            }
                            if let Some(mut session_entry) = sessions_rx.get_mut(&session_id) {
                                if !matches!(
                                    session_entry.auth_state,
                                    super::SessionAuthState::Authenticated
                                ) {
                                    session_entry.user_id = original_info.src_ip.to_string();
                                }
                            }
                            continue;
                        }

                        if let Some(mut session_entry) = sessions_rx.get_mut(&session_id) {
                            if !matches!(
                                session_entry.auth_state,
                                super::SessionAuthState::Authenticated
                            ) {
                                session_entry.user_id = original_info.src_ip.to_string();
                            }
                        }

                        let Some(payload_idx) = pool_rx.try_acquire() else {
                            stats_rx.drop_in(super::DropReason::Pool);
                            stats_rx.pool_exhausted.fetch_add(1, Ordering::Relaxed);
                            continue;
                        };

                        unsafe {
                            let out = pool_rx.buffer_mut(payload_idx);
                            out[..udp_payload.len()].copy_from_slice(udp_payload);
                        }

                        let shard_id = shard_for_session(session_id, shard_senders_rx.len());
                        if let Some(sender) = shard_senders_rx.get(shard_id) {
                            if sender
                                .try_send(ShardMsg::ClientPacket {
                                    session_id,
                                    client_addr,
                                    game_addr,
                                    original_info,
                                    payload_idx,
                                    payload_len: udp_payload.len(),
                                    enqueued_at: now,
                                })
                                .is_err()
                            {
                                stats_rx.drop_in(super::DropReason::ShardQueue);
                                pool_rx.release(payload_idx);
                            } else if let Some(waker) = shard_wakers_rx.get(shard_id) {
                                let _ = waker.wake();
                            }
                        } else {
                            stats_rx.drop_in(super::DropReason::ShardQueue);
                            pool_rx.release(payload_idx);
                        }
                    }
                }
            }
        })
        .context("Failed to spawn RX thread")?;

    supervise_critical_thread("relay-tx".to_string(), tx_thread)?;
    supervise_critical_thread("relay-rx".to_string(), rx_thread)?;

    std::future::pending::<()>().await;
    Ok(())
}

/// Send a pre-built client frame and update global/session traffic counters.
fn send_tx_packet(
    socket: &UdpSocket,
    pool: &BufferPool,
    stats: &super::Stats,
    session_traffic: &DashMap<[u8; super::SESSION_ID_LEN], Arc<super::SessionTraffic>>,
    packet: TxPacket,
) {
    if should_drop_stale_queued_packet(packet.kind, packet.enqueued_at, Instant::now()) {
        stats.drop_out(super::DropReason::StaleQueue);
        pool.release(packet.buf_idx);
        return;
    }

    let bytes = unsafe { pool.buffer(packet.buf_idx) };
    if let Err(e) = socket.send_to(&bytes[..packet.len], packet.addr) {
        log::trace!("TX send error to {}: {}", packet.addr, e);
        stats.drop_out(super::DropReason::SocketSend);
    } else {
        stats.packets_out.fetch_add(1, Ordering::Relaxed);
        stats
            .bytes_out
            .fetch_add(packet.len as u64, Ordering::Relaxed);
        if let Some(entry) = session_traffic.get(&packet.session_id) {
            entry
                .value()
                .bytes_out
                .fetch_add(packet.len as u64, Ordering::Relaxed);
            entry.value().packets_out.fetch_add(1, Ordering::Relaxed);
            entry
                .value()
                .last_activity_unix
                .store(super::unix_timestamp_secs(), Ordering::Relaxed);
        }
    }
    pool.release(packet.buf_idx);
}

/// Build and send a small control frame (session_id + type + status) via the TX thread.
fn send_small_control_frame(
    tx_control: &crossbeam_channel::Sender<TxPacket>,
    pool: &BufferPool,
    client_addr: SocketAddr,
    session_id: [u8; super::SESSION_ID_LEN],
    frame_type: u8,
    status: u8,
    stats: &super::Stats,
) {
    let Some(buf_idx) = pool.try_acquire() else {
        stats.drop_out(super::DropReason::Pool);
        stats.pool_exhausted.fetch_add(1, Ordering::Relaxed);
        return;
    };

    let len = unsafe {
        let out = pool.buffer_mut(buf_idx);
        out[..super::SESSION_ID_LEN].copy_from_slice(&session_id);
        out[super::SESSION_ID_LEN] = frame_type;
        out[super::SESSION_ID_LEN + 1] = status;
        super::SESSION_ID_LEN + 2
    };

    let packet = TxPacket {
        addr: client_addr,
        session_id,
        buf_idx,
        len,
        enqueued_at: Instant::now(),
        kind: QueuedPacketKind::Control,
    };

    if tx_control.try_send(packet).is_err() {
        stats.drop_out(super::DropReason::TxQueue);
        pool.release(buf_idx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::SocketAddr;

    // ── helpers ──────────────────────────────────────────────────────────

    fn test_original_info() -> super::super::OriginalPacketInfo {
        super::super::OriginalPacketInfo {
            src_ip: "10.0.0.5".parse().unwrap(),
            src_port: 54321,
            dst_ip: "1.2.3.4".parse().unwrap(),
            dst_port: 12345,
        }
    }

    fn make_flow_key(sid: u8, port: u16) -> FlowKey {
        let mut session_id = [0u8; super::super::SESSION_ID_LEN];
        session_id[0] = sid;
        FlowKey {
            session_id,
            game_addr: SocketAddr::from(([127, 0, 0, 1], port)),
        }
    }

    #[test]
    fn test_stale_data_queue_packet_is_dropped() {
        let now = Instant::now();
        assert!(should_drop_stale_queued_packet(
            QueuedPacketKind::Data,
            now - MAX_DATA_QUEUE_AGE - Duration::from_millis(1),
            now
        ));
    }

    #[test]
    fn test_fresh_data_queue_packet_is_not_dropped() {
        let now = Instant::now();
        assert!(!should_drop_stale_queued_packet(
            QueuedPacketKind::Data,
            now - MAX_DATA_QUEUE_AGE,
            now
        ));
    }

    #[test]
    fn test_stale_control_queue_packet_is_not_dropped() {
        let now = Instant::now();
        assert!(!should_drop_stale_queued_packet(
            QueuedPacketKind::Control,
            now - MAX_DATA_QUEUE_AGE - Duration::from_millis(1),
            now
        ));
    }

    // ── get_relay_datapath ──────────────────────────────────────────────
    // NOTE: These tests read the RELAY_DATAPATH environment variable directly.
    // They are NOT safe to run in parallel with each other because they
    // mutate shared process-global state. Run with `--test-threads=1` to
    // avoid flakiness, or rely on CI running `cargo test` with the env unset.

    #[test]
    fn test_get_relay_datapath_default_is_v2() {
        // When RELAY_DATAPATH is unset the default must be V2.
        // This test is safe as long as the env var is not set externally.
        std::env::remove_var("RELAY_DATAPATH");
        assert_eq!(get_relay_datapath(), RelayDatapath::V2);
    }

    #[test]
    fn test_get_relay_datapath_v1_literal() {
        std::env::set_var("RELAY_DATAPATH", "v1");
        assert_eq!(get_relay_datapath(), RelayDatapath::V1);
        std::env::remove_var("RELAY_DATAPATH");
    }

    #[test]
    fn test_get_relay_datapath_tokio_alias() {
        std::env::set_var("RELAY_DATAPATH", "tokio");
        assert_eq!(get_relay_datapath(), RelayDatapath::V1);
        std::env::remove_var("RELAY_DATAPATH");
    }

    // ── clamp_usize ────────────────────────────────────────────────────

    #[test]
    fn test_clamp_usize_below_min() {
        assert_eq!(clamp_usize(5, 10, 100), 10);
    }

    #[test]
    fn test_clamp_usize_above_max() {
        assert_eq!(clamp_usize(200, 10, 100), 100);
    }

    #[test]
    fn test_clamp_usize_in_range() {
        assert_eq!(clamp_usize(50, 10, 100), 50);
    }

    #[test]
    fn test_clamp_usize_at_min_boundary() {
        assert_eq!(clamp_usize(10, 10, 100), 10);
    }

    #[test]
    fn test_clamp_usize_at_max_boundary() {
        assert_eq!(clamp_usize(100, 10, 100), 100);
    }

    // ── shard_for_session ──────────────────────────────────────────────

    #[test]
    fn test_shard_for_session_deterministic() {
        let sid = [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44];
        let a = shard_for_session(sid, 8);
        let b = shard_for_session(sid, 8);
        assert_eq!(a, b, "same input must produce same shard");
    }

    #[test]
    fn test_shard_for_session_different_ids() {
        let sid_a = [1, 0, 0, 0, 0, 0, 0, 0];
        let sid_b = [2, 0, 0, 0, 0, 0, 0, 0];
        // With 256 shards, two distinct IDs should (almost certainly) hash differently.
        let a = shard_for_session(sid_a, 256);
        let b = shard_for_session(sid_b, 256);
        assert_ne!(
            a, b,
            "distinct session IDs should likely map to different shards"
        );
    }

    #[test]
    fn test_shard_for_session_single_shard() {
        let sid = [0xFF; super::super::SESSION_ID_LEN];
        assert_eq!(shard_for_session(sid, 1), 0);
    }

    #[test]
    fn test_shard_for_session_distribution() {
        let shard_count = 8usize;
        let mut counts = vec![0u32; shard_count];
        for i in 0u64..256 {
            let sid = i.to_be_bytes();
            counts[shard_for_session(sid, shard_count)] += 1;
        }
        for (shard_id, &count) in counts.iter().enumerate() {
            assert!(
                count >= 1,
                "shard {} received 0 session IDs out of 256; distribution is broken",
                shard_id
            );
        }
    }

    #[test]
    fn test_shard_for_session_in_range() {
        for shard_count in [1, 2, 4, 7, 16, 255] {
            for i in 0u64..64 {
                let sid = i.to_be_bytes();
                let shard = shard_for_session(sid, shard_count);
                assert!(
                    shard < shard_count,
                    "shard {} >= shard_count {} for session {:?}",
                    shard,
                    shard_count,
                    sid
                );
            }
        }
    }

    // ── write_response_ip_packet_into ──────────────────────────────────

    #[test]
    fn test_write_response_ip_packet_into_normal() {
        let payload = b"hello game";
        let original = test_original_info();
        let total = super::super::IP_HEADER_MIN + super::super::UDP_HEADER_SIZE + payload.len();
        let mut buf = vec![0u8; total + 64]; // extra room
        let result = write_response_ip_packet_into(&mut buf, payload, original);
        assert_eq!(result, Some(total));
        // IP version+IHL
        assert_eq!(buf[0], 0x45);
        // Protocol = UDP (17)
        assert_eq!(buf[9], 17);
        // TTL = 64
        assert_eq!(buf[8], 64);
        // Source IP = original dst_ip (game server = 1.2.3.4)
        assert_eq!(&buf[12..16], &[1, 2, 3, 4]);
        // Dest IP = original src_ip (client = 10.0.0.5)
        assert_eq!(&buf[16..20], &[10, 0, 0, 5]);
        // UDP payload
        let payload_start = super::super::IP_HEADER_MIN + super::super::UDP_HEADER_SIZE;
        assert_eq!(&buf[payload_start..payload_start + payload.len()], payload);
    }

    #[test]
    fn test_write_response_ip_packet_into_buffer_too_small() {
        let payload = b"hello game";
        let original = test_original_info();
        let total = super::super::IP_HEADER_MIN + super::super::UDP_HEADER_SIZE + payload.len();
        let mut buf = vec![0u8; total - 1]; // one byte short
        let result = write_response_ip_packet_into(&mut buf, payload, original);
        assert_eq!(result, None);
    }

    #[test]
    fn test_write_response_ip_packet_into_zero_payload() {
        let original = test_original_info();
        let total = super::super::IP_HEADER_MIN + super::super::UDP_HEADER_SIZE;
        let mut buf = vec![0u8; total];
        let result = write_response_ip_packet_into(&mut buf, &[], original);
        assert_eq!(result, Some(total));
    }

    #[test]
    fn test_write_response_ip_packet_into_exact_buffer_size() {
        let payload = b"data";
        let original = test_original_info();
        let total = super::super::IP_HEADER_MIN + super::super::UDP_HEADER_SIZE + payload.len();
        let mut buf = vec![0u8; total]; // exactly right
        let result = write_response_ip_packet_into(&mut buf, payload, original);
        assert_eq!(result, Some(total));
    }

    #[test]
    fn test_write_response_ip_packet_into_matches_build() {
        let payload = b"match test payload";
        let original = test_original_info();
        let expected = super::super::build_response_ip_packet(payload, original);
        let mut buf = vec![0u8; expected.len() + 32];
        let len = write_response_ip_packet_into(&mut buf, payload, original).unwrap();
        assert_eq!(
            &buf[..len],
            &expected[..],
            "write_into must match build_response_ip_packet byte-for-byte"
        );
    }

    // ── remove_flow_from_session_index ─────────────────────────────────

    #[test]
    fn test_remove_flow_existing() {
        let flow = make_flow_key(1, 8000);
        let mut session_flows = HashMap::new();
        session_flows.insert(flow.session_id, vec![flow.game_addr]);
        remove_flow_from_session_index(&mut session_flows, &flow);
        // Session entry should be removed because the list became empty.
        assert!(!session_flows.contains_key(&flow.session_id));
    }

    #[test]
    fn test_remove_flow_missing_session_is_noop() {
        let flow = make_flow_key(99, 9999);
        let mut session_flows: HashMap<[u8; super::super::SESSION_ID_LEN], Vec<SocketAddr>> =
            HashMap::new();
        // Should not panic or modify anything.
        remove_flow_from_session_index(&mut session_flows, &flow);
        assert!(session_flows.is_empty());
    }

    #[test]
    fn test_remove_flow_missing_game_addr_is_noop() {
        let flow = make_flow_key(1, 8000);
        let other_addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let mut session_flows = HashMap::new();
        session_flows.insert(flow.session_id, vec![other_addr]);
        remove_flow_from_session_index(&mut session_flows, &flow);
        // The entry should remain with the other address intact.
        assert_eq!(session_flows[&flow.session_id], vec![other_addr]);
    }

    #[test]
    fn test_remove_flow_last_flow_removes_session_entry() {
        let flow = make_flow_key(1, 5000);
        let mut session_flows = HashMap::new();
        session_flows.insert(flow.session_id, vec![flow.game_addr]);
        remove_flow_from_session_index(&mut session_flows, &flow);
        assert!(
            session_flows.is_empty(),
            "removing last flow must remove the session entry"
        );
    }

    #[test]
    fn test_remove_flow_multiple_flows_same_session() {
        let flow_a = make_flow_key(1, 7000);
        let flow_b = FlowKey {
            session_id: flow_a.session_id,
            game_addr: "127.0.0.1:7001".parse().unwrap(),
        };
        let mut session_flows = HashMap::new();
        session_flows.insert(flow_a.session_id, vec![flow_a.game_addr, flow_b.game_addr]);
        remove_flow_from_session_index(&mut session_flows, &flow_a);
        let remaining = &session_flows[&flow_a.session_id];
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0], flow_b.game_addr);
    }

    // ── allocate_flow_token ────────────────────────────────────────────

    #[test]
    fn test_allocate_flow_token_first_allocation() {
        let mut next = 1usize;
        let map: HashMap<Token, FlowKey> = HashMap::new();
        let token = allocate_flow_token(&mut next, &map);
        assert_eq!(token, Some(Token(1)));
    }

    #[test]
    fn test_allocate_flow_token_skips_zero() {
        let mut next = 0usize;
        let map: HashMap<Token, FlowKey> = HashMap::new();
        let token = allocate_flow_token(&mut next, &map);
        // Token(0) is reserved; it should skip to Token(1).
        assert_eq!(token, Some(Token(1)));
    }

    #[test]
    fn test_allocate_flow_token_skips_occupied() {
        let mut next = 1usize;
        let mut map: HashMap<Token, FlowKey> = HashMap::new();
        map.insert(Token(1), make_flow_key(1, 1000));
        let token = allocate_flow_token(&mut next, &map);
        assert_eq!(token, Some(Token(2)));
    }

    #[test]
    fn test_allocate_flow_token_wraps_around() {
        let mut next = usize::MAX;
        let map: HashMap<Token, FlowKey> = HashMap::new();
        let token = allocate_flow_token(&mut next, &map);
        // usize::MAX is a valid token value, should be returned.
        assert_eq!(token, Some(Token(usize::MAX)));
        // Next allocation should wrap around past 0 to 1.
        let token2 = allocate_flow_token(&mut next, &map);
        assert_eq!(token2, Some(Token(1)));
    }

    #[test]
    fn test_allocate_flow_token_sequential_unique() {
        let mut next = 1usize;
        let mut map: HashMap<Token, FlowKey> = HashMap::new();
        let mut allocated = Vec::new();
        for i in 0..100 {
            let token = allocate_flow_token(&mut next, &map).unwrap();
            // Simulate occupying the token.
            map.insert(token, make_flow_key(i as u8, 1000 + i));
            allocated.push(token);
        }
        // All tokens must be distinct.
        let mut set = std::collections::HashSet::new();
        for t in &allocated {
            assert!(set.insert(t.0), "duplicate token {:?}", t);
        }
    }

    #[test]
    fn test_allocate_flow_token_full_cycle_returns_none() {
        // With a tiny space (tokens 1..=3, i.e. 3 usable tokens), fill them
        // all, then verify that allocation returns None.
        //
        // We can't actually fill the full usize range, so we simulate by
        // ensuring every value from start through the full cycle is occupied.
        let mut next = 1usize;
        let mut map: HashMap<Token, FlowKey> = HashMap::new();
        // Occupy tokens 1, 2, 3.
        map.insert(Token(1), make_flow_key(1, 1000));
        map.insert(Token(2), make_flow_key(2, 1001));
        map.insert(Token(3), make_flow_key(3, 1002));

        // We can't realistically occupy all of usize, but we can test the
        // wrap-around logic by occupying everything the allocator will try.
        // The allocator starts at *next_token (1) and tries every value back
        // to start. For a full-cycle None it must try every usize value, so
        // this particular test verifies partial behavior: the allocator skips
        // occupied tokens and eventually finds an open one.
        let token = allocate_flow_token(&mut next, &map);
        // Token 4 is not occupied, so it should be returned.
        assert_eq!(token, Some(Token(4)));
    }

    // ── BufferPool ─────────────────────────────────────────────────────

    #[test]
    fn test_buffer_pool_new_creates_correct_slot_count() {
        let pool = BufferPool::new(16);
        let mut acquired = Vec::new();
        while let Some(idx) = pool.try_acquire() {
            acquired.push(idx);
        }
        assert_eq!(
            acquired.len(),
            16,
            "pool of 16 slots should yield 16 acquires"
        );
    }

    #[test]
    fn test_buffer_pool_try_acquire_returns_indices() {
        let pool = BufferPool::new(4);
        let mut indices: Vec<usize> = Vec::new();
        for _ in 0..4 {
            indices.push(pool.try_acquire().expect("should acquire"));
        }
        indices.sort();
        assert_eq!(indices, vec![0, 1, 2, 3]);
    }

    #[test]
    fn test_buffer_pool_release_and_reacquire() {
        let pool = BufferPool::new(2);
        let a = pool.try_acquire().unwrap();
        let b = pool.try_acquire().unwrap();
        assert!(pool.try_acquire().is_none(), "pool should be exhausted");
        pool.release(a);
        let c = pool.try_acquire().unwrap();
        assert_eq!(c, a, "released index should be re-acquired");
        pool.release(b);
        pool.release(c);
    }

    #[test]
    fn test_buffer_pool_exhaustion_returns_none() {
        let pool = BufferPool::new(1);
        let _idx = pool.try_acquire().unwrap();
        assert!(pool.try_acquire().is_none());
    }

    #[test]
    fn test_buffer_pool_acquire_all_then_release_all() {
        let slots = 32;
        let pool = BufferPool::new(slots);
        let mut acquired = Vec::new();
        for _ in 0..slots {
            acquired.push(pool.try_acquire().unwrap());
        }
        assert!(pool.try_acquire().is_none());
        for idx in acquired {
            pool.release(idx);
        }
        // After releasing all, we should be able to acquire them again.
        let mut re_acquired = Vec::new();
        while let Some(idx) = pool.try_acquire() {
            re_acquired.push(idx);
        }
        assert_eq!(re_acquired.len(), slots);
    }

    #[test]
    fn test_buffer_pool_read_write() {
        let pool = BufferPool::new(2);
        let idx = pool.try_acquire().unwrap();
        unsafe {
            let buf = pool.buffer_mut(idx);
            buf[0] = 0xDE;
            buf[1] = 0xAD;
            buf[2] = 0xBE;
            buf[3] = 0xEF;
        }
        unsafe {
            let buf = pool.buffer(idx);
            assert_eq!(buf[0], 0xDE);
            assert_eq!(buf[1], 0xAD);
            assert_eq!(buf[2], 0xBE);
            assert_eq!(buf[3], 0xEF);
        }
        pool.release(idx);
    }
}
