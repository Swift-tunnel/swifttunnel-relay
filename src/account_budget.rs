//! Account-wide observation and optional enforcement across sessions/datapaths.
//!
//! Limits are per relay process, shared by every session of an authenticated
//! account. Zero means unlimited. Observe is the default. Counters measure
//! offered IP packets/bytes, including budget drops, excluding control frames.
//! Flow counts describe inbound tuples seen within 120 seconds, not kernel
//! conntrack entries. No destination or egress attribution is persisted here.
use dashmap::DashMap;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, LazyLock, Mutex,
    },
};

const FLOW_IDLE_SECONDS: u64 = 120;
const ACCOUNT_IDLE_SECONDS: u64 = 600;
static BUDGETS: LazyLock<Budgets> = LazyLock::new(|| Budgets::new(Policy::from_env()));

#[derive(Clone, Copy, Default)]
struct Policy {
    enforce: bool,
    packets: u64,
    bytes: u64,
    new_flows: u64,
}
impl Policy {
    fn from_env() -> Self {
        let number = |key| {
            std::env::var(key)
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0)
        };
        Self {
            enforce: std::env::var("RELAY_ACCOUNT_BUDGET_MODE").is_ok_and(|s| s == "enforce"),
            packets: number("RELAY_ACCOUNT_PACKETS_PER_SECOND"),
            bytes: number("RELAY_ACCOUNT_BYTES_PER_SECOND"),
            new_flows: number("RELAY_ACCOUNT_NEW_FLOWS_PER_MINUTE"),
        }
    }
}
#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct Flow {
    sid: [u8; 8],
    proto: u8,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
}
impl Flow {
    fn parse(sid: [u8; 8], p: &[u8]) -> Option<Self> {
        if p.len() < 20 || p[0] >> 4 != 4 || !matches!(p[9], 6 | 17) {
            return None;
        }
        if u16::from_be_bytes([p[6], p[7]]) & 0x1fff != 0 {
            return None;
        }
        let offset = ((p[0] & 15) as usize) * 4;
        if offset < 20 || p.len() < offset + 4 {
            return None;
        }
        Some(Self {
            sid,
            proto: p[9],
            src: Ipv4Addr::new(p[12], p[13], p[14], p[15]),
            dst: Ipv4Addr::new(p[16], p[17], p[18], p[19]),
            sport: u16::from_be_bytes([p[offset], p[offset + 1]]),
            dport: u16::from_be_bytes([p[offset + 2], p[offset + 3]]),
        })
    }
}
struct State {
    second: u64,
    minute: u64,
    counts: [u64; 4],
    totals: [u64; 4],
    peaks: [u64; 4],
    samples: Vec<[u64; 4]>,
    new_flows: u64,
    total_new_flows: u64,
    peak_flows: usize,
    breaches: u64,
    drops: u64,
    untracked: u64,
    flows: HashMap<Flow, u64>,
}
impl State {
    fn new(now: u64) -> Self {
        Self {
            second: now,
            minute: now / 60,
            counts: [0; 4],
            totals: [0; 4],
            peaks: [0; 4],
            samples: Vec::with_capacity(60),
            new_flows: 0,
            total_new_flows: 0,
            peak_flows: 0,
            breaches: 0,
            drops: 0,
            untracked: 0,
            flows: HashMap::new(),
        }
    }
}
struct Account {
    state: Mutex<State>,
    last_used: AtomicU64,
    slots: Arc<AtomicUsize>,
}
impl Drop for Account {
    fn drop(&mut self) {
        let state = self.state.get_mut().unwrap_or_else(|e| e.into_inner());
        self.slots.fetch_sub(state.flows.len(), Ordering::Relaxed);
    }
}
struct Budgets {
    policy: Policy,
    accounts: DashMap<String, Arc<Account>>,
    slots: Arc<AtomicUsize>,
    admission: Mutex<()>,
    capacity_packets: AtomicU64,
    capacity_drops: AtomicU64,
    account_limit: usize,
    flow_limit: usize,
}
impl Budgets {
    fn new(policy: Policy) -> Self {
        Self {
            policy,
            accounts: DashMap::new(),
            slots: Arc::new(AtomicUsize::new(0)),
            admission: Mutex::new(()),
            capacity_packets: AtomicU64::new(0),
            capacity_drops: AtomicU64::new(0),
            account_limit: super::MAX_SESSIONS_TOTAL,
            flow_limit: super::MAX_FLOWS_TOTAL,
        }
    }
    fn account(&self, user: &str, now: u64) -> Option<Arc<Account>> {
        if let Some(account) = self.accounts.get(user) {
            return Some(Arc::clone(account.value()));
        }
        // Serialize admission, not packets. A len/insert pair alone exceeds the
        // cap when several authenticated accounts first send concurrently.
        let _admission = self.admission.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(account) = self.accounts.get(user) {
            return Some(Arc::clone(account.value()));
        }
        if self.accounts.len() >= self.account_limit {
            return None;
        }
        Some(Arc::clone(
            self.accounts
                .entry(user.to_string())
                .or_insert_with(|| {
                    Arc::new(Account {
                        state: Mutex::new(State::new(now)),
                        last_used: AtomicU64::new(now),
                        slots: Arc::clone(&self.slots),
                    })
                })
                .value(),
        ))
    }
    fn event(&self, user: &str, out: bool, bytes: usize, flow: Option<Flow>, now: u64) -> bool {
        let Some(account) = self.account(user, now) else {
            self.capacity_packets.fetch_add(1, Ordering::Relaxed);
            if self.policy.enforce {
                self.capacity_drops.fetch_add(1, Ordering::Relaxed);
            }
            return !self.policy.enforce;
        };
        account.last_used.fetch_max(now, Ordering::Relaxed);
        let mut state = account.state.lock().unwrap_or_else(|e| e.into_inner());
        // Threads can acquire this lock in a different order from their clock
        // reads. An older timestamp must never reopen a consumed window.
        let now = now.max(state.second);
        if state.second != now {
            let sample = state.counts;
            if state.samples.len() == 60 {
                state.samples.remove(0);
            }
            state.samples.push(sample);
            state.counts = [0; 4];
            state.second = now;
        }
        if state.minute != now / 60 {
            state.new_flows = 0;
            state.minute = now / 60;
        }
        if let Some(key) = flow {
            if state
                .flows
                .get(&key)
                .is_some_and(|seen| now.saturating_sub(*seen) >= FLOW_IDLE_SECONDS)
            {
                state.flows.remove(&key);
                self.slots.fetch_sub(1, Ordering::Relaxed);
            }
        }
        let offset = if out { 2 } else { 0 };
        for (index, amount) in [(offset, 1), (offset + 1, bytes as u64)] {
            state.counts[index] = state.counts[index].saturating_add(amount);
            state.totals[index] = state.totals[index].saturating_add(amount);
            state.peaks[index] = state.peaks[index].max(state.counts[index]);
        }
        let new_flow = flow.is_some_and(|key| !state.flows.contains_key(&key));
        let exceeded = (self.policy.packets > 0
            && state.counts[0].saturating_add(state.counts[2]) > self.policy.packets)
            || (self.policy.bytes > 0
                && state.counts[1].saturating_add(state.counts[3]) > self.policy.bytes)
            || (new_flow && self.policy.new_flows > 0 && state.new_flows >= self.policy.new_flows);
        if exceeded {
            state.breaches += 1;
            if self.policy.enforce {
                state.drops += 1;
                return false;
            }
        }
        if let Some(key) = flow {
            if new_flow {
                if self
                    .slots
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                        (n < self.flow_limit).then_some(n + 1)
                    })
                    .is_err()
                {
                    state.untracked += 1;
                    if self.policy.enforce {
                        state.drops += 1;
                    }
                    return !self.policy.enforce;
                }
                state.new_flows += 1;
                state.total_new_flows += 1;
            }
            state.flows.insert(key, now);
            state.peak_flows = state.peak_flows.max(state.flows.len());
        }
        true
    }
    fn maintain(&self, now: u64) {
        // Run outside receive/TX loops. Never evict an account while event()
        // holds an Arc, or an enforced allowance could split across two states.
        self.accounts.retain(|_, account| {
            now.saturating_sub(account.last_used.load(Ordering::Relaxed)) < ACCOUNT_IDLE_SECONDS
                || Arc::strong_count(account) > 1
        });
        for account in self.accounts.iter() {
            let mut s = account.state.lock().unwrap_or_else(|e| e.into_inner());
            let before = s.flows.len();
            s.flows
                .retain(|_, seen| now.saturating_sub(*seen) < FLOW_IDLE_SECONDS);
            self.slots
                .fetch_sub(before - s.flows.len(), Ordering::Relaxed);
        }
    }
    fn snapshot(&self) -> Value {
        let now = super::mono_timestamp_ms() / 1000;
        let rows: Vec<_> = self
            .accounts
            .iter()
            .map(|entry| {
                let s = entry.state.lock().unwrap_or_else(|e| e.into_inner());
                let p95: Vec<_> = (0..4)
                    .map(|i| {
                        let mut values: Vec<_> = s.samples.iter().map(|v| v[i]).collect();
                        values.push(s.counts[i]);
                        values.sort_unstable();
                        values[(values.len() * 95).div_ceil(100).saturating_sub(1)]
                    })
                    .collect();
                let recent_flows = s
                    .flows
                    .values()
                    .filter(|seen| now.saturating_sub(**seen) < FLOW_IDLE_SECONDS)
                    .count();
                json!({
                    "account": entry.key(),
                    "totals": s.totals,
                    "peak_per_second": s.peaks,
                    "p95_recent_active_seconds": p95,
                    "new_flows_this_minute": if s.minute == now / 60 { s.new_flows } else { 0 },
                    "total_new_flows": s.total_new_flows,
                    "flows_seen_within_120s": recent_flows,
                    "peak_tracked_flows": s.peak_flows,
                    "budget_breaches": s.breaches,
                    "dropped_packets": s.drops,
                    "untracked_flow_packets": s.untracked,
                })
            })
            .collect();
        json!({
            "server_id": std::env::var("RELAY_SERVER_ID").unwrap_or_default(),
            "mode": if self.policy.enforce { "enforce" } else { "observe" },
            "counter_order": ["packets_in", "bytes_in", "packets_out", "bytes_out"],
            "limits": {
                "packets_per_second": self.policy.packets,
                "bytes_per_second": self.policy.bytes,
                "new_flows_per_minute": self.policy.new_flows,
            },
            "untracked_account_packets": self.capacity_packets.load(Ordering::Relaxed),
            "capacity_dropped_packets": self.capacity_drops.load(Ordering::Relaxed),
            "accounts": rows,
        })
    }
}
pub(crate) fn allow(
    sessions: &DashMap<[u8; 8], super::SessionEntry>,
    sid: [u8; 8],
    out: bool,
    packet: &[u8],
) -> bool {
    let Some(session) = sessions.get(&sid) else {
        return false;
    };
    if session.auth_state != super::SessionAuthState::Authenticated {
        return true;
    }
    BUDGETS.event(
        &session.user_id,
        out,
        packet.len(),
        if out { None } else { Flow::parse(sid, packet) },
        super::mono_timestamp_ms() / 1000,
    )
}
pub(crate) fn snapshot() -> String {
    BUDGETS.snapshot().to_string()
}
pub(crate) fn start_maintenance() {
    std::thread::Builder::new()
        .name("account-budget-prune".into())
        .spawn(|| loop {
            std::thread::sleep(std::time::Duration::from_secs(30));
            BUDGETS.maintain(super::mono_timestamp_ms() / 1000);
        })
        .expect("start account budget maintenance");
}

#[cfg(test)]
mod tests {
    use super::*;
    fn flow(sid: u64) -> Flow {
        Flow {
            sid: sid.to_be_bytes(),
            proto: 17,
            src: Ipv4Addr::LOCALHOST,
            dst: Ipv4Addr::new(1, 1, 1, 1),
            sport: 100,
            dport: 200,
        }
    }
    #[test]
    fn sessions_and_directions_share_packet_and_byte_limits() {
        let budget = Budgets::new(Policy {
            enforce: true,
            packets: 2,
            bytes: 100,
            new_flows: 0,
        });
        assert!(budget.event("one", false, 40, Some(flow(1)), 1));
        assert!(budget.event("one", true, 40, None, 1));
        assert!(!budget.event("one", false, 1, Some(flow(2)), 1));
        assert!(budget.event("other", false, 40, Some(flow(2)), 1));
        assert!(!budget.event("one", false, 101, None, 2));
        assert!(budget.event("one", false, 40, None, 3));
    }
    #[test]
    fn flow_churn_is_account_wide_and_observe_never_enforces_configured_limits() {
        let budget = Budgets::new(Policy {
            enforce: true,
            new_flows: 1,
            ..Policy::default()
        });
        assert!(budget.event("one", false, 40, Some(flow(1)), 1));
        assert!(!budget.event("one", false, 40, Some(flow(2)), 1));
        assert!(budget.event("one", false, 40, Some(flow(2)), 61));
        let observe = Budgets::new(Policy {
            packets: 1,
            bytes: 1,
            new_flows: 1,
            ..Policy::default()
        });
        for sid in 1..10 {
            assert!(observe.event("one", false, 100, Some(flow(sid)), 1));
        }
        assert_eq!(observe.snapshot()["accounts"][0]["budget_breaches"], 9);
        assert_eq!(observe.snapshot()["accounts"][0]["dropped_packets"], 0);
    }
    #[test]
    fn stale_flows_release_the_shared_tracking_capacity() {
        let budget = Budgets::new(Policy::default());
        budget.event("one", false, 40, Some(flow(1)), 1);
        assert_eq!(budget.slots.load(Ordering::Relaxed), 1);
        budget.event("one", false, 40, Some(flow(2)), 122);
        budget.maintain(122);
        assert_eq!(budget.slots.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn delayed_threads_cannot_reopen_an_old_window() {
        let budget = Budgets::new(Policy {
            enforce: true,
            packets: 1,
            ..Policy::default()
        });
        assert!(budget.event("one", false, 1, None, 61));
        assert!(!budget.event("one", false, 1, None, 60));
        assert!(!budget.event("one", false, 1, None, 61));
    }

    #[test]
    fn capacity_preserves_tracked_accounts_and_recovers_after_idle() {
        for enforce in [false, true] {
            let mut budget = Budgets::new(Policy {
                enforce,
                ..Policy::default()
            });
            budget.account_limit = 1;
            budget.flow_limit = 1;
            assert!(budget.event("one", false, 40, Some(flow(1)), 1));
            assert_eq!(budget.event("two", false, 40, None, 1), !enforce);
            assert_eq!(budget.event("one", false, 40, Some(flow(2)), 1), !enforce);
            assert!(budget.event("one", false, 40, Some(flow(1)), 1));
            assert_eq!(budget.accounts.len(), 1);
            assert_eq!(budget.slots.load(Ordering::Relaxed), 1);
            budget.maintain(602);
            assert_eq!(budget.slots.load(Ordering::Relaxed), 0);
            assert!(budget.event("two", false, 40, Some(flow(2)), 602));
        }
    }

    #[test]
    fn concurrent_accounts_cannot_exceed_capacity() {
        let mut budget = Budgets::new(Policy::default());
        budget.account_limit = 2;
        std::thread::scope(|scope| {
            for i in 0..16 {
                let budget = &budget;
                scope.spawn(move || {
                    budget.event(&i.to_string(), false, 1, None, 1);
                });
            }
        });
        assert_eq!(budget.accounts.len(), 2);
    }

    /// Run explicitly in release mode. This isolates the added policy work;
    /// it does not simulate sockets, TUN, queueing, Linux, or production load.
    #[test]
    #[ignore = "manual release-mode packet policy microbenchmark"]
    fn packet_policy_microbenchmark() {
        use std::{hint::black_box, time::Instant};
        let sessions = DashMap::new();
        for sid in 1u64..=4 {
            sessions.insert(
                sid.to_be_bytes(),
                super::super::SessionEntry {
                    user_id: "benchmark-owner".into(),
                    auth_state: super::super::SessionAuthState::Authenticated,
                    lease_expires_at_unix: Some(u64::MAX),
                    client_addr: "127.0.0.1:40000".parse().unwrap(),
                    created_at_unix: 1,
                    last_activity: Instant::now(),
                    last_activity_unix: 1,
                },
            );
        }
        let mut packet = [0u8; 100];
        packet[0] = 0x45;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
        for threads in [1, 4] {
            for enabled in [false, true] {
                let budget = Budgets::new(Policy::default());
                let barrier = std::sync::Barrier::new(threads);
                std::thread::scope(|scope| {
                    let handles: Vec<_> = (1..=threads)
                        .map(|worker| {
                            let (sessions, budget, barrier, packet) =
                                (&sessions, &budget, &barrier, &packet);
                            scope.spawn(move || {
                                let sid = (worker as u64).to_be_bytes();
                                budget.event(
                                    "benchmark-owner",
                                    false,
                                    100,
                                    Flow::parse(sid, packet),
                                    1,
                                );
                                let mut samples = Vec::new();
                                barrier.wait();
                                let started = Instant::now();
                                for n in 0..500_000 {
                                    let measured = (n % 1024 == 0).then(Instant::now);
                                    // The return path already looks up the current owner.
                                    black_box(super::super::forwarding_addr(
                                        sessions,
                                        black_box(sid),
                                        true,
                                        1,
                                    ));
                                    if enabled {
                                        let session = sessions.get(&sid).unwrap();
                                        black_box(budget.event(
                                            &session.user_id,
                                            false,
                                            packet.len(),
                                            Flow::parse(sid, packet),
                                            super::super::mono_timestamp_ms() / 1000,
                                        ));
                                    }
                                    if let Some(start) = measured {
                                        samples.push(start.elapsed().as_nanos());
                                    }
                                }
                                (started.elapsed().as_nanos() / 500_000, samples)
                            })
                        })
                        .collect();
                    let mut samples = Vec::new();
                    let mut per_worker = Vec::new();
                    for handle in handles {
                        let (mean, mut values) = handle.join().unwrap();
                        per_worker.push(mean);
                        samples.append(&mut values);
                    }
                    samples.sort_unstable();
                    println!("threads={threads} enabled={enabled} mean_ns_per_call_by_worker={per_worker:?} sampled_p50_ns={} p95_ns={} p99_ns={}", samples[samples.len()/2], samples[samples.len()*95/100], samples[samples.len()*99/100]);
                });
            }
        }
    }
}
