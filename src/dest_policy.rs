//! Which networks the relay forwards client traffic to.
//!
//! SwiftTunnel carries Roblox and nothing else, yet every public address used
//! to be a valid destination, so a modified client could aim this relay at
//! anyone, a player's home connection included. This narrows forwarding to
//! Roblox's own networks, plus CloudFront for TCP, which fronts the part of
//! Roblox's control plane that Route Assist carries over HTTPS.
//!
//! Observe is the default. Nothing is dropped: traffic outside the list is
//! counted instead, so real sessions show what enforcing would break before
//! anything is enforced. A list that catches gameplay fails invisibly and the
//! lag gets blamed on us, so that evidence comes first.
//!
//! Environment:
//! - `RELAY_DEST_POLICY_MODE`: `off`, `observe` (default) or `enforce`.
//!   Anything unrecognised means observe, so a typo never drops traffic.
//! - `RELAY_DEST_ALLOWLIST_FILE`: the list, as written by
//!   `update-dest-allowlist.sh`, read once at startup. Enforce requires it:
//!   the built-in list has no CloudFront ranges, and enforcing that would cut
//!   Route Assist.
//! - `RELAY_DEST_TCP_PORTS`: TCP ports allowed on listed networks, comma
//!   separated. Default `80,443`.
//!
//! What it keeps: counters, plus a sampled and capped tally of unlisted
//! destinations by /24 network, so observe mode can say where the unlisted
//! traffic went. In memory only, with no account or session attached, served
//! on the token-protected local stats API. Nothing is written to disk.
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    hash::Hash,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicU64, Ordering},
        LazyLock, Mutex,
    },
};

/// Every IPv4 prefix Roblox's two networks announced on 2026-09-10, per
/// RIPEstat. AS22697 also announces 45 /24s inside 128.116.0.0/17, which that
/// prefix already covers.
///
/// The client's own list in `geolocation.rs` also carries 209.206.40.0/21 and
/// 103.142.220.0/23. Neither network announces them, so they are left out, and
/// observe mode will show if anything real still goes there.
const BUILT_IN_ROBLOX: &[&str] = &[
    // AS22697
    "128.116.0.0/17",
    "103.140.28.0/23",
    "141.193.3.0/24",
    "205.201.62.0/24",
    // AS11281
    "204.13.168.0/24",
    "204.13.169.0/24",
    "204.13.170.0/24",
    "204.13.171.0/24",
    "204.13.172.0/24",
    "204.13.173.0/24",
    "204.13.174.0/24",
    "204.9.184.0/24",
    "23.173.192.0/24",
];

const DEFAULT_TCP_PORTS: &[u16] = &[80, 443];

/// Broader than this is almost certainly a typo, and not a small one:
/// 128.0.0.0/1 would open half the internet.
const MIN_PREFIX_LEN: u32 = 8;

/// One unlisted packet in this many goes into the tally. The counters see every
/// packet; the tally only has to rank networks.
const SAMPLE_EVERY: u64 = 16;
/// Distinct networks, and separately ports, the tally holds before it stops
/// adding new ones.
const SAMPLE_CAP: usize = 256;
/// How many of each the snapshot reports, busiest first.
const SNAPSHOT_TOP: usize = 32;

static POLICY: LazyLock<DestPolicy> = LazyLock::new(DestPolicy::from_env);

/// Whether a client packet may be forwarded. Always true outside enforce mode.
///
/// Anything that is not TCP is judged by the UDP list. `dst_port` is `None`
/// for fragments, which carry no port, and then only the network decides.
pub(crate) fn permits(protocol: u8, dst: Ipv4Addr, dst_port: Option<u16>) -> bool {
    POLICY.permits(protocol, dst, dst_port)
}

/// JSON for the local stats API.
pub(crate) fn snapshot() -> String {
    POLICY.snapshot().to_string()
}

/// One line for the startup log. Calling it also loads the policy, so a bad
/// allowlist file is reported at startup rather than on the first packet.
pub(crate) fn describe() -> String {
    POLICY.describe()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Off,
    Observe,
    Enforce,
}

impl Mode {
    fn parse(raw: Option<&str>) -> Self {
        match raw
            .map(|value| value.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("off") => Mode::Off,
            Some("enforce") => Mode::Enforce,
            _ => Mode::Observe,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Observe => "observe",
            Mode::Enforce => "enforce",
        }
    }
}

/// An IPv4 prefix, as its first address and mask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Net {
    base: u32,
    mask: u32,
}

impl Net {
    fn parse(cidr: &str) -> Option<Self> {
        let (addr, len) = cidr.trim().split_once('/')?;
        let addr: Ipv4Addr = addr.parse().ok()?;
        let len: u32 = len.parse().ok()?;
        if !(MIN_PREFIX_LEN..=32).contains(&len) {
            return None;
        }
        let mask = u32::MAX << (32 - len);
        Some(Self {
            base: u32::from(addr) & mask,
            mask,
        })
    }

    fn contains(self, ip: u32) -> bool {
        (ip & self.mask) == self.base
    }

    fn covers(self, other: Net) -> bool {
        other.mask >= self.mask && self.contains(other.base)
    }
}

/// Disjoint prefixes, sorted by first address.
#[derive(Debug, Default)]
struct NetSet(Vec<Net>);

impl NetSet {
    fn new(mut nets: Vec<Net>) -> Self {
        // A prefix sorts ahead of everything inside it (same or lower first
        // address, shorter mask), so one pass drops whatever the last kept
        // prefix already covers and leaves the rest disjoint.
        nets.sort_unstable_by_key(|net| (net.base, net.mask));
        let mut kept: Vec<Net> = Vec::with_capacity(nets.len());
        for net in nets {
            if kept.last().is_some_and(|last| last.covers(net)) {
                continue;
            }
            kept.push(net);
        }
        Self(kept)
    }

    /// With disjoint prefixes the only candidate is the last one starting at
    /// or before the address.
    fn contains(&self, ip: Ipv4Addr) -> bool {
        let ip = u32::from(ip);
        let after = self.0.partition_point(|net| net.base <= ip);
        after > 0 && self.0[after - 1].contains(ip)
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Debug, Default)]
struct Allowlist {
    udp: Vec<Net>,
    tcp: Vec<Net>,
    invalid_lines: usize,
}

/// One prefix per line. A bare prefix applies to UDP and TCP; `udp` or `tcp`
/// in front limits it to that protocol. `#` starts a comment.
fn parse_allowlist(text: &str) -> Allowlist {
    let mut list = Allowlist::default();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        let entry = match words.as_slice() {
            [cidr] => Net::parse(cidr).map(|net| (true, true, net)),
            ["udp", cidr] => Net::parse(cidr).map(|net| (true, false, net)),
            ["tcp", cidr] => Net::parse(cidr).map(|net| (false, true, net)),
            _ => None,
        };
        match entry {
            Some((udp, tcp, net)) => {
                if udp {
                    list.udp.push(net);
                }
                if tcp {
                    list.tcp.push(net);
                }
            }
            None => list.invalid_lines += 1,
        }
    }
    list
}

fn parse_ports(raw: Option<&str>) -> Vec<u16> {
    let ports: Vec<u16> = raw
        .unwrap_or_default()
        .split(',')
        .filter_map(|port| port.trim().parse::<u16>().ok())
        .filter(|port| *port != 0)
        .collect();
    if ports.is_empty() {
        DEFAULT_TCP_PORTS.to_vec()
    } else {
        ports
    }
}

#[derive(Default)]
struct Counters {
    udp_unlisted: AtomicU64,
    tcp_unlisted_network: AtomicU64,
    tcp_unlisted_port: AtomicU64,
    dropped: AtomicU64,
}

#[derive(Default)]
struct Tally {
    /// (protocol, first address of the /24) to sampled packets.
    networks: HashMap<(u8, u32), u64>,
    /// Unlisted TCP ports on listed networks, to sampled packets.
    tcp_ports: HashMap<u16, u64>,
    /// Samples turned away because the tally was full.
    overflow: u64,
}

#[derive(Clone, Copy)]
enum Unlisted {
    Network,
    Port,
}

struct DestPolicy {
    mode: Mode,
    /// Why enforce was asked for and not honoured, if it was.
    enforce_refused: Option<String>,
    /// Problems loading the allowlist, for the startup log and the snapshot.
    notes: Vec<String>,
    source: String,
    udp: NetSet,
    tcp: NetSet,
    tcp_ports: Vec<u16>,
    sample_every: u64,
    counters: Counters,
    tick: AtomicU64,
    tally: Mutex<Tally>,
}

impl DestPolicy {
    fn from_env() -> Self {
        let mode = Mode::parse(std::env::var("RELAY_DEST_POLICY_MODE").ok().as_deref());
        let file = std::env::var("RELAY_DEST_ALLOWLIST_FILE")
            .ok()
            .map(|path| path.trim().to_string())
            .filter(|path| !path.is_empty())
            .map(|path| {
                let contents = std::fs::read_to_string(&path);
                (path, contents)
            });
        let tcp_ports = parse_ports(std::env::var("RELAY_DEST_TCP_PORTS").ok().as_deref());
        let policy = Self::build(mode, file, tcp_ports);
        for note in &policy.notes {
            log::warn!("Destination policy: {}", note);
        }
        if let Some(reason) = &policy.enforce_refused {
            log::error!(
                "Destination policy: observing instead of enforcing: {}",
                reason
            );
        }
        policy
    }

    fn build(
        requested: Mode,
        file: Option<(String, std::io::Result<String>)>,
        tcp_ports: Vec<u16>,
    ) -> Self {
        let mut notes = Vec::new();
        let mut loaded = None;
        if let Some((path, contents)) = file {
            match contents {
                Err(error) => notes.push(format!(
                    "cannot read {path}: {error}; using the built-in list"
                )),
                Ok(text) => {
                    let list = parse_allowlist(&text);
                    if list.invalid_lines > 0 {
                        notes.push(format!(
                            "{path}: skipped {} unreadable lines",
                            list.invalid_lines
                        ));
                    }
                    if list.udp.is_empty() || list.tcp.is_empty() {
                        notes.push(format!(
                            "{path} needs prefixes for both UDP and TCP; using the built-in list"
                        ));
                    } else {
                        loaded = Some((path, list));
                    }
                }
            }
        }

        let mut mode = requested;
        let mut enforce_refused = None;
        if requested == Mode::Enforce && loaded.is_none() {
            mode = Mode::Observe;
            enforce_refused = Some(
                "enforce needs a readable RELAY_DEST_ALLOWLIST_FILE covering UDP and TCP. \
                 The built-in list has no CloudFront ranges, so enforcing it would cut \
                 Route Assist"
                    .to_string(),
            );
        }

        let (source, udp, tcp) = match loaded {
            Some((path, list)) => (path, list.udp, list.tcp),
            None => {
                let roblox: Vec<Net> = BUILT_IN_ROBLOX
                    .iter()
                    .filter_map(|cidr| Net::parse(cidr))
                    .collect();
                ("built-in".to_string(), roblox.clone(), roblox)
            }
        };

        Self {
            mode,
            enforce_refused,
            notes,
            source,
            udp: NetSet::new(udp),
            tcp: NetSet::new(tcp),
            tcp_ports,
            sample_every: SAMPLE_EVERY,
            counters: Counters::default(),
            tick: AtomicU64::new(0),
            tally: Mutex::new(Tally::default()),
        }
    }

    fn permits(&self, protocol: u8, dst: Ipv4Addr, dst_port: Option<u16>) -> bool {
        if self.mode == Mode::Off {
            return true;
        }
        let unlisted = if protocol == 6 {
            if !self.tcp.contains(dst) {
                self.counters
                    .tcp_unlisted_network
                    .fetch_add(1, Ordering::Relaxed);
                Unlisted::Network
            } else if dst_port.is_some_and(|port| !self.tcp_ports.contains(&port)) {
                self.counters
                    .tcp_unlisted_port
                    .fetch_add(1, Ordering::Relaxed);
                Unlisted::Port
            } else {
                return true;
            }
        } else if self.udp.contains(dst) {
            return true;
        } else {
            self.counters.udp_unlisted.fetch_add(1, Ordering::Relaxed);
            Unlisted::Network
        };

        self.tally(protocol, dst, dst_port, unlisted);
        if self.mode == Mode::Enforce {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    fn tally(&self, protocol: u8, dst: Ipv4Addr, dst_port: Option<u16>, unlisted: Unlisted) {
        if self.tick.fetch_add(1, Ordering::Relaxed) % self.sample_every != 0 {
            return;
        }
        let mut guard = self
            .tally
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let tally = &mut *guard;
        match unlisted {
            Unlisted::Network => {
                let network = u32::from(dst) & 0xFFFF_FF00;
                bump(
                    &mut tally.networks,
                    (protocol, network),
                    &mut tally.overflow,
                );
            }
            Unlisted::Port => {
                if let Some(port) = dst_port {
                    bump(&mut tally.tcp_ports, port, &mut tally.overflow);
                }
            }
        }
    }

    fn snapshot(&self) -> Value {
        let tally = self
            .tally
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut networks: Vec<(u64, u8, u32)> = tally
            .networks
            .iter()
            .map(|(&(protocol, network), &samples)| (samples, protocol, network))
            .collect();
        networks.sort_unstable_by(|a, b| b.cmp(a));
        let networks: Vec<Value> = networks
            .into_iter()
            .take(SNAPSHOT_TOP)
            .map(|(samples, protocol, network)| {
                json!({
                    "protocol": protocol_name(protocol),
                    "network": format!("{}/24", Ipv4Addr::from(network)),
                    "samples": samples,
                })
            })
            .collect();
        let mut ports: Vec<(u64, u16)> = tally
            .tcp_ports
            .iter()
            .map(|(&port, &samples)| (samples, port))
            .collect();
        ports.sort_unstable_by(|a, b| b.cmp(a));
        let ports: Vec<Value> = ports
            .into_iter()
            .take(SNAPSHOT_TOP)
            .map(|(samples, port)| json!({ "port": port, "samples": samples }))
            .collect();

        let counters = &self.counters;
        json!({
            "mode": self.mode.as_str(),
            "enforce_refused": self.enforce_refused,
            "allowlist": {
                "source": self.source,
                "udp_networks": self.udp.len(),
                "tcp_networks": self.tcp.len(),
                "tcp_ports": self.tcp_ports,
                "notes": self.notes,
            },
            "unlisted_packets": {
                "udp": counters.udp_unlisted.load(Ordering::Relaxed),
                "tcp_network": counters.tcp_unlisted_network.load(Ordering::Relaxed),
                "tcp_port": counters.tcp_unlisted_port.load(Ordering::Relaxed),
            },
            "dropped_packets": counters.dropped.load(Ordering::Relaxed),
            "unlisted_sample": {
                "sample_every": self.sample_every,
                "networks": networks,
                "tcp_ports": ports,
                "overflow": tally.overflow,
            },
        })
    }

    fn describe(&self) -> String {
        format!(
            "Destination policy: {} ({} list, {} UDP and {} TCP networks, TCP ports {:?}; env RELAY_DEST_POLICY_MODE)",
            self.mode.as_str(),
            self.source,
            self.udp.len(),
            self.tcp.len(),
            self.tcp_ports,
        )
    }
}

fn bump<K: Hash + Eq>(map: &mut HashMap<K, u64>, key: K, overflow: &mut u64) {
    if let Some(count) = map.get_mut(&key) {
        *count += 1;
    } else if map.len() < SAMPLE_CAP {
        map.insert(key, 1);
    } else {
        *overflow += 1;
    }
}

fn protocol_name(protocol: u8) -> Value {
    match protocol {
        6 => json!("tcp"),
        17 => json!("udp"),
        other => json!(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Roblox's main range for both protocols, and a CloudFront range for TCP.
    const FILE: &str = "128.116.0.0/17\ntcp 13.32.0.0/15\n";

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn policy(mode: Mode, file: &str) -> DestPolicy {
        let mut policy = DestPolicy::build(
            mode,
            Some(("test".to_string(), Ok(file.to_string()))),
            DEFAULT_TCP_PORTS.to_vec(),
        );
        policy.sample_every = 1;
        policy
    }

    #[test]
    fn prefixes_parse_and_nonsense_does_not() {
        let net = Net::parse("128.116.0.0/17").unwrap();
        assert_eq!(net.mask.count_ones(), 17);
        // Host bits are cleared rather than rejected.
        assert_eq!(Net::parse("128.116.9.9/17"), Some(net));
        for bad in [
            "128.116.0.0",
            "128.116.0.0/33",
            "abc/24",
            "1.2.3/24",
            "10.0.0.0/7",
            "0.0.0.0/0",
            "",
        ] {
            assert!(Net::parse(bad).is_none(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn every_built_in_prefix_parses() {
        for cidr in BUILT_IN_ROBLOX {
            assert!(Net::parse(cidr).is_some(), "{cidr}");
        }
    }

    #[test]
    fn covered_prefixes_collapse_and_edges_are_exact() {
        let set = NetSet::new(
            [
                "128.116.0.0/24",
                "128.116.0.0/17",
                "128.116.95.0/24",
                "204.13.168.0/24",
            ]
            .iter()
            .filter_map(|cidr| Net::parse(cidr))
            .collect(),
        );
        assert_eq!(set.len(), 2);
        assert!(set.contains(ip(128, 116, 0, 0)));
        assert!(set.contains(ip(128, 116, 127, 255)));
        assert!(!set.contains(ip(128, 116, 128, 0)));
        assert!(!set.contains(ip(128, 115, 255, 255)));
        assert!(set.contains(ip(204, 13, 168, 77)));
        assert!(!set.contains(ip(204, 13, 169, 0)));
        assert!(!NetSet::default().contains(ip(128, 116, 0, 1)));
    }

    #[test]
    fn built_in_list_covers_roblox_and_nothing_else() {
        let policy = DestPolicy::build(Mode::Observe, None, DEFAULT_TCP_PORTS.to_vec());
        assert_eq!(policy.source, "built-in");
        assert!(policy.udp.contains(ip(128, 116, 50, 10)));
        assert!(policy.udp.contains(ip(204, 13, 170, 5)));
        assert!(policy.udp.contains(ip(103, 140, 29, 1)));
        assert!(!policy.udp.contains(ip(1, 1, 1, 1)));
        // The client still lists this, but nobody announces it.
        assert!(!policy.udp.contains(ip(209, 206, 40, 1)));
        assert!(policy.describe().contains("observe (built-in list"));
    }

    #[test]
    fn observe_counts_unlisted_traffic_and_forwards_all_of_it() {
        let policy = policy(Mode::Observe, FILE);
        assert!(policy.permits(17, ip(1, 1, 1, 1), Some(5000)));
        assert!(policy.permits(6, ip(128, 116, 1, 1), Some(8080)));
        assert!(policy.permits(17, ip(128, 116, 1, 1), Some(55000)));

        let snapshot = policy.snapshot();
        assert_eq!(snapshot["mode"], "observe");
        assert_eq!(snapshot["unlisted_packets"]["udp"], 1);
        assert_eq!(snapshot["unlisted_packets"]["tcp_port"], 1);
        assert_eq!(snapshot["dropped_packets"], 0);
        assert_eq!(
            snapshot["unlisted_sample"]["networks"][0]["network"],
            "1.1.1.0/24"
        );
        assert_eq!(snapshot["unlisted_sample"]["tcp_ports"][0]["port"], 8080);
    }

    #[test]
    fn enforce_drops_what_observe_would_have_counted() {
        let policy = policy(Mode::Enforce, FILE);
        assert_eq!(policy.mode, Mode::Enforce);
        // Gameplay and the web front doors pass.
        assert!(policy.permits(17, ip(128, 116, 50, 10), Some(55000)));
        assert!(policy.permits(6, ip(128, 116, 50, 10), Some(443)));
        assert!(policy.permits(6, ip(13, 32, 1, 1), Some(443)));
        // A home connection does not, by either protocol.
        assert!(!policy.permits(17, ip(1, 1, 1, 1), Some(5000)));
        assert!(!policy.permits(6, ip(1, 1, 1, 1), Some(443)));
        // CloudFront is listed for TCP only.
        assert!(!policy.permits(17, ip(13, 32, 1, 1), Some(443)));
        // A listed network, but not a web port.
        assert!(!policy.permits(6, ip(128, 116, 50, 10), Some(22)));
        // Fragments carry no port, so the network decides.
        assert!(policy.permits(17, ip(128, 116, 50, 10), None));
        assert!(!policy.permits(17, ip(1, 1, 1, 1), None));
        assert_eq!(policy.snapshot()["dropped_packets"], 5);
    }

    #[test]
    fn off_forwards_everything_and_records_nothing() {
        let policy = policy(Mode::Off, FILE);
        assert!(policy.permits(17, ip(1, 1, 1, 1), Some(5000)));
        assert_eq!(policy.snapshot()["unlisted_packets"]["udp"], 0);
    }

    #[test]
    fn enforce_without_a_usable_file_observes_instead() {
        // The built-in list has no CloudFront, so enforcing it would cut Route
        // Assist. Asking for enforce without a file must not do that.
        let no_file = DestPolicy::build(Mode::Enforce, None, DEFAULT_TCP_PORTS.to_vec());
        assert_eq!(no_file.mode, Mode::Observe);
        assert!(no_file.enforce_refused.is_some());
        assert!(no_file.permits(17, ip(1, 1, 1, 1), Some(5000)));

        let unreadable = DestPolicy::build(
            Mode::Enforce,
            Some((
                "missing".to_string(),
                Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
            )),
            DEFAULT_TCP_PORTS.to_vec(),
        );
        assert_eq!(unreadable.mode, Mode::Observe);
        assert_eq!(unreadable.source, "built-in");

        // UDP prefixes alone would leave TCP with nothing and drop all of it.
        let one_sided = DestPolicy::build(
            Mode::Enforce,
            Some((
                "udp-only".to_string(),
                Ok("udp 128.116.0.0/17\n".to_string()),
            )),
            DEFAULT_TCP_PORTS.to_vec(),
        );
        assert_eq!(one_sided.mode, Mode::Observe);
        assert_eq!(one_sided.notes.len(), 1);
    }

    #[test]
    fn allowlist_lines_choose_their_protocol() {
        let list = parse_allowlist(
            "# header\n128.116.0.0/17\nudp 103.140.28.0/23\ntcp 13.32.0.0/15  # CloudFront\n\nicmp 1.2.3.0/24\nnot a prefix\n",
        );
        assert_eq!(list.udp.len(), 2);
        assert_eq!(list.tcp.len(), 2);
        assert_eq!(list.invalid_lines, 2);
    }

    #[test]
    fn modes_and_ports_parse_conservatively() {
        assert_eq!(Mode::parse(None), Mode::Observe);
        assert_eq!(Mode::parse(Some(" Enforce ")), Mode::Enforce);
        assert_eq!(Mode::parse(Some("off")), Mode::Off);
        // A typo must never start dropping traffic.
        assert_eq!(Mode::parse(Some("enforced")), Mode::Observe);

        assert_eq!(parse_ports(None), vec![80, 443]);
        assert_eq!(parse_ports(Some("443, 8443")), vec![443, 8443]);
        assert_eq!(parse_ports(Some("nonsense,0")), vec![80, 443]);
    }

    #[test]
    fn the_unlisted_sample_stays_bounded() {
        let policy = policy(Mode::Observe, FILE);
        let extra = 50u32;
        for n in 0..(SAMPLE_CAP as u32 + extra) {
            let dst = Ipv4Addr::from(u32::from(ip(1, 0, 0, 0)) + (n << 8));
            policy.permits(17, dst, Some(5000));
        }
        let snapshot = policy.snapshot();
        assert_eq!(
            snapshot["unlisted_packets"]["udp"],
            SAMPLE_CAP as u64 + u64::from(extra)
        );
        assert_eq!(snapshot["unlisted_sample"]["overflow"], u64::from(extra));
        assert_eq!(
            snapshot["unlisted_sample"]["networks"]
                .as_array()
                .unwrap()
                .len(),
            SNAPSHOT_TOP
        );
    }

    /// Per-packet cost of the check every client packet now passes through.
    ///
    /// Shaped like production: the built-in Roblox list for UDP, and 224 TCP
    /// networks, the count a generated allowlist file loads today. Run with
    /// `cargo test --release permits_microbenchmark -- --ignored --nocapture`.
    /// It measures the lookup alone, not sockets, queueing or real load.
    #[test]
    #[ignore = "manual release-mode microbenchmark"]
    fn permits_microbenchmark() {
        use std::hint::black_box;
        use std::time::Instant;

        let mut file = String::from("128.116.0.0/17\n103.140.28.0/23\n141.193.3.0/24\n");
        for n in 0..221u32 {
            let base = Ipv4Addr::from(u32::from(ip(13, 0, 0, 0)) + (n << 8));
            file.push_str(&format!("tcp {base}/24\n"));
        }
        // The unit-test helper samples every unlisted packet. Measure the
        // production sampling interval here instead.
        let observe = DestPolicy::build(
            Mode::Observe,
            Some(("benchmark".to_string(), Ok(file))),
            DEFAULT_TCP_PORTS.to_vec(),
        );
        let iterations = 10_000_000u32;
        let cases: [(&str, u8, Ipv4Addr, u16); 4] = [
            ("udp listed (gameplay)", 17, ip(128, 116, 50, 10), 55000),
            ("tcp listed, web port", 6, ip(13, 0, 200, 9), 443),
            ("udp unlisted, observe", 17, ip(1, 1, 1, 1), 5000),
            ("tcp unlisted, observe", 6, ip(1, 1, 1, 1), 443),
        ];
        for (label, protocol, dst, port) in cases {
            let started = Instant::now();
            for _ in 0..iterations {
                black_box(observe.permits(
                    black_box(protocol),
                    black_box(dst),
                    black_box(Some(port)),
                ));
            }
            let per = started.elapsed().as_nanos() as f64 / f64::from(iterations);
            println!("{label:<24} {per:>6.2} ns per packet");
        }
    }
}
