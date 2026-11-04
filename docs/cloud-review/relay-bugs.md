# Relay bug hunt log

Running log of problems found while reviewing the relay. Each entry gives the
file and line at the time it was found, why it matters, and what was done.
Line numbers refer to the code before the fix landed.

## Pass 1: forwarding path

### 1. v2 shard leaves flow responses stuck in the socket after a burst (fixed)

- `src/datapath_v2.rs:604` (`for _ in 0..MAX_FLOW_RECV_BURST`) and
  `src/datapath_v2.rs:586` (poll timeout).
- mio registers every socket edge-triggered (`EPOLLET`). The shard read at most
  64 datagrams per readiness event and then moved on. If more than 64 were
  queued, the rest got no new event until the game server sent again, so they
  waited one extra server tick (about 16 ms at 60 Hz) or longer. Bursts like
  this are exactly what happens after a scheduling hiccup, so the relay turned
  a short stall into extra jitter on the next frames.
- The inbox had the same shape: after 1024 messages the shard went back to
  `poll` with a timeout of up to `CLEANUP_INTERVAL` (30 s). Any messages left in
  the inbox waited for the next RX wake, or were dropped as stale after 250 ms.
- Fix: the shard remembers flows whose burst budget ran out and drains them on
  the next pass, and polls with a zero timeout while such flows or inbox
  messages are waiting. Fairness between flows is kept, since each flow still
  gets at most one burst per pass.
- Also folded the per-response session lookup into one `get_mut` (was a read
  guard plus a second write lookup) and stopped an oversized response from
  abandoning the rest of the burst.
- Test: `shard_drains_a_flow_past_its_burst_budget_without_new_traffic` queues
  135 responses at once; before the fix only 128 arrived.

### 2. v2 global flow cap read counters refreshed only every 30 s (fixed)

- `src/datapath_v2.rs:759` (cap check) and `:939` (only store of the counter).
- Each shard published its flow count only during the 30 s cleanup, and not at
  all after `RemoveSession`. The `MAX_FLOWS_TOTAL` check summed those stale
  numbers, so between cleanups the cap did not apply: one source alone may open
  4096 flows per second, about 120k per cleanup interval.
- Every v2 flow is a socket, and `v3-relay.service` set `LimitNOFILE=65536`, far
  below `MAX_FLOWS_TOTAL` (262144). A flood of new flows therefore ran the
  process out of file descriptors first, which also breaks the health and
  stats listeners and resolver sockets.
- Fix: publish the shard count on every insert and session removal; clamp the
  flow cap to the soft `RLIMIT_NOFILE` minus 4096 spare descriptors; raise
  `LimitNOFILE` in the unit file to 524288 so the configured cap is reachable.
- Test: `flow_cap_stays_inside_the_fd_limit`.

### 3. Write lock and `String` allocation per data packet for the legacy user id (fixed)

- `src/datapath_v2.rs:1810,1844,1877,1888` and `src/main.rs:2304,2336,2366,2375`.
- Every TCP, UDP and fragment packet took a `sessions` write guard and, for
  non-authenticated sessions, formatted `src_ip.to_string()` into a new heap
  `String`. The write guard is taken even for authenticated sessions, where
  nothing changes, and it contends with the shard and TX threads that look up
  the same DashMap shard on every response packet.
- Fix: `note_legacy_user_ip` formats into a stack buffer, compares under a
  read guard, and only takes the write guard and touches the heap when the
  identity really changes. Applied to both datapaths.
- Test: `legacy_user_id_tracks_the_tunnel_ip_but_never_overrides_authenticated`.
