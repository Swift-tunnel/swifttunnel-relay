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

## Pass 2: auth, ICMP errors, TUN, setup, resolve, budgets

### 4. Forged auth hellos could buy unbounded signature checks on the RX thread (fixed)

- `src/main.rs:403` (`PendingAuthLimiter`), used at `src/datapath_v2.rs:1344`
  and `src/main.rs:1955`.
- Hellos are verified before anything else, on the one receive thread that
  forwards every player's traffic. The only limit was 256 per second per
  hash bucket, and a spoofed source address lands in a different bucket for
  free, so 4096 buckets admitted about a million verifications a second.
  Rejecting a junk token with a 64-byte signature measured about 56 us in a
  release build, so roughly 18k forged hellos a second (about 2 MB/s, no
  account needed) would have kept the RX thread fully busy and stalled
  forwarding for everybody on the relay.
- Fix: `allow_verification` adds a relay-wide ceiling of 2048 signature checks
  per second on top of the per-bucket limit (about 11% of one core at worst).
  Hellos over the ceiling are dropped silently and counted as `rate_limit`;
  clients already retry an unanswered hello. Ticket format and ack codes are
  unchanged.
- Test: `spoofed_hellos_cannot_buy_unbounded_signature_checks`.

### 5. An ICMP error cost the next client packet, or stranded queued responses (fixed)

- `src/datapath_v2.rs:604` (`drain_flow_responses` error arm), `:848` (shard
  send), `src/main.rs:2619` and `:2706` (v1 flow handler send and recv).
- Flow sockets are connected UDP sockets. When an ICMP port unreachable,
  protocol unreachable, administratively prohibited or fragmentation needed
  message comes back for one datagram, Linux parks the error on the socket and
  reports it once, on the next call, and that call does nothing else. Checked
  on this kernel: the send after a port unreachable failed with
  `ECONNREFUSED` and its datagram never left; a recv returned the error ahead
  of two responses that were already queued.
- v2 send: the error was logged at debug and the client packet was lost.
- v2 receive: the drain returned on the error. The socket is edge-triggered,
  so the queued responses waited for the game server's next datagram (one
  tick or more of added delay, or forever if it was the last one).
- v1: `ECONNREFUSED` on recv was not treated as transient, so each one slept
  the flow task 10 ms (holding up client packets queued for that flow) and
  five in a row tore the flow down. Sends lost the packet as in v2.
- Fix: `is_deferred_icmp_error` names the one-shot errnos. Sends retry once
  after one, and the drain keeps reading (still bounded by the burst budget).
  Persistent errors are unchanged, so a broken socket cannot make the drain spin.
- Tests: `flow_send_survives_an_icmp_error_from_an_earlier_datagram`,
  `flow_drain_reads_responses_queued_behind_an_icmp_error` (both fail without
  the fix), `only_one_shot_icmp_errors_are_retried`.

### 6. One session in 65536 got the TUN device's own address and no TCP (fixed)

- `src/tcp_tun.rs:530` (`assign_session_ip`).
- Sessions get `10.200.<sid[0]>.<sid[1]>`, skipping only `.0.0` and
  `.255.255`. A session id starting `00 01` got `10.200.0.1`, which is the
  address the relay puts on `swifttun0`. Packets written to the TUN with a
  local address as their source are martians and the kernel drops them, so
  that session's TCP (Route Assist, HTTPS) silently never connected, and so did
  its UDP when `RELAY_TUN_UDP=true`. Session ids are random, so this hit about
  one session in 65536; on a busy relay that is a few players a day.
- Fix: the interface address is skipped like the other reserved pairs and the
  next byte pair is used.
- Test: `test_assign_session_ip_never_hands_out_the_tun_interface_address`.
