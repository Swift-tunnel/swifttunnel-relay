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

### 7. setup-tun.sh let tunnel clients reach services on the relay host (fixed)

- `setup-tun.sh:113` (forbidden destination rules live in FORWARD only).
- A tunnelled packet addressed to any address the host owns (its public IP,
  `10.200.0.1`, a private interface) is delivered locally, so it goes through
  INPUT and the FORWARD drop list never sees it. `is_forbidden_dst` does not
  know the host's own public address either. Any client could therefore talk
  to every service on the relay from a `10.200.x.x` source: SSH, monitoring
  agents, anything bound to a private interface or allowed by a `10.0.0.0/8`
  source rule. The relay needs nothing from the TUN delivered locally.
- Fix: `INPUT -i swifttun0 -j DROP` (tagged `swifttunnel-tun-input`, removed
  and re-added on every run so it stays first and is never duplicated).

### 8. TCP MSS was clamped in one direction only (fixed)

- `setup-tun.sh:85`.
- Only the client's SYN was clamped, which limits what servers send. The
  server's SYN-ACK reached the client unclamped, so a client sends segments
  sized for a 1500-byte path; a full one plus the relay's 36 bytes of framing
  does not fit in one datagram from the client, and uploads (POST bodies,
  asset uploads over Route Assist) go out fragmented or are lost where
  fragments are dropped.
- Fix: also clamp SYN-ACKs leaving toward `swifttun0` to the same 1340.
- Test for 7 and 8: `tests/setup_tun.sh` runs the script against a fake
  `iptables` that keeps its rules in a file and a temporary `/etc`
  (`SWIFTTUNNEL_ETC_DIR`, defaults to `/etc`). It checks both rules, that a
  rerun changes nothing, and that limit modes replace each other. It fails
  against the previous script.

### 9. Resolve frames could start unbounded lookups from the RX thread (fixed)

- `src/datapath_v2.rs:1688` and `src/main.rs:2216` (0xA6 handlers).
- Every resolve frame from an authenticated session spawned a task doing up
  to 16 sequential `getaddrinfo` calls, with no limit on how many, and the v2
  receive thread logged a line at info for each one first. One client sending
  resolve frames at the per-source packet limit (50k a second) could pile up
  tasks without bound, hold every blocking thread the runtime has (512) on
  slow lookups, and keep the forwarding thread busy writing log lines.
- Fix: `ResolveLimiter` admits at most 8 requests a second per session
  (hashed into 4096 fixed buckets), 256 a second relay-wide, and 64 in flight.
  The permit travels with the lookup task and frees its slot when it ends.
  Refused requests count as `rate_limit`; the frame format is unchanged.
- Test: `resolve_requests_are_bounded_per_session_globally_and_in_flight`.

### 10. One account could exhaust budget flow tracking for every account (fixed)

- `src/account_budget.rs:221` (new-flow slot reservation).
- Flow tuples are tracked in one relay-wide table capped at `MAX_FLOWS_TOTAL`.
  When it is full, every new flow is "untracked", and enforce mode drops
  untracked flows. Nothing limited one account's share, and every new
  5-tuple counts, so one account sweeping fresh source ports (a TCP SYN
  sweep through the TUN, at a few thousand packets a second) filled the
  table within a minute or two and then blocked new connections for every
  other player on the relay until its own entries aged out 120 s later.
- Fix: an account may hold at most 8192 tracked tuples; beyond that its own
  new flows go untracked (dropped in enforce mode, counted in observe mode)
  without touching the shared table.
- Test: `one_account_cannot_take_every_flow_slot_from_the_others`.

### 11. A lost auth ack turned the client's retry into a "replayed ticket" (fixed)

- `src/main.rs:905` (`verify_relay_ticket_once`), used by both receive loops.
- The `AUTH_ACK_OK` is one UDP datagram. When it is lost, the client sends
  the same hello again with the same `jti`, and the replay cache answered
  `AUTH_ACK_REPLAY` although that ticket had just authenticated the session.
  To the client that is a refused ticket, so it has to fetch a new one (a
  round trip to the web backend) or gives up, on exactly the lossy links
  where the relay matters most.
- Fix: `verify_auth_hello` acks `OK` and changes nothing when a seen ticket
  is a retransmission of the hello that already authenticated this session:
  same endpoint, same owner, same lease expiry, lease still current. Any
  other reuse is still `AUTH_ACK_REPLAY`, so a captured hello sent from
  somewhere else gains nothing. Wire format and ack codes are unchanged.
- Test: `tests/auth_retransmit.rs` (both datapaths); fails before the fix.

### 12. The public health endpoint spawned a thread per idle connection (fixed)

- `src/main.rs:2988` (`run_health_http_server_blocking`), public on 8081.
- Each accepted connection got its own OS thread, which then waited up to
  5 s for a request, with no limit on how many. The relay runs as root, so
  `LimitNPROC` does not apply. Anyone could open idle connections faster than
  they time out: measured, 300 idle connections took the relay from 15 to 315
  threads. Each also holds a descriptor from the 4096 kept spare for
  everything that is not a flow socket, and thousands of threads compete with
  the RX, shard and TX threads for CPU.
- Fix: at most 32 health clients at once (extra connections are closed at
  accept), and a 2 s timeout instead of 5 s.
- Test: `tests/health.rs` (Linux), fails before the fix.

### 13. The speedtest server was an open reflection amplifier (fixed)

- `relay-speedtest.py:672` (`MSG_DOWNLOAD_REQUEST` in `run_server`), run on
  public UDP 9000 by `relay-speedtest.service` and opened in the README's ufw
  steps.
- A download request is one small datagram naming a packet count (up to
  2^32) and payload size (up to 65535), and the server sent that much to the
  datagram's source address, which nothing checked. Anyone could spoof a
  victim's address: measured against the old server, one 24-byte request for
  2000 packets put 2.8 MB on the wire toward the claimed sender, and the
  request format allows billions of packets. That is abuse traffic from our
  relay IPs, the kind of reputation that already costs real gameplay. The
  single-threaded server was also stuck for as long as the send took.
  Upload state was a dict keyed by source with no bound, so spoofed
  `UPLOAD_PREP`s grew it without end.
- Fix: the HELLO reply now carries a 16-byte cookie (HMAC of the source
  address and a one-minute window, per-process secret) and a download request
  must echo it from the same address. HELLO requests are padded to the size
  of the reply, so the reply amplifies nothing; an unpadded legacy HELLO is
  still echoed but earns no cookie. Downloads are clamped to
  `--max-download-packets` (default 20000) and 1400-byte payloads, gaps to
  1 s, and upload state to 1024 entries. This is an operator tool, not part
  of the apps, but its client and server must now be updated together
  (README updated).
- Test: `tests/relay_speedtest_server.py` (spoofed and cross-address requests
  get nothing, clamping holds, HELLO reply is no larger than the request).

### 14. Clients could relay traffic to the relay host itself (fixed)

- `src/main.rs:770` (`is_forbidden_dst`).
- The forbidden ranges cover private, loopback and reserved space, but the
  relay's own public address is an ordinary public address, so a UDP flow (or
  a TUN packet) to it was relayed to the relay host. That reached whatever
  listens there: the speedtest server, the relay's own port (a session
  inside the relay whose source is the relay itself, outside every per-source
  limit), and any service that trusts traffic from the host's own address.
  Issue 7 closes this for the TUN in the firewall; this closes it for the UDP
  datapath, where the traffic comes from the relay's own sockets and never
  crosses `swifttun0`.
- Fix: the host's IPv4 addresses (from `getifaddrs`) are forbidden
  destinations. They are read at startup and refreshed by both cleanup tasks
  every 30 s, and kept in a fixed array of atomics so the per-packet check
  takes no lock.
- Test: `the_relay_host_is_never_a_destination`.
