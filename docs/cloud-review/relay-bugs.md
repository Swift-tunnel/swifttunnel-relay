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
