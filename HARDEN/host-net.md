# HARDEN surface: network host, threading, and TLS (example/miniircd.c)

The example binary owns the sockets, the worker threads, the per-connection
output buffers, and the OpenSSL plumbing. The uircd engine is serialized behind
`g_lock`; this surface is about what happens outside that lock and at the edges
the engine never sees.

## Round 1 (2026-11-18)

### Observed

- One worker thread per core; each creates its own listener with `SO_REUSEPORT`
  (`make_listener`) so the kernel load-balances accept. Each worker runs its own
  libiox loop.
- `g_lock` guards every `uircd_*` call and every access to a connection's output
  buffer. Cross-worker output (a broadcast whose targets live on other workers)
  is appended under the lock in `on_out`, and the owning worker is woken through
  a non-blocking self-pipe (`wake`). A connection is only ever freed by its
  owning worker in `close_conn`, always under `g_lock`. `on_drop` sets
  `c->cli = NULL` because uircd frees the client right after the callback, so no
  later `close_conn` double-frees it through `uircd_closed`.
- `buf_append` caps a connection's queued output at `MAX_OUTBUF` (1 MiB); on
  overflow it returns -1 and `on_out` sets `want_close`, so a slow or stuck
  reader cannot grow memory without bound.
- TLS: `tls_init` sets a TLS 1.2 floor, disables renegotiation, prefers server
  ciphers, and verifies the key matches the cert. The handshake is driven
  non-blocking in `drive_handshake`; the client is only registered with the
  engine after the handshake completes.
- `daemonize()` is called before any thread is created, so the double-fork does
  not race the worker threads.
- Termination signals are blocked in all threads and handled by the main thread
  via `sigwait`; shutdown sets `g_stop`, wakes every worker (each stops its own
  loop), joins, then frees.
- `accept` runs in a loop until EAGAIN. New `conn` structs are `calloc`ed before
  `uircd_accept`, which enforces `max_clients` (default 1024) and refuses beyond
  it; a refused connection is flushed and closed, so descriptor use is bounded by
  `max_clients`.

### Judged

#### 1. No per-IP connection cap and no unregistered-session timeout  [H-002]

- **Claim:** nothing limits how many connections one source IP may hold, and an
  unregistered connection (TCP/TLS established, no NICK/USER) is only reclaimed
  by the ping cycle (`ping_interval` 120 s then `ping_timeout` 60 s). A single
  IP can therefore occupy up to `max_clients` (default 1024) slots for roughly
  three minutes each, or indefinitely if it answers PINGs, denying service to
  everyone else without authenticating.
- **Lines:** example/miniircd.c `on_accept` (no per-IP accounting); uircd.c
  `uircd_tick` (ping is the only reaper); uircd.c `uircd_accept` (global cap
  only).
- **Scenario:** open 1024 TCP connections from one host, send nothing; the
  server refuses all other clients until the ping timeout fires.
- **Falsifier:** a per-IP limit of N exists and a script opening N+1 connections
  from one address sees the N+1th refused, and an unregistered connection is
  dropped after a short registration deadline (seconds, not the ping cycle).
  Reasoned from the lines, not run this round.
- **Fix shape:** a per-IP counter keyed on `peer_ip` enforced in `on_accept` or
  in `uircd_accept`, plus a per-client registration deadline checked in
  `uircd_tick`. **OPEN.** Left to a human: the right limits depend on the
  deployment, so this is recorded rather than guessed.

### Not checked this round

- No fuzzing of the TLS record layer (OpenSSL is trusted as the boundary).
- No test of behaviour under `accept` returning EMFILE (descriptor exhaustion);
  the path logs nothing and continues, which is plausibly correct but unverified.
- Thread-safety was reasoned from the locking discipline and exercised by a live
  multi-worker run under ASan, not proven with a race detector (TSan).

## Round 2 (2026-11-18)

### 1. Per-IP cap and registration deadline added  [H-002]

- **What changed:** the engine gained two configurable limits, both resolved in
  `uircd_new` with defaults.
  - `max_per_ip` (default 8): `uircd_accept` counts existing clients whose stored
    `host` equals the new `peer_ip`; at the cap it emits
    `ERROR :Too many connections from your host`, calls `drop`, and returns NULL,
    exactly as the server-full path does. A connection from any other IP is
    unaffected.
  - `reg_timeout_ms` (default 30000): each client's connect time is stamped on
    the first `uircd_tick` that sees it (`connect_ms`). An unregistered client
    past the deadline is sent `ERROR :Registration timeout` and quit inside
    `uircd_tick`, with the same swap-remove bookkeeping (`i--; continue`) the
    ping-timeout path uses. The deadline check guards `now_ms > connect_ms` so a
    `now_ms == 0` first tick cannot underflow.
- **Lines:** uircd.c `uircd_accept` (per-IP loop); uircd.c `uircd_tick`
  (deadline); uircd.h `struct uircd_config` (`max_per_ip`, `reg_timeout_ms`).
  example/miniircd.c exposes both as `-P` and `-R`.
- **Falsifier:** `HARDEN/harness/conn_cap.c`, built and run under ASan+UBSan this
  round. Opens `max_per_ip` connections from one IP and asserts the next is
  refused while a second IP is accepted, then ticks past `reg_timeout_ms` (and
  short of `ping_interval_ms`) and asserts the unregistered sessions are gone.
  Prints `survived`. Discriminates: without the cap the extra accept returns
  non-NULL; without the deadline the count holds until the ping cycle.
- **State:** **FIXED.** The defaults are deliberately conservative; an operator
  raises them with `-P`/`-R` when a trusted NAT or proxy sits in front.

### Not checked this round

- The per-IP match is an exact string compare on the printable `peer_ip`. A host
  reached through both IPv4 and IPv6, or behind a shared NAT, is counted per
  textual address, which is the intended granularity but not a per-subnet cap.

## Round 3 (2026-11-18) -- ThreadSanitizer run

Round 1 left the thread-safety claim reasoned from the single-lock discipline
and one live ASan run, not proven. This round built the host under
ThreadSanitizer (`make tsan`) and drove it with `HARDEN/harness/tsan_load.c`:
hundreds of concurrent connections across 4 to 8 workers joining one busy
channel. Two races surfaced; both are fixed, and a rerun is clean (0 warnings
over 1600+ connections).

### 1. Use-after-free in on_io when a fd is both writable and readable  [H-007]

- **Claim:** `on_io` is the single per-fd watcher. It called `on_writable` then
  `on_readable` for the event mask. When a fd carried both `IOX_WRITE` and
  `IOX_READ` in one poll pass and `on_writable` closed the connection (a write
  error, or `want_close` with the buffer now drained), `close_conn` freed the
  `conn`; `on_io` then passed the freed pointer to `on_readable`. TSan caught the
  read in `on_readable` (miniircd.c:301) against the `free` in `close_conn`
  reached from `on_writable`, both on the same worker thread in one
  `iox_loop_poll` pass. Reachable by any client; an abrupt close while the server
  is still flushing fan-out output is the natural trigger.
- **Lines:** example/miniircd.c `on_io`; `on_writable` (its `close_conn` paths);
  `close_conn`.
- **Falsifier:** `HARDEN/harness/tsan_load.c` driving a `make tsan` server with
  more than one worker. Before the fix TSan reports `heap-use-after-free` with
  `on_readable` reading what `on_writable` -> `close_conn` freed; after, 0
  warnings. Run and reproduced this round.
- **Fix shape:** the worker records the conn `on_io` is dispatching (`io_cur`),
  and `close_conn` sets `io_cur_freed` when it frees that conn. `on_io` skips the
  read half when the flag is set. This covers every close path inside
  `on_writable`, including `drive_handshake`. **Fixed this round.**

### 2. Data race on the shutdown flag g_stop  [H-008]

- **Claim:** `g_stop` was `volatile sig_atomic_t`, written unlocked by the main
  thread after `sigwait` and read by every worker (`on_wake`, `worker_main`).
  `volatile sig_atomic_t` is async-signal safe but is not a thread
  synchronization; TSan reports the main write against a worker read. Benign in
  practice (a late read just delays a worker's exit by one loop pass) but a real
  race.
- **Lines:** example/miniircd.c `g_stop` declaration; write in `main`; reads in
  `on_wake` and `worker_main`.
- **Falsifier:** the same TSan run reports a data race on global `g_stop`; 0
  after the fix.
- **Fix shape:** declare `g_stop` as `atomic_int`. Direct reads and writes then
  compile to atomic operations, with no other change. `g_stop` is never touched
  from an async signal handler (signals are handled via `sigwait` in `main`), so
  dropping `sig_atomic_t` is safe. **Fixed this round.**

### Not checked this round

- No TSan coverage of the TLS handshake path (the load run was plaintext); the
  handshake close paths share the `on_io`/`close_conn` fix but were not exercised
  under TSan.
- TSan requires ASLR off on this kernel (`setarch -R`); the run is otherwise
  unmodified.

## Round 4 (2026-11-18) -- descriptor exhaustion

Round 1 noted the `accept` EMFILE path as "plausibly correct but unverified."
This round verified it and found it wrong.

### 1. Busy-loop on accept descriptor exhaustion  [H-009]

- **Claim:** on `accept()` returning `EMFILE`/`ENFILE` (and the allocation
  errors `ENOBUFS`/`ENOMEM`) the handler fell through to `break`, taking no other
  action. libiox is level-triggered (poll), so a connection still queued on the
  listener keeps it readable; the loop re-enters `on_accept`, `accept` fails the
  same way, breaks, and the loop polls again. With the fd table full and a
  connection pending this spins at 100% CPU (one core pegged) until a descriptor
  frees. An attacker who exhausts the process fd table (open connections, bounded
  by `max_clients` and the per-IP cap but also by `RLIMIT_NOFILE`, which may be
  lower) turns the server's own accept loop into a denial of service. The
  condition was logged nowhere.
- **Lines:** example/miniircd.c `on_accept` (the former bare `break`).
- **Falsifier:** `HARDEN/harness/emfile_load.c` against a server run under a low
  `RLIMIT_NOFILE` (`ulimit -n 64`). Sampling the server's `utime+stime` over a
  3-second exhaustion window: ~300 ticks (a pegged core) before the fix, ~1
  after. Reproduced this round, both directions.
- **Fix shape:** each worker reserves a spare fd (`/dev/null`). On exhaustion it
  closes the spare and uses the freed slot to `accept` and immediately `close`
  the backlog, shedding those connections (the client gets a prompt close rather
  than a hang) and clearing the listener's readiness so the loop stops spinning,
  then reopens the spare. The event is logged once per second. When descriptors
  free up, `on_accept` reopens the reserve and normal accepting resumes (verified
  by a client registering after the load released). **Fixed this round.** Checked
  clean under ASan (no fd or memory leak across repeated exhaustion cycles).

### Not checked this round

- The reserve-and-shed is per worker; under a process-wide `ENFILE` several
  workers contend for freed slots, which is still forward progress but not
  coordinated. Not stress-tested across many workers at a hard `RLIMIT_NOFILE`.
