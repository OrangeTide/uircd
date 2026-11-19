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
