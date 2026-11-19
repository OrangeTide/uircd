# HARDEN ledger -- uircd

This file is the source of truth. One finding per row in the `harden` block
below, nine tab-separated columns. The top sheet `HARDEN-REPORT.md` is generated
from this block, never the other way round. A row with no falsifier is refused;
a closed row is never deleted.

Columns: `id  sev  state  area  claim  where  falsifier  back  fwd`

Severity: BLOCK (breaks a stated contract) | HOLD (needs a human) | WARN
(genuine weakness) | NOTE (small/informational) | OPP (opportunity).
State: OPEN | FIXED | ACCEPTED | RETIRED.

```harden
id	sev	state	area	claim	where	falsifier	back	fwd
H-001	WARN	FIXED	protocol	An operator running KLINE on a ban that matches their own connection had uircd_ban_add free the operator's client, after which cmd_kline dereferenced it (heap-use-after-free read of c->nick). Reproduced under ASan via HARDEN/harness/kline_self_uaf.	uircd.c cmd_kline; uircd.c:305 cli_target	HARDEN/harness/kline_self_uaf.c: ./kline_self_uaf prints "survived" after the fix and aborts with ASan heap-use-after-free before it	HARDEN/protocol.md#1	tree:round-1
H-002	WARN	FIXED	host-net	No per-IP connection cap and no unregistered-session deadline: one source IP could hold up to max_clients (default 1024) slots by connecting and not registering, reclaimed only by the 120s+60s ping cycle, denying service without authenticating	uircd.c uircd_accept (per-IP cap); uircd.c uircd_tick (registration deadline)	HARDEN/harness/conn_cap.c: opening max_per_ip+1 connections from one IP sees the last refused while another IP is accepted, and an unregistered session is dropped after reg_timeout_ms rather than the ping cycle; prints "survived"	HARDEN/host-net.md#2	tree:round-2
H-003	NOTE	FIXED	auth	Response timing enumerated valid account/oper names: the KDF ran only for a name that existed with the needed flag and returned in ~1us for a miss (measured ~61ms vs ~0.001ms), also exposing oper-capable and offline names WHO does not. Fixed by async auth: the verdict is delivered at a fixed deadline+jitter on both the hit and miss path, so timing no longer separates them, and a miss runs no KDF	example/miniircd.c on_auth, on_auth_deadline (deadline-scheduled verdict); example/auth.c auth_lookup, auth_compute (miss runs no scrypt)	Over many trials the response-time distributions for a known-bad name and an unknown name overlap within the jitter window; true only once the verdict is tied to a deadline, not to whether the KDF ran. Structural (same deadline formula both paths); dedicated distribution harness not run	HARDEN/auth.md#1	tree:round-12
H-004	NOTE	FIXED	protocol	uircd_ban_add collected victims into a fixed victims[256], so a ban matching more than 256 connected clients left the rest connected until reconnect; the index was bounded so no memory unsafety, an enforcement gap	uircd.c uircd_ban_add	Drive 300 matching clients through the API, add the ban, assert uircd_client_count drops to the non-matching count; fixed by allocating the victim list from s->n_clients	HARDEN/protocol.md#2	tree:round-1
H-005	NOTE	FIXED	protocol	parse_term accepts a field!=glob negation and GKILL/kill_match honor it, but uircd_ban_add and client_banned matched with client_field_match which ignored negate, so a negated KLINE spec banned as if positive; now a term_matches helper applies the negation on every path	uircd.c term_matches; uircd.c client_banned; uircd.c uircd_ban_add	HARDEN/harness/ban_negation.c: add ban nick!=keep with keep and other connected, assert other is the one removed; prints "survived"	HARDEN/protocol.md#4	tree:round-2
H-006	NOTE	FIXED	repo	No SECURITY.md: the repository gave no private route to report a vulnerability and no request to keep addresses out of reports	SECURITY.md	SECURITY.md exists, names a private reporting route, and asks reporters not to include third-party addresses	HARDEN.md#round-log	tree:round-1
H-007	BLOCK	FIXED	host-net	Heap-use-after-free in the threaded host: when one fd was ready for both write and read in a single poll pass, on_io called on_writable (which could close_conn and free the conn on a write error or drained want_close) then still called on_readable on the freed conn. Reachable by any client, no auth. Found under TSan.	example/miniircd.c on_io; example/miniircd.c on_writable; example/miniircd.c close_conn	HARDEN/harness/tsan_load.c under make tsan with -t>1: TSan reports heap-use-after-free (on_readable after close_conn in on_writable) before the fix, 0 warnings after; on_io now tracks the dispatched conn and skips the read half if close_conn freed it	HARDEN/host-net.md#3	tree:round-3
H-008	NOTE	FIXED	host-net	Data race on the shutdown flag g_stop: declared volatile sig_atomic_t, written unlocked by the main thread after sigwait and read by every worker, which is async-signal safe but not a thread synchronization and races under TSan	example/miniircd.c g_stop; example/miniircd.c on_wake; example/miniircd.c worker_main	Same TSan run as H-007: TSan reports a data race on g_stop (main write vs worker read) before the fix, 0 after; g_stop is now atomic_int so direct reads and writes are atomic	HARDEN/host-net.md#3	tree:round-3
H-009	WARN	FIXED	host-net	Descriptor-exhaustion busy-loop: on accept() returning EMFILE/ENFILE/ENOBUFS/ENOMEM the handler just broke out, but libiox is level-triggered, so a connection left queued kept the listener readable and on_accept respun at 100% CPU (one core pegged) for as long as the fd table stayed full, a self-inflicted or attacker-induced livelock; the condition was also logged nowhere	example/miniircd.c on_accept	HARDEN/harness/emfile_load.c against a server run with a low RLIMIT_NOFILE: server CPU over a 3s exhaustion window is ~300 ticks (a pegged core) before the fix and ~1 after; the fix frees a reserved fd to accept-and-close the backlog (shedding load, logged rate-limited) and resumes accepting when fds free	HARDEN/host-net.md#4	tree:round-4
H-010	WARN	FIXED	host-net	Half-open TLS handshakes were unbounded: a connection is registered with the engine (uircd_accept) only after the handshake completes, so max_clients, the per-IP cap, and the registration deadline (all enforced in the engine) did not apply while handshaking. A slow or abandoned TLS handshake held an fd and an SSL object indefinitely, and one IP could hold far more than its cap, a slowloris/resource-exhaustion DoS	example/miniircd.c on_accept (TLS branch); example/miniircd.c on_tick; example/miniircd.c drive_handshake	HARDEN/harness/tls_fuzz.c slowloris mode against an ASan server with -P 2: 200 half-open handshakes from one IP are all held (server fd count rises by ~200 and never falls) before the fix; after, each worker sweeps its own conns in on_tick and closes any still handshaking past HANDSHAKE_TIMEOUT_MS (10s), so the fd count returns to baseline	HARDEN/host-net.md#6	tree:round-6
H-011	WARN	FIXED	host-net	The EMFILE reserve-shed busy-looped under a hard process-wide RLIMIT_NOFILE with multiple workers. On exhaustion each worker freed its reserved fd to accept-and-close its backlog, but N workers share one fd table, so a worker that lost the race to reopen its reserve had no slot to shed with and respun the still-readable listener. H-009 bounded the single-worker case; this is the multi-worker process-wide case, measured with all four workers pegged (process CPU ~400 ticks/sec) under sustained exhaustion	example/miniircd.c on_accept (EMFILE branch); example/miniircd.c on_relisten	HARDEN/harness/emfile_load.c against a 4-worker server under a hard ulimit (ulimit -n 96): process utime+stime over a 4s exhaustion window is ~1600 ticks (all workers pegged) before the fix and ~2 after; the fix pauses the listener with iox_fd_mod(...,0) and re-arms it after a 100ms backoff timer (on_relisten), and a client is served once descriptors free	HARDEN/host-net.md#10	tree:round-10
H-012	WARN	FIXED	auth	The scrypt KDF ran under the single global lock: on_readable held g_lock across uircd_recv -> cmd_pass/cmd_oper -> cfg.auth, so the ~61ms scrypt ran while holding g_lock and one login stalled every worker. Reachable with no secret (a bare PASS matches a shared * entry). Fixed: cmd_pass/cmd_oper return UIRCD_AUTH_PENDING, the host runs the KDF in a bounded pool with no lock held, and the verdict is applied later via uircd_auth_complete	example/miniircd.c on_auth (enqueue, no KDF under lock), kdf_main (auth_compute off-lock); uircd.c cmd_pass, cmd_oper (PENDING), uircd_auth_complete	A registered observer PING RTT stays within normal bounds while a login flood is in flight; satisfied structurally (auth_compute holds no engine lock) and confirmed by a TSan run showing the KDF pool runs off g_lock with 0 races; dedicated RTT harness not run	HARDEN/auth.md#2	tree:round-12
H-013	OPP	FIXED	auth	Asynchronous authentication: run the KDF off the global lock in a bounded pool and deliver the login verdict at a scheduled deadline with jitter, closing both the timing enumeration (H-003) and the global-lock stall (H-012) without a decoy-KDF DoS. Implemented: UIRCD_AUTH_PENDING + uircd_auth_complete in the engine (holding the client's input until the verdict), and a bounded KDF thread pool, deadline timer, and {worker,auth_id} lifetime token in the host	uircd.h (UIRCD_AUTH_PENDING, uircd_auth_complete); uircd.c cmd_pass, cmd_oper, uircd_auth_complete, feed_bytes/hold; example/miniircd.c on_auth, kdf_main, on_auth_deadline, auth_warmup; example/auth.c auth_lookup/auth_compute	HARDEN/harness/async_auth.c drives the real uircd.c through UIRCD_AUTH_PENDING/uircd_auth_complete and prints "survived": a deferred accept replays held NICK/USER to register, a deferred reject drops the client, hold-cap overflow drops it, a close mid-pending frees the hold buffer, and a deferred OPER grants on accept, all under ASan+UBSan (verified to FAIL on an engine whose uircd_auth_complete is a no-op). An unknown-name flood costs ~no server CPU (auth_compute skips scrypt on a miss); engine, host, and KDF pool also ran clean under TSan (0 races, 0 leaks) over concurrent logins including mid-auth closes	HARDEN/DESIGN-async-auth.md	tree:round-13
```

## Round log

- 2026-11-18, round 1 (no commits yet; fixes live in the round-1 working tree,
  marked `tree:round-1` in `fwd` -- the user owns commit timing). Read the full
  tree at first write: `uircd.c`, `example/*.c`, `tools/uircdpasswd.c`.
  6 rows: 2 WARN, 4 NOTE. Fixed this round: H-001 (self-KLINE UAF, reproduced
  and re-run `survived` under ASan+UBSan), H-004 (ban victim cap), H-006
  (SECURITY.md added). Accepted: H-003, H-005. Open: H-002.
  Harnesses in `HARDEN/harness/` built against the real `uircd.c` under
  ASan+UBSan. The whole example was also exercised live (plaintext and TLS,
  multi-worker) under ASan with no report.
  Not checked this round, said plainly: the vendored scrypt and libiox sources
  were taken as trusted upstream and not re-audited; no TSan run (thread safety
  was reasoned from the single-lock discipline and a live multi-worker ASan
  run); no TLS record-layer fuzzing; descriptor-exhaustion (EMFILE on accept)
  path unverified; H-002's falsifier and H-003/H-005's falsifiers were reasoned
  from the lines, not run as standalone harnesses.

- 2026-11-18, round 2 (fixes in the round-2 working tree, `tree:round-2`). Scope:
  close H-002 and H-005. Added a per-IP connection cap (`max_per_ip`, default 8)
  enforced in `uircd_accept`, and an unregistered-session registration deadline
  (`reg_timeout_ms`, default 30000) enforced in `uircd_tick`; both are config
  fields with defaults and the example exposes them as `-P`/`-R`. Fixed H-005 by
  routing ban matching through a new `term_matches` helper that applies the
  `!=` negation, so negated KLINE specs ban the set they name. New harnesses
  `HARDEN/harness/conn_cap.c` and `HARDEN/harness/ban_negation.c` built and run
  under ASan+UBSan, both print `survived`; the H-001 harness still prints
  `survived`. Added a `make check` target that builds and runs all three
  harnesses. H-002 and H-005 move to FIXED; H-003 remains ACCEPTED.
  Not checked this round: same standing gaps as round 1 (no TSan, no TLS
  record-layer fuzzing, EMFILE-on-accept path unverified); the per-IP cap is a
  per-textual-address count, not per-subnet.

- 2026-11-18, round 3 (fixes in the round-3 working tree, `tree:round-3`). Scope:
  close the round-1 thread-safety gap with a real ThreadSanitizer run. Added a
  `make tsan` build and the driver `HARDEN/harness/tsan_load.c` (hundreds of
  concurrent clients on one busy channel across 4-8 workers). Two races found and
  fixed: H-007, a heap-use-after-free in `on_io` when one fd was both writable and
  readable in a poll pass and the writable half closed the connection (BLOCK,
  reachable by any client); H-008, a benign data race on the `g_stop` shutdown
  flag. H-007 fixed by having `on_io` track the dispatched conn and skip the read
  half when `close_conn` freed it; H-008 fixed by making `g_stop` `atomic_int`.
  Rerun under TSan is clean: 0 warnings over 1600+ connections, 4 and 8 workers.
  The ASan harnesses (`make check`) and the optimized build still pass.
  Not checked this round: the TSan load run was plaintext, so the TLS handshake
  close paths were not exercised under TSan (they share the fix); no TLS
  record-layer fuzzing; EMFILE-on-accept still unverified. TSan needs ASLR off
  (`setarch -R`) on this kernel.

- 2026-11-18, round 4 (fixes in the round-4 working tree, `tree:round-4`). Scope:
  verify the round-1 "EMFILE-on-accept unverified" gap. Found H-009: on accept
  descriptor exhaustion the level-triggered loop busy-looped at 100% CPU (a
  pegged core) with the condition logged nowhere, a denial of service. Measured
  with `HARDEN/harness/emfile_load.c` against a server under `ulimit -n 64`:
  ~300 CPU ticks over a 3s exhaustion window before the fix, ~1 after. Fixed by a
  per-worker reserved fd that is freed to accept-and-close the backlog (shedding
  load, logged once per second) and reclaimed afterward; accepting resumes when
  descriptors free. Checked clean under ASan across repeated exhaustion cycles;
  `make check` and the optimized build still pass. H-009 is WARN, FIXED.
  Not checked this round: the reserve-and-shed was not stress-tested across many
  workers at a hard process-wide `RLIMIT_NOFILE`; TLS record-layer fuzzing and
  TSan coverage of the TLS handshake close paths remain open.

- 2026-11-18, round 5 (verification only, no code change). Scope: close the
  round-3 gap that the TSan run was plaintext. Built under `make tsan` with a
  self-signed cert and drove TLS load with `HARDEN/harness/tls_load.c` (four
  connection modes: clean TLS, mid-flight drop, non-TLS garbage, and immediate
  abort) across 4 and 6 workers, ~1200 connections per run. ThreadSanitizer
  reported 0 warnings; about 600 sessions per run completed the handshake and
  registered, the rest drove `drive_handshake`'s error and close paths. No new
  finding: the handshake close paths share the H-007 `on_io`/`close_conn` guard,
  now shown clean for TLS as well. The ledger block is unchanged, so the report
  is unchanged.
  Not checked this round: no TLS record-layer fuzzing (malformed/fragmented
  records, renegotiation); OpenSSL remains the trusted record-layer boundary.

- 2026-11-18, round 6 (fixes in the round-6 working tree, `tree:round-6`). Scope:
  TLS record-layer fuzzing. Drove the TLS port with `HARDEN/harness/tls_fuzz.c`
  (random bytes, truncated and oversized records, drip-fed and record-shaped
  noise, plus a slowloris mode). 1500 malformed-record connections under
  ASan+UBSan: no report, no crash, no CPU peg, legit clients still served, so
  miniircd's SSL error handling is memory-safe. Found H-010: half-open TLS
  handshakes were unbounded because a connection is registered with the engine
  only after the handshake, so max_clients, the per-IP cap, and the registration
  deadline did not apply; with `-P 2` a single IP held 200 half-open handshakes
  (server fd count +200, never reclaimed). Fixed by stamping `hs_start_ms` and
  having every worker sweep its own conns in `on_tick`, closing any still
  handshaking past `HANDSHAKE_TIMEOUT_MS` (10s); the fd count then returns to
  baseline. The sweep path was run under TSan (0 warnings) and ASan (no leak).
  `make check` and the optimized build still pass. H-010 is WARN, FIXED.
  Not checked this round: no renegotiation/fragmentation-specific fuzzing beyond
  the patterns above; `HANDSHAKE_TIMEOUT_MS` is fixed, not command-line tunable.

- 2026-11-18, round 7 (configuration work, no finding, `tree:round-7`). Not a
  finding-driven round: it records a feature change and the new parse surface it
  adds. The example host gained a gitconfig-style config file (`-f`,
  `example/miniircd.conf`), the TLS handshake deadline became tunable (`-H` and
  `[tls] handshake-timeout`, resolving round 6's "not tunable" note), and the
  library gained `uircd_config_set(cfg, key, value)`, a string-keyed setter that
  parses and validates each value (the example dogfoods it for its `[limits]`
  section). New input surface reviewed: the config file is a local,
  operator-supplied file (not a network/attacker input), but its parsers were
  still checked for memory safety. `uircd_config_set` was unit-tested under
  ASan+UBSan across every key type and all error paths (unknown key, non-numeric,
  trailing garbage, empty, unsigned overflow, NULL arguments); it uses `strtoul`
  with full validation and stores string values as pointers (no allocation), so
  it adds no ownership or free obligation. The config loader was exercised with
  malformed lines, missing brackets, and unknown and bad-valued keys: each is
  reported with file and line and refuses startup, and a config-driven run under
  ASan showed no leak at exit. `make check` and the optimized build still pass.
  No ledger row added; the report is unchanged.
  Not checked this round: no fuzzing of the config lexer with adversarial files
  (very long lines, embedded NULs, deep repetition); it is treated as trusted
  local operator input, parsed with bounded `read_file` (1 MiB cap) and
  fixed-size section buffers.

- 2026-11-18, round 8 (config lexer fuzzing, no finding, `tree:round-8`). Closed
  round 7's gap. Added a config-check mode (`-C`) that parses and validates the
  configuration then exits without binding or threading, both a useful operator
  "configtest" and the fuzz entry point. Drove `miniircd -C -f` (built ASan+UBSan,
  leak detection on) over 3000 adversarial files from
  `HARDEN/harness/conf_fuzz.c` (random bytes with embedded NULs, a huge line past
  the 1 MiB cap, hundreds of thousands of lines, unbalanced brackets, ~100 KB
  section names and key/value pairs, numeric overflow and edge values, CR/tab
  noise, a BOM, pathological separators). Result: 0 crashes, 0 hangs, 0 sanitizer
  reports, 0 leaks; malformed files are rejected with a file:line message, and
  oversized files are refused by `read_file` before the lexer runs. No finding:
  the lexer uses stack buffers and one `read_file` heap buffer with no
  length-dependent copy that can overrun. `make check` and the optimized build
  still pass. No ledger row added; the report is unchanged.
  Not checked this round: the fuzzer is a structural generator, not
  coverage-guided (no libFuzzer/AFL over `load_config` in isolation); judged
  sufficient for trusted local operator input.

- 2026-11-18, round 9 (TLS renegotiation/fragmentation, no finding,
  `tree:round-9`). Closed round 6's last gap. OpenSSL is the trusted record
  layer; the target was miniircd's own non-blocking SSL I/O. Drove the TLS port
  with `HARDEN/harness/tls_reneg.c` (4 workers, 1000 connections per run, five
  modes: TLS 1.2 client renegotiation, TLS 1.3 key update, fragmented records,
  one-byte-per-record writes, renegotiation flood). ASan+UBSan: 0 reports, no
  crash, no CPU peg, still serving. TSan: 0 warnings. A focused probe confirmed
  the server refuses renegotiation (`SSL_OP_NO_RENEGOTIATION`): a client's TLS 1.2
  `SSL_renegotiate` + `SSL_do_handshake` fails rather than completing a second
  handshake, so reneg plaintext injection and reneg-flood CPU abuse are off the
  table. No finding, no ledger row; the report is unchanged. `make check` and the
  optimized build still pass.
  Not checked this round: the record layer below the OpenSSL API (malformed,
  overlapping, or compressed records, byte-level alert flooding) was not fuzzed;
  OpenSSL stays the trusted record-layer boundary.

- 2026-11-18, round 10 (fix in the round-10 working tree, `tree:round-10`).
  Closed round 4's open caveat by stress-testing the EMFILE reserve-shed across
  many workers at a hard process-wide `RLIMIT_NOFILE`. Found H-011: with workers
  sharing one fd table, a worker that loses the race to reopen its reserved fd
  has no slot to shed with and respins the still-readable listener; measured all
  four workers pegged (~1600 process CPU ticks over a 4s window) with `ulimit -n
  96 -t 4`. Fixed by pausing the listener (`iox_fd_mod(...,0)`) and re-arming it
  after a 100 ms backoff (`on_relisten`), which bounds CPU regardless of reserve
  availability; CPU drops to ~2 ticks and accepting resumes once descriptors
  free. Checked clean under ASan and TSan at the hard limit; the single-worker
  H-009 case stays at ~1 tick. `make check` and the optimized build still pass.
  H-011 is WARN, FIXED. (The 100 ms accept backoff was made configurable
  afterward via `-b` and `[limits] accept-backoff-ms`; not a security change, so
  no new ledger row.)

- 2026-11-19, round 11 (review and design, no code change). Reviewed H-003 and
  measured the timing gap directly: ~61 ms (known name, scrypt runs) vs ~0.001 ms
  (unknown name), confirming the enumeration signal and showing it also exposes
  oper-capable names and offline account names that WHO does not. The review
  surfaced a larger defect in the same path: H-012, the ~61 ms scrypt runs under
  the global lock (`on_readable` holds `g_lock` across `uircd_recv` -> `cmd_pass`/
  `cmd_oper` -> `cfg.auth`), so one login stalls every worker and a single IP can
  hold the lock a large fraction of the time with no secret. Opened H-012 (WARN,
  OPEN). Wrote `HARDEN/DESIGN-async-auth.md`: defer the verdict to a scheduled
  deadline with jitter and run the KDF off the lock in a bounded pool, which
  closes both H-003 and H-012 without the decoy-KDF DoS that a synchronous
  constant-time path would add. Recorded the design as H-013 (OPP, OPEN) and
  pointed H-003's plan at the design note. No code changed; `make check` and the
  build are unaffected.
  Not measured cleanly this round: the cross-worker PING-latency falsifier for
  H-012 was grounded in the measured KDF time and the lock path, not run as a
  standalone harness (the ad hoc probe stalled behind the very serialization it
  demonstrates); it will be measured when the design is implemented.

- 2026-11-19, round 12 (implementation, `tree:round-12`). Built the async-auth
  design, closing H-003, H-012, and H-013. Engine (uircd.h/uircd.c): the auth
  callback gained a conn handle and a third verdict, UIRCD_AUTH_PENDING; cmd_pass
  and cmd_oper return it to park the client, the recv loop was split into
  feed_bytes with a bounded (4 KiB) hold buffer that holds further input while a
  verdict is outstanding, and uircd_auth_complete applies the deferred verdict
  and replays the held input. Host (example/miniircd.c): a fixed KDF thread pool
  (default 2) runs scrypt with no lock held; on_auth does the cheap lookup under
  g_lock, enqueues a job and arms a deadline timer (default 120ms + up to 20ms
  jitter, same formula hit or miss), and a job references its connection only by
  {worker, auth_id} so a connection that closes mid-KDF is safe. auth.c split
  into auth_lookup (cheap, may run under the lock) and auth_compute (scrypt, no
  lock, wipes the password; a miss runs no scrypt). New host config keys
  `[auth] auth-deadline-ms, auth-jitter-ms, kdf-threads`. One race surfaced and
  was fixed during the work: the vendored scrypt lazily picks its smix function
  on first call, which raced across the new pool threads (TSan); fixed host-side
  with auth_warmup(), one scrypt on the main thread before the pool starts, with
  no change to the vendored code. Verified: functional logins (good/bad/unknown/
  shared-PASS/OPER, pipelined PASS+NICK+USER and held-after-OPER replay) behave
  correctly; ASan+UBSan under live auth traffic shows 0 errors and 0 leaks; TSan
  over concurrent logins including many mid-auth closes shows 0 races. `make
  check` and the optimized build still pass. H-003 and H-012 move to FIXED, H-013
  to FIXED. This is a breaking change to the uircd auth callback contract,
  acceptable pre-1.0 and called out in uircd.h.
  Not run this round: a dedicated timing-distribution harness (the equal-deadline
  property is structural, same formula on both paths) and a standalone
  cross-worker PING-RTT harness (the off-lock property is structural and
  TSan-confirmed). Under extreme KDF saturation a valid login can fail closed
  after the deadline poll window (~1s); that is the intended bounded-CPU tradeoff.

- 2026-11-19, round 13 (verification only, `tree:round-13`). Made H-013's
  falsifier runnable, closing round 12's "not run" gap for the engine-contract
  half. Added `HARDEN/harness/async_auth.c`, which drives the real `uircd.c`
  through the deferred-auth path single-threaded (no KDF pool: this tests the
  engine contract, not the host threading) and asserts five properties: a PENDING
  verdict parks the client and holds its further input; a later accept replays
  the held NICK/USER to complete registration and set the account; a deferred
  reject under require_login drops the client through the held USER's
  try_register; input past the 4 KiB hold cap drops the client; and closing a
  client mid-pending frees it, hold buffer and all. It builds under ASan+UBSan
  and prints "survived", and was confirmed to FAIL (exit 1) against an engine
  whose `uircd_auth_complete` is a no-op, so it discriminates. Wired into
  `make check` (now four harnesses, all "survived"). No code or ledger-finding
  change; H-013's falsifier column now cites the harness and the row stays FIXED.
  Not run this round: the harness covers the engine's pending/hold/complete
  contract and lifetime, not the host's KDF-pool timing; the equal-deadline
  (H-003) and off-lock (H-012) properties remain structural and TSan-confirmed as
  recorded in round 12, without a dedicated measuring harness.
