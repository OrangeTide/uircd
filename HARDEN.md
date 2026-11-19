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
H-003	NOTE	ACCEPTED	auth	auth_verify runs scrypt only for existing account names and returns immediately for unknown ones, so response timing enumerates valid account/oper names; accepted because IRC names are not secret (WHO, membership, KILL output expose them) and a constant-cost path adds a full KDF to every bad login	example/auth.c auth_verify; example/auth.c find_entry	The unknown-name path runs a decoy scrypt of equal cost so known-bad and unknown names time the same	HARDEN/auth.md#1	-
H-004	NOTE	FIXED	protocol	uircd_ban_add collected victims into a fixed victims[256], so a ban matching more than 256 connected clients left the rest connected until reconnect; the index was bounded so no memory unsafety, an enforcement gap	uircd.c uircd_ban_add	Drive 300 matching clients through the API, add the ban, assert uircd_client_count drops to the non-matching count; fixed by allocating the victim list from s->n_clients	HARDEN/protocol.md#2	tree:round-1
H-005	NOTE	FIXED	protocol	parse_term accepts a field!=glob negation and GKILL/kill_match honor it, but uircd_ban_add and client_banned matched with client_field_match which ignored negate, so a negated KLINE spec banned as if positive; now a term_matches helper applies the negation on every path	uircd.c term_matches; uircd.c client_banned; uircd.c uircd_ban_add	HARDEN/harness/ban_negation.c: add ban nick!=keep with keep and other connected, assert other is the one removed; prints "survived"	HARDEN/protocol.md#4	tree:round-2
H-006	NOTE	FIXED	repo	No SECURITY.md: the repository gave no private route to report a vulnerability and no request to keep addresses out of reports	SECURITY.md	SECURITY.md exists, names a private reporting route, and asks reporters not to include third-party addresses	HARDEN.md#round-log	tree:round-1
H-007	BLOCK	FIXED	host-net	Heap-use-after-free in the threaded host: when one fd was ready for both write and read in a single poll pass, on_io called on_writable (which could close_conn and free the conn on a write error or drained want_close) then still called on_readable on the freed conn. Reachable by any client, no auth. Found under TSan.	example/miniircd.c on_io; example/miniircd.c on_writable; example/miniircd.c close_conn	HARDEN/harness/tsan_load.c under make tsan with -t>1: TSan reports heap-use-after-free (on_readable after close_conn in on_writable) before the fix, 0 warnings after; on_io now tracks the dispatched conn and skips the read half if close_conn freed it	HARDEN/host-net.md#3	tree:round-3
H-008	NOTE	FIXED	host-net	Data race on the shutdown flag g_stop: declared volatile sig_atomic_t, written unlocked by the main thread after sigwait and read by every worker, which is async-signal safe but not a thread synchronization and races under TSan	example/miniircd.c g_stop; example/miniircd.c on_wake; example/miniircd.c worker_main	Same TSan run as H-007: TSan reports a data race on g_stop (main write vs worker read) before the fix, 0 after; g_stop is now atomic_int so direct reads and writes are atomic	HARDEN/host-net.md#3	tree:round-3
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
