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
H-002	WARN	OPEN	host-net	No per-IP connection cap and no unregistered-session deadline: one source IP can hold up to max_clients (default 1024) slots by connecting and not registering, reclaimed only by the 120s+60s ping cycle, denying service without authenticating	example/miniircd.c on_accept; uircd.c uircd_tick; uircd.c uircd_accept	A per-IP limit N exists: opening N+1 connections from one address sees the N+1th refused, and an unregistered connection is dropped after a seconds-scale registration deadline rather than the ping cycle	HARDEN/host-net.md#1	-
H-003	NOTE	ACCEPTED	auth	auth_verify runs scrypt only for existing account names and returns immediately for unknown ones, so response timing enumerates valid account/oper names; accepted because IRC names are not secret (WHO, membership, KILL output expose them) and a constant-cost path adds a full KDF to every bad login	example/auth.c auth_verify; example/auth.c find_entry	The unknown-name path runs a decoy scrypt of equal cost so known-bad and unknown names time the same	HARDEN/auth.md#1	-
H-004	NOTE	FIXED	protocol	uircd_ban_add collected victims into a fixed victims[256], so a ban matching more than 256 connected clients left the rest connected until reconnect; the index was bounded so no memory unsafety, an enforcement gap	uircd.c uircd_ban_add	Drive 300 matching clients through the API, add the ban, assert uircd_client_count drops to the non-matching count; fixed by allocating the victim list from s->n_clients	HARDEN/protocol.md#2	tree:round-1
H-005	NOTE	ACCEPTED	protocol	parse_term accepts a field!=glob negation and GKILL/kill_match honor it, but uircd_ban_add and client_banned match with client_field_match which ignores negate, so a negated KLINE spec bans as if positive; accepted and documented rather than left silently wrong	uircd.c client_field_match; uircd.c client_banned; uircd.c uircd_ban_add	Add ban nick!=keep, connect keep and other, assert other is the one removed (true only when negation is applied to bans)	HARDEN/protocol.md#3	-
H-006	NOTE	FIXED	repo	No SECURITY.md: the repository gave no private route to report a vulnerability and no request to keep addresses out of reports	SECURITY.md	SECURITY.md exists, names a private reporting route, and asks reporters not to include third-party addresses	HARDEN.md#round-log	tree:round-1
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
