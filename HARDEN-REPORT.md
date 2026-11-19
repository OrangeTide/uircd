# HARDEN report: HARDEN ledger -- uircd

stamp: 20261119-043114
ledger-hash: b6b6
source: HARDEN.md (the ledger block)

## Top sheet

As of 2026-11-19 UTC: **0 open BLOCK**, **0 open HOLD**, 0 open opportunities, 4 fixed.
An open BLOCK breaks a contract the project states today; an open HOLD needs a reader before it is a risk or not.

### Actions


### Since the archived report

- (first report; no predecessor to compare)

## Counts

| sev | OPEN | FIXED | ACCEPTED | RETIRED | all |
|---|---|---|---|---|---|
| BLOCK | 0 | 0 | 0 | 0 | 0 |
| HOLD | 0 | 0 | 0 | 0 | 0 |
| WARN | 0 | 2 | 0 | 0 | 2 |
| NOTE | 0 | 2 | 2 | 0 | 4 |
| OPP | 0 | 0 | 0 | 0 | 0 |
| all | | | | | 6 |

## Every finding, one line

- H-001 WARN FIXED [protocol]: An operator running KLINE on a ban that matches their own connection had uircd_ban_add free the operator's client, after which cmd_kline dereferenced it (heap-use-after-free read of c->nick). Reproduced under ASan via HARDEN/harness/kline_self_uaf. (`uircd.c cmd_kline; uircd.c:305 cli_target`)
- H-002 WARN FIXED [host-net]: No per-IP connection cap and no unregistered-session deadline: one source IP could hold up to max_clients (default 1024) slots by connecting and not registering, reclaimed only by the 120s+60s ping cycle, denying service without authenticating (`uircd.c uircd_accept (per-IP cap); uircd.c uircd_tick (registration deadline)`)
- H-003 NOTE ACCEPTED [auth]: auth_verify runs scrypt only for existing account names and returns immediately for unknown ones, so response timing enumerates valid account/oper names; accepted because IRC names are not secret (WHO, membership, KILL output expose them) and a constant-cost path adds a full KDF to every bad login (`example/auth.c auth_verify; example/auth.c find_entry`)
- H-004 NOTE FIXED [protocol]: uircd_ban_add collected victims into a fixed victims[256], so a ban matching more than 256 connected clients left the rest connected until reconnect; the index was bounded so no memory unsafety, an enforcement gap (`uircd.c uircd_ban_add`)
- H-005 NOTE ACCEPTED [protocol]: parse_term accepts a field!=glob negation and GKILL/kill_match honor it, but uircd_ban_add and client_banned match with client_field_match which ignores negate, so a negated KLINE spec bans as if positive; accepted and documented rather than left silently wrong (`uircd.c client_field_match; uircd.c client_banned; uircd.c uircd_ban_add`)
- H-006 NOTE FIXED [repo]: No SECURITY.md: the repository gave no private route to report a vulnerability and no request to keep addresses out of reports (`SECURITY.md`)

## How to read this, and how to check it

- Three layers: this top sheet (judged, for a decision), the ledger below and in the source
  file (judged, one row per finding), and the sources each row names in its `back` column
  (observed: reports, harness runs, quotes). Follow `back` to the evidence, `fwd` to the plan.
- To check this report is current, regenerate it from the ledger and diff, ignoring the stamp
  and ledger-hash lines; any difference means the ledger moved and the report is stale.
- The ledger is well formed when every row has nine columns, a non-empty falsifier, and an
  id that is never reused; the generator refuses it otherwise (a FAULT).

## The ledger this report was drawn from

```harden
id	sev	state	area	claim	where	falsifier	back	fwd
H-001	WARN	FIXED	protocol	An operator running KLINE on a ban that matches their own connection had uircd_ban_add free the operator's client, after which cmd_kline dereferenced it (heap-use-after-free read of c->nick). Reproduced under ASan via HARDEN/harness/kline_self_uaf.	uircd.c cmd_kline; uircd.c:305 cli_target	HARDEN/harness/kline_self_uaf.c: ./kline_self_uaf prints "survived" after the fix and aborts with ASan heap-use-after-free before it	HARDEN/protocol.md#1	tree:round-1
H-002	WARN	FIXED	host-net	No per-IP connection cap and no unregistered-session deadline: one source IP could hold up to max_clients (default 1024) slots by connecting and not registering, reclaimed only by the 120s+60s ping cycle, denying service without authenticating	uircd.c uircd_accept (per-IP cap); uircd.c uircd_tick (registration deadline)	HARDEN/harness/conn_cap.c: opening max_per_ip+1 connections from one IP sees the last refused while another IP is accepted, and an unregistered session is dropped after reg_timeout_ms rather than the ping cycle; prints "survived"	HARDEN/host-net.md#2	tree:round-2
H-003	NOTE	ACCEPTED	auth	auth_verify runs scrypt only for existing account names and returns immediately for unknown ones, so response timing enumerates valid account/oper names; accepted because IRC names are not secret (WHO, membership, KILL output expose them) and a constant-cost path adds a full KDF to every bad login	example/auth.c auth_verify; example/auth.c find_entry	The unknown-name path runs a decoy scrypt of equal cost so known-bad and unknown names time the same	HARDEN/auth.md#1	-
H-004	NOTE	FIXED	protocol	uircd_ban_add collected victims into a fixed victims[256], so a ban matching more than 256 connected clients left the rest connected until reconnect; the index was bounded so no memory unsafety, an enforcement gap	uircd.c uircd_ban_add	Drive 300 matching clients through the API, add the ban, assert uircd_client_count drops to the non-matching count; fixed by allocating the victim list from s->n_clients	HARDEN/protocol.md#2	tree:round-1
H-005	NOTE	ACCEPTED	protocol	parse_term accepts a field!=glob negation and GKILL/kill_match honor it, but uircd_ban_add and client_banned match with client_field_match which ignores negate, so a negated KLINE spec bans as if positive; accepted and documented rather than left silently wrong	uircd.c client_field_match; uircd.c client_banned; uircd.c uircd_ban_add	Add ban nick!=keep, connect keep and other, assert other is the one removed (true only when negation is applied to bans)	HARDEN/protocol.md#3	-
H-006	NOTE	FIXED	repo	No SECURITY.md: the repository gave no private route to report a vulnerability and no request to keep addresses out of reports	SECURITY.md	SECURITY.md exists, names a private reporting route, and asks reporters not to include third-party addresses	HARDEN.md#round-log	tree:round-1
```
