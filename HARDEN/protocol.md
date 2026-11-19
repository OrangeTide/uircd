# HARDEN surface: IRC protocol engine (uircd.c)

The network-peer surface. Every byte here originates from an untrusted client
socket and is parsed by `uircd_recv` -> `dispatch` -> the command handlers.
The engine does no I/O; it is driven by the host, so "the attacker" is any
connected client, and for the oper-gated commands, an authenticated operator.

## Round 1 (2026-11-18)

### Observed

- `uircd_recv` (uircd.c) buffers bytes into `c->inbuf[INBUF_MAX]` (512) and
  only stores while `inlen < INBUF_MAX`; an over-long line sets `skipping` and
  is discarded to the next `\n`. Each completed line is copied into a stack
  `char line[INBUF_MAX + 1]` with `llen <= 512`, NUL-terminated. No unbounded
  copy.
- `parse_line` tokenizes in place, skips an optional client-sent `:prefix`,
  caps params at `MAXPARAMS` (16), treats a leading `:` as the trailing arg.
- `sendf` formats with `vsnprintf(buf, 510, ...)` into `char buf[560]`, clamps
  the result to 509, then appends CRLF. `numeric` formats a `tail[512]` then
  hands it to `sendf` with a `%s`. No caller passes attacker bytes as the
  format string; user data always arrives through `%s`.
- Flood accounting: `c->flood_count` increments per line and is checked
  against `flood_lines` (default 20) before dispatch; the window resets in
  `uircd_tick`. On exceed the client is sent `ERROR :Excess flood` and
  destroyed, and `uircd_recv` returns `UIRCD_ERR`, stopping the batch.
- `valid_nick` / `valid_chan` restrict the character set and length before a
  nick or channel name is stored.
- Admin handlers (`cmd_kill`, `cmd_kline`, `cmd_gkill`) can destroy clients,
  including the caller. `cmd_kill` returns `self` and `cmd_gkill` pre-detects a
  self-match and returns `self_dead`, so neither touches `c` after it may be
  freed. `cmd_kline` did **not** do this (see finding 1).
- `uircd_ban_add` and `uircd_kill_match` collect matching clients into a list
  and then destroy them, so destruction (a swap-remove in `s->clients`) does
  not disturb the collection walk.

### Judged

#### 1. Use-after-free when an operator KLINEs their own connection  [H-001]

- **Claim:** `cmd_kline` called `uircd_ban_add`, which kills every client the
  ban matches. When the ban matches the operator's own connection, `c` is
  freed inside `uircd_ban_add`; the old `cmd_kline` then called
  `numeric(s, c, ...)`, a heap-use-after-free read of the freed client (the
  `cli_target` access of `c->nick`).
- **Lines:** uircd.c `cmd_kline`; crash observed at uircd.c:305 `cli_target`.
- **Scenario:** an oper (an easy accident on a shared host where the oper's own
  IP is in range) runs `KLINE ip=<self>`; ASan aborts on the self-ban.
- **Falsifier:** `HARDEN/harness/kline_self_uaf.c`. Built under
  ASan+UBSan it reproduces the heap-use-after-free before the fix and prints
  `survived` after. Discriminates: the UAF read is gone only when the handler
  stops touching `c`.
- **Fix shape:** detect the self-match with `parse_term` + `client_field_match`
  before calling `uircd_ban_add`, and return that flag without referencing `c`
  afterward, mirroring `cmd_gkill`. **Fixed this round.**

#### 2. A ban capped simultaneous removals at 256  [H-004]

- **Claim:** `uircd_ban_add` collected victims into a fixed `victims[256]`, so a
  ban matching more than 256 connected clients left the remainder connected
  until they reconnected. No memory unsafety (the index was bounded), a
  correctness/enforcement gap.
- **Lines:** uircd.c `uircd_ban_add` (the former fixed-array loop).
- **Scenario:** 300 clients from one subnet; `KLINE ip=<subnet>` leaves ~44
  connected.
- **Falsifier:** drive 300 matching clients through the public API, add the
  ban, assert `uircd_client_count` drops to the non-matching count. Reasoned
  from the lines, not run as a standalone harness this round.
- **Fix shape:** allocate the victim list from `s->n_clients`, as
  `uircd_kill_match` already does. **Fixed this round.**

#### 3. Ban matching ignores the `!=` negation that the query grammar accepts  [H-005]

- **Claim:** `parse_term` parses a `field!=glob` negation and `client_matches`
  honors it, but `uircd_ban_add` matches with `client_field_match`, which
  ignores `negate`. So a negated ban spec (`ip!=10.0.0.0/8`) is stored and
  matches as if positive, banning the wrong set. `uircd_kill_match`/GKILL
  honor negation; KLINE bans do not.
- **Lines:** uircd.c `client_field_match` vs `client_matches`; `uircd_ban_add`;
  `client_banned`.
- **Scenario:** `KLINE ip!=203.0.113.5` intends "everyone but 5" but bans 5.
- **Falsifier:** add a ban `nick!=keep`, connect `keep` and `other`, assert
  `other` is the one removed. Reasoned, not run this round.
- **Fix shape:** have `client_banned` and `uircd_ban_add` apply `b.term.negate`,
  or reject a negated spec in `uircd_ban_add`. **Accepted** this round and
  recorded; negated bans are an uncommon admin input and the behaviour is
  documented here rather than silently wrong in code. Recorded ACCEPTED in the
  ledger. (Closed in round 2 below, finding 4.)

## Round 2 (2026-11-18)

### 4. Negated ban specs now apply the negation  [H-005]

- **What changed:** a single helper `term_matches(c, t)` now computes a term's
  verdict and flips it when `t->negate` is set. `client_matches` (always
  honored negation), `client_banned`, and `uircd_ban_add` all go through it, so
  bans and the GKILL/KILL query path share one definition. A negated KLINE spec
  now bans the complement set it names, instead of the set it excludes.
- **Lines:** uircd.c `term_matches` (new); uircd.c `client_banned`; uircd.c
  `uircd_ban_add`; uircd.c `client_matches`.
- **Falsifier:** `HARDEN/harness/ban_negation.c`, built and run under ASan+UBSan
  this round. With `keep` and `other` connected it adds `nick!=keep` and asserts
  `other` is removed and `keep` stays. Prints `survived`. Discriminates: before
  the fix the ban removed `keep`, so the assertions abort.
- **State:** **FIXED.**
