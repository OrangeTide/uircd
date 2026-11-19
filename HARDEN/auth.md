# HARDEN surface: authentication and passwd parsing (example/auth.c, b64.c)

Local-parser and credential surface. `auth_load` reads a passwd file (trusted,
operator-provided), and `auth_verify` runs scrypt over a client-supplied
password and compares it to the stored hash. `b64.c` decodes the stored salt
and hash.

## Round 1 (2026-11-18)

### Observed

- `auth_load` reads lines up to 1024 bytes, skips blank and `#` lines, and caps
  entries at `MAX_ENTRIES` (256). `parse_line` requires exactly 8 `:`-separated
  fields, rejects a non-`scrypt` algorithm, bounds the name against
  `sizeof(e->name)`, and validates that N is a power of two >= 2 and r, p are
  non-zero.
- `b64_decode` bounds every write against `dstsz` and returns `(size_t)-1` on
  malformed input or overflow. The salt buffer is `SALT_MAX` (64); the hash must
  decode to exactly `HASH_LEN` (32) or the line is rejected.
- `auth_verify` runs `crypto_scrypt` on the client password and compares with
  `ct_equal`, a constant-time comparison, so the comparison itself leaks no
  timing about how many bytes matched.
- Salts are generated in `tools/uircdpasswd.c` from `getrandom`, not from the
  vendored scrypt DRBG. The tool wipes the plaintext password and derived hash
  from its stack before exit and reads the password with terminal echo off.

### Judged

#### 1. Response timing distinguishes known from unknown account names  [H-003]

- **Claim:** `auth_verify` calls `find_entry` first and returns immediately when
  the name is absent, running the (deliberately expensive) scrypt KDF only for
  names that exist. The difference in response time lets an attacker enumerate
  valid account and oper names.
- **Lines:** example/auth.c `auth_verify` (the early `if (!e ...) return` before
  `crypto_scrypt`); `find_entry`.
- **Scenario:** time many `PASS name:x` or `OPER name x` attempts; names that
  take ~scrypt-time to fail are real accounts.
- **Falsifier:** the fail path for an unknown name runs a scrypt of equal cost
  to the real path (a dummy verification against a fixed decoy record), so the
  timing of a known-bad and an unknown name are indistinguishable. Reasoned, not
  measured this round.
- **Fix shape:** on a missing entry, run `crypto_scrypt` against a fixed decoy
  salt/params and then fail, so every attempt pays the same cost. **Accepted:**
  IRC account and oper names are not treated as secrets (they appear in WHO,
  channel membership, and KILL/KLINE output), and a constant-cost path adds a
  full KDF to every bad login. Recorded for a deployment that does want name
  privacy.

### Not checked this round

- The vendored scrypt itself (`third_party/scrypt`) was taken as a trusted,
  upstream, public-domain implementation and not re-audited.
- No check that the operator sets restrictive file permissions on the passwd
  file; that is deployment guidance, noted in the README, not enforced in code.

## Round 2 (2026-11-19)

Reviewing H-003 (timing enumeration) surfaced a second, larger defect in the same
code path, and a design that resolves both.

### Observed

- Measured `auth_verify` directly: ~61 ms for a known name with a wrong password
  (full scrypt) versus ~0.001 ms for an unknown name, a ~60,000x gap and a
  trivially remote-measurable enumeration signal. This confirms H-003 with a
  number, where round 1 reasoned it from the lines.
- The enumeration also distinguishes oper-capable names: for `OPER`, the
  `!(e->flags & FLAG_OPER)` check returns before scrypt, so a slow `OPER name x`
  identifies a name that holds oper privilege, which `WHO` does not reveal. The
  gap likewise exposes account names that are offline or never connect, again not
  visible through normal IRC commands. So the "names are not secret" basis for
  accepting H-003 is weaker than round 1 stated.

### Judged

#### 1. The scrypt KDF runs under the global lock  [H-012]

- **Claim:** `auth_verify`'s ~61 ms scrypt runs while the host holds the single
  global lock. `on_readable` takes `g_lock` across `uircd_recv` (`miniircd.c`),
  which dispatches `PASS`/`OPER` to `cmd_pass`/`cmd_oper`, which call `cfg.auth`
  (`uircd.c:895,911`). Under one global lock, that 61 ms serializes every worker:
  one login stalls the whole server. It is reachable without any secret, since a
  bare `PASS <pw>` matches a shared `*` entry and account names are not secret;
  with the flood and per-IP limits a single IP can hold the lock a large fraction
  of the time, an availability DoS.
- **Lines:** example/miniircd.c `on_readable` (`g_lock` across `uircd_recv`);
  uircd.c `cmd_pass`, `cmd_oper` (`cfg.auth` under the lock); example/auth.c
  `auth_verify`.
- **Scenario:** a registered observer pings in a loop while a few connections
  send bad logins; the observer's trivial `PING` requests queue behind serialized
  61 ms KDFs and stall far past normal RTT (observed: the probe hangs).
- **Falsifier:** a registered observer's `PING` RTT stays within normal bounds
  while a login flood is in flight. True only when the KDF no longer runs under
  `g_lock`. Grounded this round in the measured 61 ms KDF plus the code path
  holding `g_lock`; to be measured cleanly on implementation.
- **Fix shape:** the async-auth redesign in `HARDEN/DESIGN-async-auth.md`: run the
  KDF off the lock in a bounded pool and deliver the verdict at a scheduled
  deadline. The same design closes H-003. **Open**, designed not yet built.

## Round 3 (2026-11-19)

Implemented the async-auth design, which resolves H-003, H-012, and the H-013
opportunity row. No new credential-surface finding; this section records what the
implementation changed and the one concurrency defect it surfaced.

### Changed

- `auth.c` split: `auth_lookup` does the cheap table lookup and snapshots the
  stored parameters (or marks a miss) and may run under a lock; `auth_compute`
  runs scrypt and the constant-time compare with no lock, wipes the password
  copy, and runs no scrypt on a miss. `auth_verify` is gone.
- The engine's auth callback now receives the connection handle and may return
  `UIRCD_AUTH_PENDING`. `cmd_pass`/`cmd_oper` park the client on that verdict and
  the engine holds the client's further input (bounded 4 KiB) until
  `uircd_auth_complete` delivers the result and replays the held input.
- The host runs a fixed KDF thread pool off `g_lock`, arms a per-attempt deadline
  timer (`BASE + jitter`, same formula for a hit and a miss), and routes the
  result back by `{worker, auth_id}` rather than a conn pointer, so a connection
  that closes mid-KDF is safe.

### Judged

#### 1. First-call race in the vendored scrypt under the new KDF pool  [no row]

- **Observed:** `third_party/scrypt/crypto_scrypt.c` lazily selects its `smix`
  implementation on the first call (`if (smix_func == NULL) selectsmix();`), a
  write-once global. Running scrypt from the single engine thread never raced on
  it, but the new KDF pool calls it from several threads; TSan reported a data
  race on `smix_func` between two pool threads on the first concurrent calls.
- **Falsifier:** a concurrent login load under TSan reports 0 data races. Before
  the fix TSan flags the `smix_func` write/read; after, 0.
- **Fix:** host-side `auth_warmup()` runs one trivial scrypt on the main thread
  before the pool starts, resolving `smix_func` while only one thread exists; the
  pool threads then only read it. The vendored code is unchanged. Re-run under
  TSan over concurrent logins (including many connections that close mid-KDF): 0
  races. Not a ledger row: it was introduced and closed within this round's work
  and never shipped.

### Not checked this round

- No dedicated timing-distribution harness: the equal-deadline property is
  structural (the response is scheduled to the same `BASE + jitter` formula on
  both paths and the KDF result is only latched, not delivered early).
- No standalone cross-worker PING-RTT harness for H-012: the off-lock property is
  structural (`auth_compute` takes no engine lock) and TSan-confirmed.
- The vendored scrypt and its parameters were not otherwise re-audited.
