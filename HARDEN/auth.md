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
