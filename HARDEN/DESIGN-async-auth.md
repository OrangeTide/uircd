# DESIGN: asynchronous authentication

Status: implemented in round 12 (`tree:round-12`). Resolves H-003, H-012, and
the H-013 opportunity row. The sections below are the design as built; one point
not anticipated here is recorded under "As built".

## Problem

Two findings share one root cause.

- **H-003 (timing enumeration):** `auth_verify` runs scrypt only for a name that
  exists with the needed flag and returns in ~1 us for a miss, so response time
  enumerates account and oper names. Measured: ~61 ms (hit) vs ~0.001 ms (miss)
  with the default `N=16384, r=8, p=1`.
- **H-012 (global-lock stall):** that ~61 ms scrypt runs **under the single
  global lock**. The host holds `g_lock` across `uircd_recv`
  (`miniircd.c` `on_readable`), which dispatches `PASS`/`OPER` to
  `cmd_pass`/`cmd_oper`, which call `cfg.auth` (`uircd.c:895,911`). So one login
  stalls every worker for the KDF duration. Reachable without any secret: a bare
  `PASS <pw>` matches a shared `*` entry, and account names are not secret.

Root cause: authentication is synchronous, blocking, and on the lock.

## Goals

1. Equal response timing for hit and miss (close H-003) without a decoy KDF.
2. Never run the KDF under `g_lock` or on the event thread (close H-012).
3. Bound the response time to a deadline the server controls.
4. A failed login, especially an unknown name, costs ~no CPU (no decoy-KDF DoS).
5. A small, clear API change and no new unbounded resource.

Non-goals: defending a local attacker who can observe CPU or power (out of
scope; under "no local access" a calibrated wait is equivalent to real work);
changing the passwd format or the KDF.

## Approach: deferred verdict + off-lock KDF

Separate deciding the answer from telling the client, and move the KDF off the
lock.

### Timing model

On a `PASS`/`OPER` attempt at `t0`, schedule the verdict for

    deadline = t0 + BASE + rand(0, JITTER)

with the **same formula on both paths**. `BASE` is >= the slowest configured
scrypt, so the real KDF always finishes before the deadline. `JITTER` (e.g.
0-20 ms) blurs the delay's variance, so a miss that only waits is
indistinguishable from a hit that computed, by distribution and not merely by
mean. Both paths answer at the deadline, so timing carries no hit/miss signal. A
miss does no KDF; a hit runs the KDF off-lock and latches its result for the
deadline.

### Library API change (uircd)

Authentication becomes three-valued and resumable.

- New verdict `UIRCD_AUTH_PENDING` the callback may return in addition to
  `UIRCD_OK`/`UIRCD_ERR`. It means "the host will deliver the verdict later."
- On `PENDING`, `cmd_pass`/`cmd_oper` park the client in an awaiting-auth state:
  registration is neither completed nor rejected, and further input from that
  client is held until the verdict arrives. At most one auth is in flight per
  client; a second `PASS`/`OPER` while pending is ignored.
- New call:

      void uircd_auth_complete(struct uircd *s, struct uircd_client *c, int ok);

  The host calls it when the deferred verdict is ready. The engine then resumes
  exactly as if the callback had returned `ok`/`err` synchronously (completes
  registration, or emits the failure) and processes any held input.
- Lifetime: while pending the client stays alive. If `uircd_closed` arrives first
  (peer dropped), the pending verdict is discarded; the host must not call
  `uircd_auth_complete` after `uircd_closed` for that client. The engine treats a
  complete for a client that is not awaiting that auth as a no-op.

### Host implementation (miniircd)

- Split `auth.c` into `auth_lookup(kind, name) -> entry* | MISS` (cheap, may run
  under the lock) and `auth_compute(entry, pass) -> ok` (the scrypt, no lock).
- In the auth callback (invoked under `g_lock` inside `uircd_recv`): do the cheap
  lookup, snapshot `{salt, params, stored hash}` or `MISS` plus a copy of the
  password, compute `deadline`, enqueue a job, and return `UIRCD_AUTH_PENDING`.
  Do not run scrypt here.
- A small fixed-size **KDF thread pool** (e.g. 2-4 threads, separate from the IO
  workers) runs `auth_compute` without `g_lock`. A `MISS` job does no scrypt.
  Each job carries the owning worker and a conn token (generation) so a result
  for a since-closed conn is dropped.
- Delivery: the job posts `{conn token, ok}` to the owning worker's result queue
  and wakes it over the existing self-pipe. Simplest control flow: when the
  attempt starts, arm one iox timer for `deadline`; the compute finishes before
  then by construction, so at fire the owner reads the latched result and calls
  `uircd_auth_complete` under `g_lock`, then flushes.
- Zero-cost miss: a `MISS` job skips scrypt; the connection just waits for the
  deadline timer.

### Resource bounds (new, explicit)

- The KDF pool is fixed size, so login load produces bounded CPU regardless of
  attempt rate; excess jobs sit in a bounded queue, and a full queue fails the
  attempt fast but still answers at the deadline (no timing leak). This replaces
  today's implicit flood/per-IP bound and removes global-lock contention.
- Pending auths are bounded by `max_clients` and the one-in-flight rule.
- A pending auth that never resolves is caught by the existing registration
  deadline (`reg_timeout`): the client is dropped as unregistered.

### Lifetime and concurrency safety

Reuse the established discipline. Conns are freed only by the owning worker; a
KDF result references the conn by `{worker, generation}`; the owner validates the
generation under `g_lock` before touching the conn. A conn closed mid-KDF bumps
its generation, so the stale result is dropped. This mirrors the `io_cur_freed`
guard already used for the on_io use-after-free (H-007). The password copy in the
job is zeroed after compute.

## Alternatives considered (rejected)

- **Inline sleep under `g_lock`** to equalize timing: worsens H-012, since misses
  would now hold the lock too.
- **Decoy scrypt on a miss:** closes H-003 but adds a full KDF to every failed
  login, a CPU amplifier, and still runs under the lock unless offloaded.
- **Fixed delay without offloading the KDF:** equalizes timing but leaves H-012;
  real logins still block the lock.
- **One KDF thread per attempt:** unbounded threads under a flood; the fixed pool
  is bounded.

## Properties achieved

- H-003 closed: hit and miss answer at the same deadline +/- jitter.
- H-012 closed: the KDF never runs under `g_lock` or on the IO loop.
- No new DoS: misses cost ~0; hits are bounded by the fixed KDF pool.

## Scope of change

- `uircd.h`: add `UIRCD_AUTH_PENDING`; add `uircd_auth_complete`; document the
  async contract and the one-in-flight rule.
- `uircd.c`: awaiting-auth client state; `cmd_pass`/`cmd_oper` handle `PENDING`;
  resume logic mirroring synchronous completion; guard stale completes.
- `example/auth.c`: split lookup vs compute; zero the password copy.
- `example/miniircd.c`: KDF thread pool + bounded queue; deadline timer; result
  delivery over the self-pipe; generation/token lifetime guard; config keys
  `[auth] auth-deadline-ms`, `auth-jitter-ms`, `kdf-threads`.
- HARDEN: this note; H-012 (WARN) and the OPP row; falsifiers below.

## Risks and open questions

- Breaking change to the auth callback contract. The library is pre-1.0 with no
  tagged release, so acceptable now; it must be called out in the header.
- Added complexity (pool, queue, async resume, lifetime tokens) in exchange for
  correctness and scalability, justified by the measured ~61 ms global stall.
- `BASE` must exceed the slowest configured scrypt. Validate `BASE` >= the
  measured cost of the heaviest passwd entry at load, or calibrate at boot.

## As built

One thing the design did not anticipate: the vendored scrypt selects its `smix`
implementation lazily on the first call into a write-once global, which is safe
from one thread but races across the new KDF pool threads on their first
concurrent calls (caught by TSan). It is resolved host-side with `auth_warmup()`,
one trivial scrypt on the main thread before the pool starts, leaving the
vendored code unchanged. The KDF job references its connection only by
`{worker, auth_id}` (a monotonic id), never a conn pointer, which is how the
"generation token" lifetime guard is realized here. If the KDF pool is saturated
long enough that a job is not computed within the deadline plus a bounded poll
window (~1s), the login fails closed; that is the intended bounded-CPU tradeoff.

## Acceptance tests (falsifiers for the OPP row)

1. **Timing:** over N trials, the response-time distributions for a known-bad
   name and an unknown name overlap within `JITTER` (no separation). Closes
   H-003.
2. **No lock stall:** with a login flood in flight, a registered observer's PING
   RTT stays within normal bounds (no KDF-sized spike). Closes H-012.
3. **No DoS:** a flood of unknown-name logins produces ~no server CPU beyond
   bookkeeping (no per-attempt KDF).
