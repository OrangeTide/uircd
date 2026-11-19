# HARDEN harnesses

Each harness includes the real source it tests and stubs the rest, and is built
under AddressSanitizer and UndefinedBehaviorSanitizer. A harness prints
`survived` when the finding it targets is fixed, and reproduces the fault
(an ASan/UBSan abort, or a failed assertion) while it is open.

`make check` from the repository root builds and runs every harness and reports
whether each printed `survived`.

## kline_self_uaf  (H-001)

Reproduces the use-after-free when an operator KLINEs a ban that matches their
own connection. Drives the real `uircd.c` through its public API.

```sh
cd HARDEN/harness
cc -fsanitize=address,undefined -fno-omit-frame-pointer -g -std=c11 \
   -D_GNU_SOURCE -I../.. kline_self_uaf.c -o kline_self_uaf
./kline_self_uaf     # prints "survived" on fixed code; ASan aborts on the bug
```

Expected on the fixed tree: `survived`, exit 0.
On the pre-fix tree: `AddressSanitizer: heap-use-after-free ... in cli_target`.

## conn_cap  (H-002)

Checks the per-IP connection cap and the unregistered-session registration
deadline against the real `uircd.c`. Opens `max_per_ip` connections from one IP
and asserts the next is refused while another IP is still accepted, then ticks
the clock past `reg_timeout_ms` (but short of the ping interval) and asserts the
unregistered sessions are reclaimed.

```sh
cd HARDEN/harness
cc -fsanitize=address,undefined -fno-omit-frame-pointer -g -std=c11 \
   -D_GNU_SOURCE -I../.. conn_cap.c -o conn_cap
./conn_cap     # prints "survived" when H-002 is fixed
```

Expected on the fixed tree: `survived`, exit 0. Without the cap or the deadline
one of the harness assertions aborts.

## ban_negation  (H-005)

Checks that a negated ban spec (`nick!=keep`) removes the complement set. Adds
the ban with two clients connected, `keep` and `other`, and asserts `other` is
the one removed. Before the fix the ban ignored the negation and removed `keep`.

```sh
cd HARDEN/harness
cc -fsanitize=address,undefined -fno-omit-frame-pointer -g -std=c11 \
   -D_GNU_SOURCE -I../.. ban_negation.c -o ban_negation
./ban_negation     # prints "survived" when H-005 is fixed
```

Expected on the fixed tree: `survived`, exit 0. On the pre-fix tree the
assertions abort because the wrong client was removed.

## async_auth  (H-013)

Drives the real `uircd.c` through the deferred-authentication path
(`UIRCD_AUTH_PENDING` + `uircd_auth_complete`), single-threaded, so it exercises
the engine contract rather than the host's KDF pool. It asserts that a pending
verdict parks the client and holds its further input, a later accept replays the
held NICK/USER to register, a reject drops the client, hold-cap overflow drops
it, a close mid-pending frees the hold buffer, and a deferred OPER grants on
accept.

```sh
cd HARDEN/harness
cc -fsanitize=address,undefined -fno-omit-frame-pointer -g -std=c11 \
   -D_GNU_SOURCE -I../.. async_auth.c -o async_auth
./async_auth     # prints "survived" when the deferred-auth path is correct
```

Expected on the fixed tree: `survived`, exit 0. Against an engine whose
`uircd_auth_complete` does not apply the verdict (or that fails to hold input),
an assertion fails and it exits nonzero.

## dispatch_fuzz  (protocol engine)

Randomized fuzzer for the engine's command dispatch, the richest untrusted-input
surface: every client can send arbitrary lines that reach
JOIN/MODE/KICK/KILL/KLINE/WHO/TOPIC and the rest with attacker-chosen
parameters. It drives the real `uircd.c` through `uircd_recv`, keeping a pool of
clients (some registered, some opered), and feeds random command lines: real
commands with random-length parameters, raw bytes, over-long lines, split
writes, and pipelines. Client lifetime is tracked exactly, since the engine
frees a client when it quits it, so the freed pointer is never reused. It also
ticks the clock to exercise the ping and timeout paths.

```sh
cd HARDEN/harness
cc -fsanitize=address,undefined -fno-omit-frame-pointer -g -std=c11 \
   -D_GNU_SOURCE -I../.. dispatch_fuzz.c -o dispatch_fuzz
./dispatch_fuzz                 # 200000 iterations, seed 1; prints "survived"
./dispatch_fuzz 300000 42       # more iterations, a different seed
```

Deterministic for a given seed, so a crash reproduces. It is part of `make
check` at its default count; the campaign for the round ran several seeds at
300000 iterations (about 2.1M dispatched lines) with no ASan/UBSan error, and a
coverage build confirmed the command handlers are actually reached (for example
cmd_join, cmd_kline, cmd_kill, cmd_nick, cmd_privmsg all execute). Expected:
`survived`, exit 0.

## auth_timing  (H-003)

A load driver, not a self-contained harness: it needs a running `miniircd`
started with a passwd file and `-L`. It times a rejected login's first response
byte for a name that exists (the KDF runs) versus one that does not (no KDF), and
prints both distributions with a PASS/FAIL verdict on the median gap. With async
auth the verdict is delivered at a fixed deadline for both, so the medians
overlap and timing does not enumerate names.

```sh
make                                     # optimized miniircd + tool
./uircdpasswd alice c secret > /tmp/t.passwd
cc -O2 -g -std=c11 -D_GNU_SOURCE HARDEN/harness/auth_timing.c \
   -o /tmp/auth_timing -lpthread -lssl -lcrypto

# Positive: the shipped 120ms deadline exceeds the KDF, so the medians overlap.
./miniircd -p 7910 -A /tmp/t.passwd -L >/dev/null 2>&1 &
/tmp/auth_timing 7910 alice ghost 200          # expect PASS, gap ~1ms
kill %1

# Negative control (shows the test discriminates): an auth deadline below the
# KDF cost re-exposes the leak. Put it in a config file (a pipe is not seekable).
printf '[auth]\npasswd = /tmp/t.passwd\nrequire-login = true\n'\
'auth-deadline-ms = 1\nauth-jitter-ms = 0\n[listen]\nport = 7912\n' > /tmp/fast.conf
./miniircd -f /tmp/fast.conf >/dev/null 2>&1 &
/tmp/auth_timing 7912 alice ghost 200          # expect FAIL, gap ~60ms
kill %1
```

With `-s` the client speaks TLS, for a server started with `-c`/`-k`. The
handshake runs before the timed section, so the measurement is the same:

```sh
openssl req -x509 -newkey rsa:2048 -keyout /tmp/k.pem -out /tmp/c.pem \
   -days 1 -nodes -subj /CN=irc.test
./miniircd -p 7697 -A /tmp/t.passwd -L -c /tmp/c.pem -k /tmp/k.pem >/dev/null 2>&1 &
/tmp/auth_timing -s 7697 alice ghost 200       # expect PASS, gap ~2ms
kill %1
```

Expected: `PASS` (exit 0) on the shipped server (plaintext and TLS alike), `FAIL`
(exit 1) on the sub-KDF-deadline control. `KNOWN_NAME` must exist in the passwd
file with the `c` flag and `UNKNOWN_NAME` must not; the 5th argument overrides the
40ms threshold. Note that under a sub-KDF deadline the miss latency is itself
raised to the deadline-poll floor (the timer re-arms in ~20ms steps), which
shrinks the measured gap, so the TLS control is run with a tighter threshold
(e.g. 20) to flag its ~30ms separation; the shipped 120ms deadline leaves a clean
~2ms gap at the default threshold.

`-c N` runs N concurrent samplers to measure the gap under concurrent login load
(H-014). Give the server a high `-P` so the per-IP cap does not refuse the load:

```sh
./miniircd -p 7920 -t 4 -A /tmp/t.passwd -L -P 1000 >/dev/null 2>&1 &
/tmp/auth_timing -c 8  7920 alice ghost 40     # within pool capacity: gap ~1ms
/tmp/auth_timing -c 64 7920 alice ghost 30     # saturated: both ~1s, gap grows
kill %1
```

On the default 2-thread pool the gap stays small through moderate concurrency
and only separates at deep saturation (near the fail-closed cap); raising
`[auth] kdf-threads` to cover the concurrent-login rate keeps it at ~0ms.

## tsan_load  (H-007, H-008)

A load driver, not a self-contained harness: it needs a running server. Build
the host under ThreadSanitizer and drive it with concurrent clients to surface
the worker-interaction races.

```sh
make tsan
setarch -R env TSAN_OPTIONS=halt_on_error=0 ./miniircd -p 7903 -t 4 &
cc -O2 -g -pthread -w HARDEN/harness/tsan_load.c -o /tmp/tsan_load
for r in 1 2 3 4; do /tmp/tsan_load 7903 300 50; done
```

Expected on the fixed tree: ThreadSanitizer reports nothing. Before the fixes it
reports a `heap-use-after-free` (H-007) and a data race on `g_stop` (H-008).
`setarch -R` disables ASLR, which TSan requires on some kernels.
