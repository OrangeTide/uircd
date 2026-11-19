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
