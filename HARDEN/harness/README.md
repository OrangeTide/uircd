# HARDEN harnesses

Each harness includes the real source it tests and stubs the rest, and is built
under AddressSanitizer and UndefinedBehaviorSanitizer. A harness prints
`survived` when the finding it targets is fixed, and reproduces the fault
(an ASan/UBSan abort) while it is open.

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
