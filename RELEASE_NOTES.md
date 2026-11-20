# uircd 1.0.0

First release of uircd: a network-agnostic IRC server engine (`uircd.h`,
`uircd.c`) and `miniircd`, a threaded TLS example daemon built on it.

## Highlights

- A bring-your-own-network server engine: the core parses and serves IRC and
  leaves sockets, threads, and TLS to the host through four callbacks.
- Asynchronous authentication, so a slow credential check never blocks the
  engine, with login timing equalized so it cannot enumerate account names.
- Host cloaking on by default: a user's real address is hidden from other users
  behind a keyed `<hex>.cloak` token, while operators and bans still use the
  real address.
- A HARDEN security review kept in the repository: 18 findings, all fixed or
  accepted, each with a runnable falsifier, plus a dispatch fuzzer and a
  functional test suite.

## Library (uircd.h, uircd.c)

- Registration (NICK, USER, PASS), channels (JOIN, PART, TOPIC, MODE, KICK,
  NAMES, LIST), messaging (PRIVMSG, NOTICE), queries (WHO), and operator
  commands (OPER, KILL, KLINE, UNKLINE, GKILL, BANLIST), with ISUPPORT.
- Asynchronous auth via `UIRCD_AUTH_PENDING` and `uircd_auth_complete()`.
- Host cloaking; per-IP connection cap; unregistered-session deadline; line
  flood accounting. The engine is single-threaded by design and the host
  serializes access.

## Example daemon (miniircd)

- One worker per core, SO_REUSEPORT listeners, optional TLS (TLS 1.2 floor,
  renegotiation disabled), and a bounded off-lock scrypt thread pool for login
  verification.
- gitconfig-style configuration file and command-line options, a config-check
  mode (`-C`), and daemonization.
- `uircdpasswd` tool for generating scrypt password entries.

## Security

- Findings and falsifiers are recorded in `HARDEN.md`, `HARDEN/`, and
  `HARDEN/harness/`.
- Secret material is wiped with elision-resistant zeroing, and the server makes
  no outbound connections and sends nothing off the machine.

## Build and install

```sh
make                # build ./miniircd and ./uircdpasswd
make check          # run the HARDEN falsifiers under ASan + UBSan
make test           # run the functional test suite under ASan + UBSan
sudo make install   # install binaries, man pages, and a sample config
```

Requirements: a C11 compiler, pthreads, and OpenSSL for the example's TLS. The
core (`uircd.c`) itself needs none of these. A source tarball can be built with
`make dist`.

See `CHANGELOG.md` for the full list.
