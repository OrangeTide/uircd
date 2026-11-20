# uircd 0.2.1

uircd is a network-agnostic IRC server engine (`uircd.h`, `uircd.c`) and
`miniircd`, a threaded TLS example daemon built on it. This is an early,
intentionally minimal release: the public API is still settling and the IRC
command set is a subset. See "Known limitations".

## Changes since 0.2.0

Interoperability fixes found by testing against the irssi client:

- Respond to `CAP LS`/`LIST` with an empty capability list (and `NAK`
  requests), so a client doing capability negotiation on connect finishes at
  once instead of waiting.
- A bare channel list-mode query (`MODE #chan b`, sent by clients on join) now
  returns the end-of-list numeric (`368`, and `349`/`347` for `e`/`I`) rather
  than `482 You're not channel operator`.

0.2.0 added `WHOIS` (user, channels, server, operator status, end; 401 for an
unknown nick), with the host in the reply respecting cloaking.

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

## Known limitations

- The IRC command set is a subset; AWAY, ISON, USERHOST, INVITE, WALLOPS,
  VERSION, LUSERS, and MOTD-as-a-command are not implemented, and an
  unimplemented command returns a 421 reply.
- The public API is not yet frozen and may change before 1.0; the auth callback
  contract in particular changed late in development.
- Testing is synthetic and local (sanitizers, a fuzzer, and a loopback
  functional suite); it has not been run against real IRC clients or a real
  network.
- Built and tested on Linux with glibc and OpenSSL.

See `CHANGELOG.md` for the full list.
