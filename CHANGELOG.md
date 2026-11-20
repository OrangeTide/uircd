# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/) and
[Semantic Versioning](https://semver.org/).

## 0.2.1 - 2026-11-19

### Fixed

- Respond to `CAP LS`/`LIST` with an empty capability list and `NAK` requests,
  so a client doing capability negotiation on connect (for example irssi)
  finishes at once instead of waiting for a reply that never came.
- A bare channel list-mode query (`MODE #chan b`, which clients send on join)
  now returns the end-of-list numeric (`368`, and `349`/`347` for `e`/`I`)
  instead of `482 You're not channel operator`. Found by testing against irssi.

## 0.2.0 - 2026-11-19

### Added

- `WHOIS`: replies with the user line (311), channels (319), server (312),
  operator status (313), and end (318), or 401 for an unknown nick. The host in
  the 311 reply respects cloaking: an operator sees the real address, others see
  the cloak.

## 0.1.0 - 2026-11-19

First release. Early and intentionally minimal: the public API is still
settling (the authentication contract was reworked late in development) and the
IRC command set is a subset. See "Known limitations" below.

### Library (uircd.h, uircd.c)

- Network-agnostic IRC server engine driven by host callbacks (out, drop, auth,
  log). The engine is single-threaded and not thread-safe by design; the host
  serializes access.
- Registration (NICK, USER, PASS), channels (JOIN, PART, TOPIC, MODE, KICK,
  NAMES, LIST), messaging (PRIVMSG, NOTICE), queries (WHO), and operator
  commands (OPER, KILL, KLINE, UNKLINE, GKILL, BANLIST), with ISUPPORT.
- Asynchronous authentication: the auth callback may return
  `UIRCD_AUTH_PENDING` and the host delivers the verdict later with
  `uircd_auth_complete()`, so a slow credential check never blocks the engine.
- Host cloaking: a client's real address is hidden from other users behind a
  keyed `<hex>.cloak` token; operators and bans still use the real address.
- Per-connection limits: per-IP connection cap, unregistered-session deadline,
  and line flood accounting.

### Example daemon (miniircd)

- Threaded TLS server built on the engine: one worker per core, SO_REUSEPORT
  listeners, optional TLS (TLS 1.2 floor, renegotiation disabled), and a
  bounded off-lock scrypt thread pool for login verification.
- gitconfig-style configuration file and command-line options; a config-check
  mode (`-C`); daemonization.
- `uircdpasswd` tool for generating scrypt password entries.

### Security

- Carries a HARDEN review recorded in the repository (`HARDEN.md`, `HARDEN/`,
  `HARDEN/harness/`): 18 findings, all fixed or accepted with runnable
  falsifiers, plus a command-dispatch fuzzer and a functional test suite.
- Login timing is equalized so it does not enumerate account names; secret
  material is wiped with elision-resistant zeroing; the server makes no outbound
  connections and sends nothing off the machine.

### Build and packaging

- `make`, `make check` (sanitizer falsifiers), `make test` (functional suite),
  `make install`, `make dist`, and man pages for `miniircd` and `uircdpasswd`.
- Continuous integration runs the build, the functional tests, the sanitizer
  harnesses, and a ThreadSanitizer load.

### Known limitations

- The IRC command set is a subset. Notably absent: WHOIS, AWAY, ISON, USERHOST,
  INVITE, WALLOPS, VERSION, LUSERS, and MOTD as a command. A client sending an
  unimplemented command receives an "Unknown command" (421) reply.
- The public API is not yet frozen. Expect it to change before a 1.0 release;
  the authentication callback contract in particular changed late.
- Testing is synthetic and local: sanitizer falsifiers, a dispatch fuzzer, and a
  functional suite that drives the engine over loopback. It has not been
  exercised against real IRC clients or over a real network.
- Built and tested on Linux with glibc and OpenSSL; other platforms are not yet
  supported by the example host.
