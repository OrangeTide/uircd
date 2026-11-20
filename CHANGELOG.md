# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/) and
[Semantic Versioning](https://semver.org/).

## 1.0.0 - 2026-11-19

First release.

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
