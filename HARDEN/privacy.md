# HARDEN surface: privacy -- what leaves the machine (uircd.c, example/miniircd.c)

What the server discloses and to whom: data sent off the machine (telemetry,
crash reports, phone-home), and data about one user that reaches other users or
the operator's log. The config-file and passwd parsers are reviewed on the
local-parser side (rounds 7-8, auth round 1); this surface is about disclosure,
not parsing.

## Round 1 (2026-11-19)

### Observed

- No outbound network. There is no `connect()` in `uircd.c`, `example/*.c`,
  `tools/*.c`, or the vendored libiox sources; the server only `accept()`s. No
  `exec*`, `popen`, or `system`, and no `getenv`. The only `fork()` is in
  `vendor/daemonize.c` (backgrounding). So the server sends nothing off the
  machine on its own: no telemetry, crash report, update check, or license call.
  The only data that leaves a process is IRC traffic to connected clients and
  whatever the host's `log` callback writes locally.
- The stored client host is the raw peer IP. `example/miniircd.c:771,775` fill
  `c->peer_ip` with `inet_ntop` of the accepted address (no DNS lookup, no
  cloaking), and `uircd.c:1902` copies it into the engine client's `host`.
- The host IP reaches the operator log. The engine logs `connect` with `c->host`
  (`uircd.c:1912`) and `quit` with nick-or-host (`uircd.c:687,2071`); the example
  `on_log` writes these to `stderr`/the operator's sink.
- The host IP reaches other users. `cmd_who` emits `t->host` in the 352 reply
  (`uircd.c:1259-1260,1270-1271`), and `cli_prefix` builds `nick!user@host`
  (`uircd.c:338-343`) used in the broadcast prefixes of JOIN/PART/QUIT/PRIVMSG.
  So any connected user can read any other user's raw IP.
- Password material does not leak: `auth_compute` wipes its password copy after
  the compare (auth round 3); `tools/uircdpasswd.c` wipes plaintext and reads
  with echo off (auth round 1). Scrypt hashes live only in the operator's passwd
  file.

### Judged

#### 1. A user's raw IP address is disclosed to other users  [H-016]

- **Claim:** the stored host is the literal peer IP with no cloaking, and the
  server hands it to other users through `WHO`/`WHOIS` (the 352 reply prints
  `t->host`) and through the `nick!user@host` prefix on a user's messages. A
  user therefore learns the IP addresses of others on the server without
  operator privilege, which some IRC deployments deliberately prevent with host
  masking. This is disclosure to third parties (other clients), beyond the
  expected operator-side logging.
- **Lines:** `uircd.c:1902` (host = raw peer IP); `uircd.c:1259-1260,1270-1271`
  (WHO 352 emits `t->host`); `uircd.c:338-343` (cli_prefix nick!user@host).
- **Scenario:** two users connect; one issues `WHO <other>` (or simply reads the
  other's JOIN prefix in a shared channel) and reads the other's raw IP address.
- **Falsifier:** a client that queries `WHO` for a registered user receives that
  user's literal IP in the 352 reply; with host cloaking it would receive a
  masked token instead. Run this round: a client sent `NICK/USER/WHO` over a
  local connection and the 352 reply read
  `:irc.local 352 alice * ~a 127.0.0.1 irc.local alice H :0 a` -- the raw
  `127.0.0.1` is present.
- **Fix shape:** optional host masking (a cloak applied to `host` before it is
  shown to non-operators), left to a deployment that wants it; this minimal
  example does not cloak. **Accepted:** exposing user hosts is part of the IRC
  data model (hosts appear in WHO/WHOIS and prefixes by design) and the operator
  controls the deployment; cloaking is a feature, not a safety fix. Mitigated by
  disclosure this round: README and SECURITY now state that the log records
  client IPs and that a user's address is visible server-wide with no cloaking,
  so an operator can set log retention and inform users, and can add masking if
  the deployment needs it.

### Not checked this round

- No masking/cloaking implementation was attempted; the finding is accepted with
  the exposure disclosed, not removed.
- The operator's own `log` sink (file, syslog, shipping to a collector) is the
  operator's responsibility; this surface notes that the log carries client IPs
  but does not audit where an operator sends it.
- DNS: the server does no reverse lookup, so it discloses the IP, not a resolved
  hostname. A deployment that adds reverse DNS would change what is disclosed and
  should be re-reviewed.
