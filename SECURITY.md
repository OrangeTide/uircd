# Security policy

## Reporting a vulnerability

Report suspected security issues privately. Do not open a public issue for a
vulnerability, and do not include a working exploit in the first report; a
description of the problem class and the affected file and line is enough to
start.

Private route: open a GitHub **private security advisory** on this repository
("Security" tab -> "Report a vulnerability"), or send a report through whatever
private channel the repository owner has published. If neither is available,
ask the owner for a private channel before sending details.

Please leave third-party contact details, personal addresses, and unrelated
user data out of the report. Include only what is needed to reproduce: the
version or commit, the input, and what you observed.

## Scope and status

This is example and library code. It has one round of HARDEN review recorded in
[`HARDEN.md`](HARDEN.md), with reviewer reports under [`HARDEN/`](HARDEN/) and
runnable falsifiers under [`HARDEN/harness/`](HARDEN/harness/). Known, accepted
limitations are listed there with their reasons; read the ledger before
reporting so a known-accepted item is not re-filed.

## Operator guidance

- Keep the passwd file (`-A`) readable only by the account that runs the
  server; it holds scrypt password hashes.
- Terminate TLS with a real certificate; the `-c`/`-k` options take a PEM chain
  and key. The server enforces a TLS 1.2 floor and disables renegotiation.
- The server caps concurrent connections per source IP (`-P`, default 8) and
  drops sessions that do not register within a deadline (`-R`, default 30s). On
  a network fronted by a trusted NAT or proxy, raise `-P` so legitimate shared
  addresses are not throttled.
- The operator log records connecting clients' IP addresses, and a user's raw
  IP is visible to other users through `WHO`/`WHOIS` and message prefixes (there
  is no host cloaking). Retain and share logs accordingly, and tell users their
  address is visible server-wide. The server itself sends nothing off the
  machine. See finding H-016.
