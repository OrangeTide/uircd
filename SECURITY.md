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
- There is no per-IP connection limit yet (ledger H-002); put the server behind
  a firewall or connection-rate limiter on an exposed network.
