# uircd

A compact IRC server in two files, plus a standalone example daemon built on
it.

- `uircd.h` / `uircd.c` -- the server core. It parses IRC, tracks clients and
  channels, enforces bans and authentication, and decides what to send. It does
  no networking: the host owns the sockets.
- `example/miniircd.c` -- a standalone, threaded, TLS-capable ircd that drives
  the core using the vendored [libiox](https://github.com/OrangeTide/libiox)
  event loop.

## The bring-your-own-network model

The core never touches a socket. A host feeds it received bytes and provides
two callbacks, `out` (queue bytes to a peer) and `drop` (close a peer), plus an
optional `auth` hook. The whole contract is in `uircd.h`:

```c
struct uircd *s = uircd_new(&cfg);
struct uircd_client *c = uircd_accept(s, my_conn, "203.0.113.4");
uircd_recv(s, c, bytes, len);   /* feed received data */
uircd_closed(s, c);             /* peer went away */
uircd_tick(s, now_ms);          /* call ~1/sec: pings, timeouts */
```

The core is **not** thread-safe by design; a threaded host serializes every
call behind one lock. `example/miniircd.c` shows exactly that.

## Building

```sh
make                # optimized build: ./miniircd and ./uircdpasswd
make SANITIZE=1     # AddressSanitizer + UndefinedBehaviorSanitizer build
make clean
```

Requirements: a C11 compiler, pthreads, and OpenSSL (`libssl`/`libcrypto`) for
the example's TLS. The core (`uircd.c`) itself needs none of these.

Vendored under `third_party/`: libiox (the event loop) and a minimal subset of
Colin Percival's scrypt (password hashing for the example). Each has a
`VENDORED.md` recording its origin and version.

## Running the example

```sh
./miniircd -p 6667                      # plaintext, one worker per CPU
./miniircd -p 6697 -c cert.pem -k key.pem   # TLS
./miniircd -p 6667 -t 4 -A users.passwd -L  # 4 workers, require login
./miniircd -p 6667 -d                   # daemonize into the background
```

`-h` lists every option. The server runs one worker thread per core, each with
its own `SO_REUSEPORT` listener so the kernel spreads connections across
workers; shared IRC state is guarded by a single mutex.

Two limits bound abuse from a single source: `-P N` caps concurrent connections
per source IP (default 8), and `-R SEC` drops a connection that has not
registered within the deadline (default 30s), so an idle unregistered session
is reclaimed without waiting out the ping cycle. With TLS, `-H SEC` bounds how
long a connection may sit in the handshake (default 10s), so a stalled handshake
cannot hold a slot indefinitely.

## Configuration

The uircd library takes its settings as a struct (`struct uircd_config` passed
to `uircd_new`); that is its settings API, and it reads no files. A host that
would rather not name each struct field can set settings by string key with
`uircd_config_set(&cfg, "max-clients", "2048")`, which parses and validates the
value (see `uircd.h` for the key list). The example host adds its own settings
and wires both to a gitconfig-style file, so the config format lives in the
host, not the library.

```sh
./miniircd -f miniircd.conf              # read settings from a file
./miniircd -f miniircd.conf -p 6697      # file settings, port overridden
```

Command-line options override the file. `./miniircd -C -f miniircd.conf` parses
and checks a configuration then exits, without binding a port. `example/miniircd.conf`
is a documented sample; the sections are `[server]` (name, network, motd), `[listen]` (port,
ipv6), `[tls]` (cert, key, handshake-timeout), `[auth]` (passwd, require-login),
and `[limits]` (threads, accept-backoff-ms, max-per-ip, reg-timeout,
max-clients, max-channels, ping-interval, ping-timeout, flood-lines,
flood-window). Times are in seconds;
an omitted key keeps the built-in default. `-h` lists every command-line option.

## Authentication

With `-A <file>` the example verifies `PASS` and `OPER` credentials against a
passwd file of scrypt hashes. Generate entries with the bundled tool:

```sh
./uircdpasswd alice c            # a login account (prompts for the password)
./uircdpasswd admin o operpass   # an operator account
./uircdpasswd '*' c              # a shared connection password (bare PASS)
```

Each line is `name:scrypt:N:r:p:salt_b64:hash_b64:flags`, flags being `c` (may
connect) and `o` (may become an operator). Append the lines to your passwd
file. Clients log in with `PASS account:password`; `-L` makes a valid login
mandatory to connect.

## Administrative commands

An operator (`OPER name pass`) gains these, in addition to `KILL`:

| Command | Effect |
| --- | --- |
| `KLINE <term> [:reason]` | ban and disconnect everything matching a term |
| `UNKLINE <term>` | remove a ban |
| `GKILL <query> [:reason]` | mass-disconnect clients matching a query |
| `BANLIST` | list active bans |

The same operations are available to a host directly: `uircd_ban_add`,
`uircd_ban_del`, `uircd_kill_match`, `uircd_ban_list`.

### Match terms and the query language

A query is a space-separated AND of terms, each `field=glob` or `field!=glob`:

- fields: `nick user host ip real chan account`
- `glob` supports `*` (any run) and `?` (one character)
- `ip` terms also accept CIDR, e.g. `ip=10.0.0.0/8`
- `chan` matches a client that is in a channel matching the glob

Examples:

```
KLINE ip=203.0.113.*                 ban a /24 by wildcard
KLINE ip=10.0.0.0/8 :go away         ban a /8 by CIDR
GKILL nick=bot* user=~*              drop every unidented bot*
GKILL chan=#spam real=*VirusBot*     drop spammers in one channel
```

Both KLINE bans and GKILL honor a `field!=glob` negation.

## Security

This code carries a HARDEN review: see [`HARDEN.md`](HARDEN.md) for the finding
ledger, [`HARDEN/`](HARDEN) for the reviewer reports, and
[`HARDEN/harness/`](HARDEN/harness) for runnable falsifiers. Report
vulnerabilities per [`SECURITY.md`](SECURITY.md).
