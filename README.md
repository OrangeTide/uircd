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

See [`API.md`](API.md) for the full API reference (types, callbacks, lifecycle,
the deferred-auth flow, and the admin functions). The API is not frozen and may
change between releases.

## Building

```sh
make                # optimized build: ./miniircd and ./uircdpasswd
make SANITIZE=1     # AddressSanitizer + UndefinedBehaviorSanitizer build
make check          # build and run the HARDEN falsifiers under sanitizers
make test           # build and run the functional test suite under sanitizers
make install        # install binaries, man pages, and a sample config
make clean
```

Requirements: a C11 compiler, pthreads, and OpenSSL (`libssl`/`libcrypto`) for
the example's TLS. The core (`uircd.c`) itself needs none of these.

`make install` installs `miniircd` to `$(PREFIX)/sbin`, `uircdpasswd` to
`$(PREFIX)/bin`, the man pages (`miniircd.8`, `uircdpasswd.1`), and a sample
config under `$(PREFIX)/share/doc/uircd`. `PREFIX` defaults to `/usr/local`;
override it, the individual directories, or `DESTDIR` for a staged packaging
install. `make uninstall` removes them.

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
ipv6), `[tls]` (cert, key, handshake-timeout), `[auth]` (passwd, require-login,
auth-deadline-ms, auth-jitter-ms, kdf-threads), `[privacy]` (host-cloak), and
`[limits]` (threads, accept-backoff-ms, max-per-ip, reg-timeout, max-clients,
max-channels, ping-interval, ping-timeout, flood-lines, flood-window). Times in `[limits]` are
in seconds; the `[auth]` deadline and jitter are in milliseconds, as their names
say. An omitted key keeps the built-in default. `-h` lists every command-line
option.

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

The example verifies logins asynchronously. Its auth callback returns
`UIRCD_AUTH_PENDING`, running scrypt in a small off-lock thread pool
(`[auth] kdf-threads`) so one login never stalls the engine, and it answers
every attempt at a fixed deadline (`[auth] auth-deadline-ms` plus up to
`auth-jitter-ms`) whether or not a hash was checked, so response timing does not
reveal which account names exist. The deadline must exceed the slowest
configured scrypt; the default (120 ms) suits the tool's default work factors.
The library's `uircd_auth_cb` supports this through the `UIRCD_AUTH_PENDING`
verdict and `uircd_auth_complete()`; a host that returns only `UIRCD_OK`/`UIRCD_ERR`
is still verified synchronously.

Size `[auth] kdf-threads` to the number of logins you expect to be verified at
once. Each scrypt verification holds one pool thread for its full cost (tens of
milliseconds at the default work factors), so the pool verifies at most
`kdf-threads` logins per that interval. When concurrent logins exceed that rate
the pool's queue backs up, the per-attempt deadline timer re-arms in short steps
until a result is ready, and logins that cannot be answered within the retry
window are failed closed rather than left hanging. This is deliberate flood
protection, but it also slows every login during the burst. Two settings trade
off against it: more `kdf-threads` raises the steady verification rate (bounded
by available cores, since scrypt is CPU-bound), and a larger `auth-deadline-ms`
widens the window before a queued login is failed closed. A useful starting
point is one thread per core you are willing to spend on login verification,
with the deadline left at its default unless the slowest configured scrypt needs
more. Under-provisioning does not corrupt state or leak a wrong verdict; it only
raises login latency and, past deep saturation, rejects logins that time out.
The timing-equalization property degrades gracefully under this saturation: the
known-bad and unknown paths slow together, so the gap stays small until the pool
is heavily overloaded (see finding H-014 in `HARDEN.md`), and provisioning
`kdf-threads` for the expected concurrent-login rate keeps it closed.

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

### Privacy

The server and library make no outbound connections and send nothing off the
machine: no telemetry, no crash reports, no update or license checks. The only
data that leaves a process is IRC traffic to connected clients and whatever the
operator's `log` callback writes locally.

A connecting user's IP address is recorded in the operator log (the example logs
a `connect` event with the peer address). To other users it is cloaked by
default: the host shown in `WHO`/`WHOIS` and in the `nick!user@host` message
prefix is a keyed hash of the real address, `<hex>.cloak`, from which the real
address cannot be recovered. An operator still sees real addresses in
`WHO`/`WHOIS`, and bans
(`KLINE`) always match the real address, so cloaking is display-only. The key is
random per server run, so a user's cloak is stable within a run and changes on
restart. Set `[privacy] host-cloak = false` to show raw IPs instead, the older
behavior. The operator log always records real addresses; treat it accordingly.
See finding H-016 in [`HARDEN.md`](HARDEN.md).
