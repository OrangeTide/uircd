# uircd API

The public API is the single header `uircd.h`. This document is the narrative
reference; `uircd.h` has the authoritative signatures and per-field comments.

## Stability

This API is not frozen. It may change between releases, including in
incompatible ways, and the project does not promise to freeze it at any
particular version. The authentication callback, for example, changed shape
during early development. If you vendor the library, pin a specific commit or
release tag and read the CHANGELOG before upgrading.

## The model

uircd is an IRC server protocol engine with no networking of its own. The host
owns the sockets:

- The host feeds received bytes in with `uircd_recv()`.
- The engine parses IRC, tracks clients and channels, enforces bans and
  authentication, and decides what to send and when to drop a connection.
- The engine sends bytes out by calling the host's `out()` callback, and asks
  the host to close a connection by calling `drop()`.

The engine is **not thread-safe**. A multithreaded host must serialize every
`uircd_*` call and every callback for one engine behind a single lock. See
`example/miniircd` for a threaded host that does this.

## Using it

The library is two files with no dependencies of its own: add `uircd.c` to your
build and include `uircd.h`. A C11 compiler is enough; `uircd.c` needs no
pthreads, OpenSSL, or platform libraries (the example host does, for its
sockets and TLS, but the engine does not).

## Constants and types

- `UIRCD_OK` (0), `UIRCD_ERR` (-1): the usual success/failure returns.
- `UIRCD_AUTH_PENDING` (1): an auth callback returns this to defer its verdict.
- `struct uircd`: an opaque engine instance.
- `struct uircd_client`: an opaque per-connection handle.
- `enum uircd_auth_kind`: `UIRCD_AUTH_USER` (a connection login) or
  `UIRCD_AUTH_OPER` (an `OPER` command).

## Configuration

Fill a `struct uircd_config` and pass it to `uircd_new()`. The config is copied,
but string pointers are stored as-is and must outlive the engine. `out` and
`drop` are required; `auth` and `log` may be NULL. Unset numeric fields (0) take
built-in defaults.

Notable fields:

- `server_name`, `network`, `motd`, `version`: identity shown to clients.
- `require_login`: if nonzero, a client must authenticate before registering.
- `max_clients`, `max_channels`, `max_per_ip`, `reg_timeout_ms`, the ping and
  flood settings: limits and timeouts.
- `host_cloak`, `cloak_key`: enable host cloaking and supply its secret key (see
  below). These are set on the struct directly; `uircd_config_set()` does not
  cover them.
- `out`, `drop`, `auth`, `log`, `ud`: the callbacks and the opaque user pointer
  passed back to each.

`uircd_config_set(cfg, key, value)` applies one setting by string key before
`uircd_new()`, so a host can wire a config file or command line without naming
each struct field. It handles the string and numeric keys listed in `uircd.h`
(not the callbacks, `ud`, or the cloak fields). String values are stored, not
copied, so they too must outlive the engine.

## Lifecycle and connection flow

All of it is driven by the host:

1. `uircd_new(cfg)` creates the engine (NULL on failure).
2. On each accepted socket, `uircd_accept(s, host_conn, peer_ip)` returns a
   client handle. `host_conn` is your opaque per-connection pointer, handed back
   to `out()`/`drop()`. `peer_ip` is a printable address, copied, used for bans
   and logging. A NULL return means the connection was refused (server full,
   per-IP cap, or a ban); the engine has already emitted an ERROR and asked for
   `drop()`, so just run your normal close path.
3. `uircd_recv(s, c, data, len)` feeds received bytes. It returns `UIRCD_ERR` if
   the client was destroyed during processing (QUIT, flood, fatal error, ban);
   after that the handle is dead, do not touch it, and the engine has already
   asked for `drop()`.
4. `uircd_tick(s, now_ms)` runs periodic maintenance (PING idle clients, drop
   ping-timeouts and overdue unregistered sessions). Call it about once a second
   with a monotonic millisecond clock.
5. `uircd_closed(s, c)` tells the engine a connection is gone (peer closed, I/O
   error, or you finished the `drop()` it asked for). Call it exactly once per
   client, and never after `uircd_recv()` returned `UIRCD_ERR` for that client.
6. `uircd_free(s)` destroys the engine.

A minimal integration sketch (single-threaded, error handling elided):

```c
struct uircd_config cfg = {
    .server_name = "irc.example",
    .out = on_out, .drop = on_drop, .ud = host,
};
struct uircd *s = uircd_new(&cfg);

/* on a new connection: */
struct uircd_client *c = uircd_accept(s, conn, "203.0.113.4");

/* on readable data: */
if (uircd_recv(s, c, buf, n) == UIRCD_ERR)
    close_and_forget(conn);   /* do not call uircd_closed() in this case */

/* once a second: */
uircd_tick(s, monotonic_ms());

/* when the socket closes: */
uircd_closed(s, c);

/* at shutdown: */
uircd_free(s);
```

## Callbacks

- `out(ud, conn, data, len)`: queue bytes for a peer. May be called several
  times per input. Must not block; buffer and write asynchronously.
- `drop(ud, conn)`: flush, then close the socket and call `uircd_closed()`. The
  engine will not reference `conn` again after this.
- `log(ud, event, detail)`: optional. `event` is a short stable tag
  (`connect`, `register`, `quit`, `oper`, `ban`, `kill`); `detail` may be NULL.
  Note that `detail` can contain a client's real address.
- `auth(ud, conn, kind, name, pass)`: verify a credential. See below.

### Authentication, synchronous or deferred

The auth callback returns `UIRCD_OK` to accept or `UIRCD_ERR` to reject right
away. A NULL callback means no user login is required, and `OPER` always fails.

To verify off the hot path (a slow KDF, a network lookup), return
`UIRCD_AUTH_PENDING`. The engine parks the client, holding its further input,
and the host finishes later by calling `uircd_auth_complete(s, c, ok)` exactly
once. The engine then resumes as if the callback had returned that verdict
synchronously and replays the held input. At most one auth is in flight per
client. The `pass` pointer is valid only for the duration of the call, so a host
that defers must copy what it needs, and must route the verdict back using its
own `conn` handle (the client pointer may be unsafe to hold across threads).
`uircd_auth_complete()` is a no-op if the client is not awaiting a verdict, and
must not be called after `uircd_closed()` for that client.

### Host cloaking

With `host_cloak` set, the host a client shows to other users (in `WHO`,
`WHOIS`, and the `nick!user@host` prefix) is a keyed hash of the real address,
`<hex>.cloak`. Operators still see real addresses in `WHO`/`WHOIS`, and bans and
the log always use the real address, so cloaking is display-only. Set
`cloak_key` from a random source so the cloak cannot be reversed; a per-run key
is enough (the example host draws it from the OS on startup).

## Administrative extensions

These let a host manage bans and mass-disconnects outside the IRC command path
(for example from an admin socket). A match query is a space-separated AND of
`field=glob` or `field!=glob` terms, where field is one of
`nick user host ip real chan account`; see `uircd.h` for the glob and CIDR
rules and examples.

- `uircd_ban_add(s, spec, reason)`: add a persistent ban from one match term;
  kills currently matching clients. Returns the number killed, or `UIRCD_ERR`.
- `uircd_ban_del(s, spec)`: remove a ban whose spec matches exactly.
- `uircd_ban_list(s, out, max)`: count bans and optionally copy their specs.
- `uircd_kill_match(s, query, reason)`: disconnect every client matching a
  query. Returns the number killed, or `UIRCD_ERR`.
- `uircd_client_count(s)`: current number of connected clients.

## Thread safety, restated

One engine is a single-threaded world. If several threads touch the same engine
(as in the example host, which runs a worker per core), every `uircd_*` call and
every callback for that engine must run under one lock. Separate engines are
independent.
