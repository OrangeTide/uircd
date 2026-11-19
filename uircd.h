/* uircd.h : compact, network-agnostic IRC server core */

#ifndef UIRCD_H
#define UIRCD_H

#include <stddef.h>
#include <stdint.h>

/*
 * uircd is an IRC server protocol engine with no networking of its own.
 *
 * The host owns the sockets. It feeds received bytes in with uircd_recv() and
 * sends bytes out through the out() callback. The engine parses IRC messages,
 * tracks clients and channels, enforces bans and authentication, and decides
 * what to send and when to drop a connection.
 *
 * The engine is NOT thread-safe. A multithreaded host must serialize every
 * uircd_* call and every callback behind a single lock. See example/miniircd.
 */

#define UIRCD_OK  (0)
#define UIRCD_ERR (-1)

struct uircd;
struct uircd_client;

/****************************************************************
 * Host callbacks
 ****************************************************************/

/** Kind of credential the engine is asking the host to verify. */
enum uircd_auth_kind {
    UIRCD_AUTH_USER, /* connection login: PASS <pass>, or account:pass */
    UIRCD_AUTH_OPER, /* OPER <name> <pass> */
};

/** Queue bytes for delivery to a connection's peer.
 *
 * conn is the opaque handle the host passed to uircd_accept(). The engine may
 * call this many times for one input. The host buffers and writes the bytes;
 * it must not block.
 */
typedef void (*uircd_out_cb)(void *ud, void *conn,
                             const void *data, size_t len);

/** Ask the host to close a connection once queued output has drained.
 *
 * After this the engine will not reference conn again. The host should flush
 * any buffered output, then close the socket and call uircd_closed().
 */
typedef void (*uircd_drop_cb)(void *ud, void *conn);

/** Verify a credential. Return UIRCD_OK to accept, UIRCD_ERR to reject.
 *
 * name is NULL for UIRCD_AUTH_USER when only a password was supplied. A NULL
 * callback means no user authentication is required; OPER always fails when
 * the callback is NULL.
 */
typedef int (*uircd_auth_cb)(void *ud, enum uircd_auth_kind kind,
                             const char *name, const char *pass);

/** Optional notification hook for logging and admin visibility.
 *
 * event is a short stable tag ("connect", "register", "quit", "oper",
 * "ban", "kill"). detail is human-readable and may be NULL.
 */
typedef void (*uircd_log_cb)(void *ud, const char *event,
                             const char *detail);

/****************************************************************
 * Configuration
 ****************************************************************/

struct uircd_config {
    const char *server_name;   /* our name in messages, e.g. irc.local */
    const char *network;       /* NETWORK= token in RPL_ISUPPORT */
    const char *motd;          /* message of the day, may be NULL */
    const char *version;       /* server version string, may be NULL */

    int require_login;         /* nonzero: a client must authenticate (PASS
                                * or account) before it may register */

    unsigned ping_interval_ms; /* 0 -> default; idle time before PING */
    unsigned ping_timeout_ms;  /* 0 -> default; wait for PONG before drop */

    unsigned max_clients;      /* 0 -> default */
    unsigned max_channels;     /* 0 -> default */
    unsigned flood_lines;      /* 0 -> default; lines allowed per window */
    unsigned flood_window_ms;  /* 0 -> default */

    unsigned max_per_ip;       /* 0 -> default; concurrent connections allowed
                                * from one source IP. A further connection from
                                * an IP already at the cap is refused. */
    unsigned reg_timeout_ms;   /* 0 -> default; a connection that has not
                                * registered within this window is dropped,
                                * rather than waiting for the ping cycle. */

    uircd_out_cb out;          /* required */
    uircd_drop_cb drop;        /* required */
    uircd_auth_cb auth;        /* may be NULL */
    uircd_log_cb log;          /* may be NULL */
    void *ud;                  /* passed back to every callback */
};

/****************************************************************
 * Lifecycle
 ****************************************************************/

/** Create a server engine. The config is copied; its string pointers must
 *  remain valid for the engine's lifetime. Returns NULL on failure. */
struct uircd *uircd_new(const struct uircd_config *cfg);

/** Apply one setting to a config by string key, before uircd_new().
 *
 * This lets a host wire a config file or command line without naming each
 * struct field. Returns UIRCD_OK, or UIRCD_ERR for an unknown key or a value
 * that does not parse. The callbacks and ud are not settable this way.
 *
 * Keys (value shown in parentheses):
 *   server-name, network, motd, version   (string)
 *   require-login                          (0/1 or true/false/yes/no/on/off)
 *   ping-interval-ms, ping-timeout-ms      (unsigned)
 *   max-clients, max-channels              (unsigned)
 *   flood-lines, flood-window-ms           (unsigned)
 *   max-per-ip, reg-timeout-ms             (unsigned)
 *
 * A string key stores the pointer, not a copy, so value must remain valid for
 * the engine's lifetime, the same rule the config struct's string fields follow.
 */
int uircd_config_set(struct uircd_config *cfg, const char *key,
                     const char *value);

void uircd_free(struct uircd *s);

/****************************************************************
 * Connection flow (all driven by the host)
 ****************************************************************/

/** Register a newly accepted connection.
 *
 * host_conn is the opaque handle passed back to out()/drop(). peer_ip is a
 * printable numeric address (e.g. "203.0.113.4" or "2001:db8::1") used for
 * bans and logging; it is copied.
 *
 * Returns a client handle, or NULL if the connection was refused (server full,
 * per-IP cap reached, or a matching ban). On refusal the engine has already
 * emitted an ERROR line via out() and requested drop(), so the host only needs
 * to proceed with its normal close path.
 */
struct uircd_client *uircd_accept(struct uircd *s, void *host_conn,
                                  const char *peer_ip);

/** Feed received bytes for a client.
 *
 * Returns UIRCD_OK normally. Returns UIRCD_ERR if the client was destroyed
 * during processing (QUIT, flood, fatal protocol error, or a ban). After
 * UIRCD_ERR the client handle is dead: do not touch it again, and close the
 * socket. The engine will have requested drop() before returning UIRCD_ERR.
 */
int uircd_recv(struct uircd *s, struct uircd_client *c,
               const void *data, size_t len);

/** Tell the engine a connection is gone (peer closed, I/O error, or the host
 *  finished the drop() it was asked to perform). Destroys the client. Safe to
 *  call exactly once per client; never after uircd_recv() returned UIRCD_ERR. */
void uircd_closed(struct uircd *s, struct uircd_client *c);

/** Periodic maintenance: PING idle clients and drop ping-timeouts.
 *  Call roughly once per second with a monotonic millisecond clock. */
void uircd_tick(struct uircd *s, uint64_t now_ms);

/****************************************************************
 * Administrative extensions
 *
 * A match query is a space-separated AND of terms. Each term is
 *   field=glob   or   field!=glob
 * where field is one of: nick user host ip real chan account.
 * glob supports '*' (any run) and '?' (one char); matching on nick/user/
 * host/chan/account is case-insensitive per RFC1459. A "chan" term matches a
 * client that is a member of a channel matching the glob.
 *
 * Examples:
 *   ip=203.0.113.*
 *   nick=bot* user=~*
 *   chan=#spam real=*VirusBot*
 *   ip=10.0.0.0/8            (CIDR is accepted for ip terms)
 ****************************************************************/

/** Add a persistent ban from a single match term ("ip=1.2.3.*",
 *  "host=*.evil.net"). Any currently connected client that matches is killed.
 *  Returns the number of clients killed, or UIRCD_ERR on a malformed spec. */
int uircd_ban_add(struct uircd *s, const char *spec, const char *reason);

/** Remove a ban whose spec matches exactly. Returns UIRCD_OK, or UIRCD_ERR if
 *  no such ban exists. */
int uircd_ban_del(struct uircd *s, const char *spec);

/** Count the active bans; if out is non-NULL, write up to max spec strings
 *  (NUL-terminated) into it. Returns the total number of bans. */
int uircd_ban_list(struct uircd *s, const char **out, int max);

/** Disconnect every client matching a query. Returns the number killed, or
 *  UIRCD_ERR on a malformed query. reason may be NULL. */
int uircd_kill_match(struct uircd *s, const char *query, const char *reason);

/** Current number of registered + unregistered clients. */
unsigned uircd_client_count(const struct uircd *s);

#endif /* UIRCD_H */
