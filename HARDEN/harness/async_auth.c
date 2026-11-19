/* async_auth.c : falsifier for the deferred-authentication path (H-013)
 *
 * Drives the real uircd.c through its public API down the UIRCD_AUTH_PENDING /
 * uircd_auth_complete() path, single-threaded (no KDF pool needed: this tests
 * the engine contract, not the host's threading). It checks that:
 *
 *   A. a PENDING verdict parks the client and holds its further input, and a
 *      later accept replays the held NICK/USER to complete registration;
 *   B. a PENDING reject under require_login drops the client through the held
 *      USER's try_register, with no touch of the freed client afterward;
 *   C. input past the hold cap during a pending verdict drops the client
 *      cleanly (no leak, no use-after-free);
 *   D. closing a client while its verdict is still pending frees it, hold
 *      buffer and all, without a completion call;
 *   E. a deferred OPER verdict grants operator on accept;
 *   F. after a PASS is handled the plaintext password is wiped from the
 *      engine's input buffer, not left to linger (H-018).
 *
 * Under AddressSanitizer + UndefinedBehaviorSanitizer any leak of the hold
 * buffer or use-after-free aborts; a correct engine prints "survived".
 *
 * Build:
 *   cc -fsanitize=address,undefined -fno-omit-frame-pointer -g -std=c11 \
 *      -D_GNU_SOURCE -I../.. async_auth.c -o async_auth
 * Run:
 *   ./async_auth
 */

#include "uircd.h"
#include "../../uircd.c"

#include <stdio.h>
#include <string.h>

/* Callback behavior, set per scenario. */
static enum { SYNC_OK, PEND_USER, PEND_OPER } g_mode;
static int g_dropped;

static void
h_out(void *ud, void *conn, const void *data, size_t len)
{
    (void)ud; (void)conn; (void)data; (void)len;
}

static void
h_drop(void *ud, void *conn)
{
    (void)ud; (void)conn;
    g_dropped = 1;
}

static int
h_auth(void *ud, void *conn, enum uircd_auth_kind kind, const char *name,
       const char *pass)
{
    (void)ud; (void)conn; (void)name; (void)pass;
    if (g_mode == PEND_USER && kind == UIRCD_AUTH_USER)
        return UIRCD_AUTH_PENDING;
    if (g_mode == PEND_OPER && kind == UIRCD_AUTH_OPER)
        return UIRCD_AUTH_PENDING;
    return UIRCD_OK;
}

static struct uircd *
new_srv(int require_login)
{
    struct uircd_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.server_name = "test.local";
    cfg.require_login = require_login;
    cfg.out = h_out;
    cfg.drop = h_drop;
    cfg.auth = h_auth;
    return uircd_new(&cfg);
}

static int
feed(struct uircd *s, struct uircd_client *c, const char *line)
{
    return uircd_recv(s, c, line, strlen(line));
}

static void
fail(const char *what)
{
    fprintf(stderr, "FAIL: %s\n", what);
    /* exit nonzero; the make check harness treats any non-"survived" as failure */
    exit(1);
}

/* A: deferred accept replays held NICK/USER and completes registration. */
static void
scenario_accept(void)
{
    struct uircd *s = new_srv(1);
    struct uircd_client *c;

    g_mode = PEND_USER;
    g_dropped = 0;
    c = uircd_accept(s, (void *)"A", "203.0.113.1");
    if (!c) fail("A: accept");

    /* PASS defers; NICK and USER must be held, not processed. */
    feed(s, c, "PASS acct:pw\r\nNICK nn\r\nUSER nn 0 * :Real\r\n");
    if (c->auth_pending != 1) fail("A: not pending after PASS");
    if (c->registered) fail("A: registered before verdict");
    if (c->got_nick || c->got_user) fail("A: held input was processed early");

    uircd_auth_complete(s, c, 1);
    if (c->auth_pending) fail("A: still pending after complete");
    if (!c->authed) fail("A: not authed after accept");
    if (!c->registered) fail("A: not registered after held NICK/USER replay");
    if (strcmp(c->acct, "acct") != 0) fail("A: account name not set");

    uircd_closed(s, c);
    uircd_free(s);
}

/* B: deferred reject under require_login drops the client via the held USER. */
static void
scenario_reject(void)
{
    struct uircd *s = new_srv(1);
    struct uircd_client *c;

    g_mode = PEND_USER;
    g_dropped = 0;
    c = uircd_accept(s, (void *)"B", "203.0.113.2");
    if (!c) fail("B: accept");

    feed(s, c, "PASS acct:bad\r\nNICK nn\r\nUSER nn 0 * :Real\r\n");
    if (!c->auth_pending) fail("B: not pending");

    /* Reject: the replayed USER's try_register fails require_login and quits the
     * client, so the drop callback fires and c is freed. Do not touch c after. */
    uircd_auth_complete(s, c, 0);
    if (!g_dropped) fail("B: client not dropped on reject");

    uircd_free(s); /* c already freed by the quit; must not double-free */
}

/* C: input past the hold cap during a pending verdict drops the client. */
static void
scenario_overflow(void)
{
    struct uircd *s = new_srv(0);
    struct uircd_client *c;
    char big[8192];
    int rc;

    g_mode = PEND_USER;
    g_dropped = 0;
    c = uircd_accept(s, (void *)"C", "203.0.113.3");
    if (!c) fail("C: accept");

    feed(s, c, "PASS acct:pw\r\n");
    if (!c->auth_pending) fail("C: not pending");

    /* A flood larger than HOLD_MAX while the verdict is outstanding. */
    memset(big, 'x', sizeof(big));
    rc = uircd_recv(s, c, big, sizeof(big));
    if (rc != UIRCD_ERR) fail("C: oversized hold not rejected");
    if (!g_dropped) fail("C: client not dropped on hold overflow");

    uircd_free(s);
}

/* D: closing a client mid-pending frees it (hold buffer and all). */
static void
scenario_close_pending(void)
{
    struct uircd *s = new_srv(1);
    struct uircd_client *c;

    g_mode = PEND_USER;
    c = uircd_accept(s, (void *)"D", "203.0.113.4");
    if (!c) fail("D: accept");

    /* Leave a non-empty hold buffer, then close without completing. */
    feed(s, c, "PASS acct:pw\r\nNICK nn\r\n");
    if (!c->auth_pending) fail("D: not pending");
    if (!c->hold || c->hold_len == 0) fail("D: expected held input");

    uircd_closed(s, c); /* must free c->hold; ASan catches a leak */
    uircd_free(s);
}

/* E: a deferred OPER verdict grants operator. */
static void
scenario_oper(void)
{
    struct uircd *s = new_srv(0);
    struct uircd_client *c;

    g_mode = PEND_OPER; /* USER auth returns OK; OPER defers */
    c = uircd_accept(s, (void *)"E", "203.0.113.5");
    if (!c) fail("E: accept");

    feed(s, c, "NICK nn\r\nUSER nn 0 * :Real\r\n");
    if (!c->registered) fail("E: not registered");

    feed(s, c, "OPER admin secret\r\n");
    if (!c->auth_pending) fail("E: OPER not pending");
    if (c->umodes & UMODE_OPER) fail("E: oper granted before verdict");

    uircd_auth_complete(s, c, 1);
    if (!(c->umodes & UMODE_OPER)) fail("E: oper not granted on accept");

    uircd_closed(s, c);
    uircd_free(s);
}

/* F: after a PASS is handled, the plaintext password does not linger in the
 * engine's input buffer (H-018). */
static void
scenario_scrub(void)
{
    struct uircd *s = new_srv(0);
    struct uircd_client *c;
    static const char sentinel[] = "Zq7sentinelPWq7Z";

    g_mode = SYNC_OK; /* PASS accepts immediately; the client stays alive */
    c = uircd_accept(s, (void *)"F", "203.0.113.6");
    if (!c) fail("F: accept");

    feed(s, c, "PASS acct:Zq7sentinelPWq7Z\r\n");
    if (!c->authed) fail("F: PASS not accepted");

    /* The raw line sat in c->inbuf; the scrub must have zeroed it. On an engine
     * that does not wipe, the sentinel is still present and this aborts. */
    if (memmem(c->inbuf, sizeof(c->inbuf), sentinel, strlen(sentinel)) != NULL)
        fail("F: plaintext password still in c->inbuf after PASS");

    uircd_closed(s, c);
    uircd_free(s);
}

int
main(void)
{
    scenario_accept();
    scenario_reject();
    scenario_overflow();
    scenario_close_pending();
    scenario_oper();
    scenario_scrub();
    printf("survived\n");
    return 0;
}
