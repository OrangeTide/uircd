/* host_cloak.c : falsifier for host cloaking (H-016)
 *
 * With cloaking on, a user's real IP must not reach other users: the host shown
 * in WHO and in the nick!user@host message prefix must be the cloak, not the
 * real address. An operator still sees the real host in WHO, and with cloaking
 * off the real host is shown as before. This drives the real uircd.c through its
 * public API, capturing the bytes the engine sends to a client, and asserts each
 * case. It discriminates: against an engine that does not cloak, the raw IP
 * appears in the captured output and an assertion fails.
 *
 * Build:
 *   cc -fsanitize=address,undefined -fno-omit-frame-pointer -g -std=c11 \
 *      -D_GNU_SOURCE -I../.. host_cloak.c -o host_cloak
 * Run:
 *   ./host_cloak      # prints "survived"
 */

#include "uircd.h"
#include "../../uircd.c"

#include <stdio.h>
#include <string.h>

static char g_cap[65536];
static size_t g_caplen;

static void
cap_reset(void)
{
    g_caplen = 0;
    g_cap[0] = '\0';
}

static void
h_out(void *ud, void *conn, const void *data, size_t len)
{
    (void)ud; (void)conn;
    if (g_caplen + len < sizeof(g_cap)) {
        memcpy(g_cap + g_caplen, data, len);
        g_caplen += len;
        g_cap[g_caplen] = '\0';
    }
}

static void
h_drop(void *ud, void *conn)
{
    (void)ud; (void)conn;
}

static int
h_auth(void *ud, void *conn, enum uircd_auth_kind kind, const char *name,
       const char *pass)
{
    (void)ud; (void)conn; (void)kind; (void)name; (void)pass;
    return UIRCD_OK;
}

static void
fail(const char *what)
{
    fprintf(stderr, "FAIL: %s\n  captured: %s\n", what, g_cap);
    exit(1);
}

static struct uircd *
new_srv(int cloak)
{
    struct uircd_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.server_name = "test.local";
    cfg.out = h_out;
    cfg.drop = h_drop;
    cfg.auth = h_auth;
    cfg.host_cloak = cloak;
    cfg.cloak_key = 0x0123456789abcdefULL;
    return uircd_new(&cfg);
}

static struct uircd_client *
reg_client(struct uircd *s, const char *ip, const char *nick, int oper)
{
    char buf[160];
    int n;
    struct uircd_client *c = uircd_accept(s, (void *)nick, ip);
    if (!c)
        fail("accept");
    n = snprintf(buf, sizeof(buf), "NICK %s\r\nUSER u 0 * :r\r\n", nick);
    uircd_recv(s, c, buf, (size_t)n);
    if (!c->registered)
        fail("register");
    if (oper) {
        const char *op = "OPER admin secret\r\n";
        uircd_recv(s, c, op, strlen(op));
        if (!(c->umodes & UMODE_OPER))
            fail("oper");
    }
    return c;
}

int
main(void)
{
    struct uircd *s;
    struct uircd_client *c;
    static const char ip[] = "203.0.113.9";

    /* 1. Cloaking on: the raw IP must not appear in a JOIN prefix echoed to the
     *    client, and the cloak must. */
    s = new_srv(1);
    c = reg_client(s, ip, "bob", 0);
    cap_reset();
    uircd_recv(s, c, "JOIN #x\r\n", strlen("JOIN #x\r\n"));
    if (strstr(g_cap, ip))
        fail("1: raw IP in JOIN prefix under cloaking");
    if (!strstr(g_cap, ".cloak"))
        fail("1: cloak missing from JOIN prefix");

    /* 2. Cloaking on: a non-operator WHO shows the cloak, not the raw IP. */
    cap_reset();
    uircd_recv(s, c, "WHO bob\r\n", strlen("WHO bob\r\n"));
    if (strstr(g_cap, ip))
        fail("2: raw IP in WHO for a non-operator");
    if (!strstr(g_cap, ".cloak"))
        fail("2: cloak missing from WHO");
    uircd_closed(s, c);
    uircd_free(s);

    /* 3. Cloaking on: an operator WHO shows the real IP. */
    s = new_srv(1);
    c = reg_client(s, ip, "op", 1);
    cap_reset();
    uircd_recv(s, c, "WHO op\r\n", strlen("WHO op\r\n"));
    if (!strstr(g_cap, ip))
        fail("3: operator did not see the real IP in WHO");
    uircd_closed(s, c);
    uircd_free(s);

    /* 4. Cloaking off: the real IP is shown as before. */
    s = new_srv(0);
    c = reg_client(s, ip, "carol", 0);
    cap_reset();
    uircd_recv(s, c, "WHO carol\r\n", strlen("WHO carol\r\n"));
    if (!strstr(g_cap, ip))
        fail("4: raw IP missing with cloaking off");
    if (strstr(g_cap, ".cloak"))
        fail("4: cloak present with cloaking off");
    uircd_closed(s, c);
    uircd_free(s);

    printf("survived\n");
    return 0;
}
