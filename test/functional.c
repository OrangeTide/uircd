/* functional.c : functional test suite for the uircd engine
 *
 * Unlike the HARDEN harnesses (which check memory safety) and dispatch_fuzz
 * (which checks the engine does not crash), this suite checks the engine does
 * the right thing: correct numerics, message routing, channel operator rules,
 * nick collisions, authentication, and host cloaking. It drives the real
 * uircd.c through uircd_recv and asserts on the bytes the engine sends to each
 * client, so it is deterministic and needs no sockets.
 *
 * Build and run:
 *   cc -O2 -g -std=c11 -D_GNU_SOURCE -I.. test/functional.c -o functional
 *   ./functional          # prints "ALL TESTS PASSED" and exits 0, else 1
 *
 * Or: make test
 */

#include "uircd.h"
#include "../uircd.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Per-client output capture, keyed by the small id passed as host_conn. */
#define MAXC 8
static char g_cap[MAXC][65536];
static size_t g_len[MAXC];

static int g_checks, g_fails;

/* Auth callback behavior for the auth tests. */
static enum { AUTH_NONE, AUTH_OK, AUTH_FAIL } g_auth = AUTH_NONE;

static void
h_out(void *ud, void *conn, const void *data, size_t len)
{
    long id = (long)conn;
    (void)ud;
    if (id < 0 || id >= MAXC)
        return;
    if (g_len[id] + len < sizeof(g_cap[id])) {
        memcpy(g_cap[id] + g_len[id], data, len);
        g_len[id] += len;
        g_cap[id][g_len[id]] = '\0';
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
    return g_auth == AUTH_OK ? UIRCD_OK : UIRCD_ERR;
}

static void
clear(long id)
{
    g_len[id] = 0;
    g_cap[id][0] = '\0';
}

/* Assertions. want: the client's captured output contains sub. wantnot: it
 * must not. Each counts as one check; a failure is reported, not fatal, so the
 * whole suite runs and the total is printed. */
static void
want(long id, const char *sub, const char *what)
{
    g_checks++;
    if (!strstr(g_cap[id], sub)) {
        g_fails++;
        fprintf(stderr, "FAIL: %s\n  wanted substring: %s\n  in: %.200s\n",
                what, sub, g_cap[id]);
    }
}

static void
wantnot(long id, const char *sub, const char *what)
{
    g_checks++;
    if (strstr(g_cap[id], sub)) {
        g_fails++;
        fprintf(stderr, "FAIL: %s\n  did not want substring: %s\n  in: %.200s\n",
                what, sub, g_cap[id]);
    }
}

static struct uircd *
new_srv(int require_login)
{
    struct uircd_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.server_name = "irc.test";
    cfg.network = "testnet";
    cfg.require_login = require_login;
    cfg.host_cloak = 1;
    cfg.cloak_key = 0xfeedfacecafebeefULL;
    cfg.out = h_out;
    cfg.drop = h_drop;
    cfg.auth = (g_auth == AUTH_NONE) ? NULL : h_auth;
    return uircd_new(&cfg);
}

static void
feed(struct uircd *s, struct uircd_client *c, const char *line)
{
    uircd_recv(s, c, line, strlen(line));
}

/* Accept and register a client with id `id` and the given nick. */
static struct uircd_client *
reg(struct uircd *s, long id, const char *nick)
{
    char buf[128];
    struct uircd_client *c = uircd_accept(s, (void *)id, "198.51.100.7");
    if (!c) {
        fprintf(stderr, "FAIL: accept id=%ld\n", id);
        exit(1);
    }
    snprintf(buf, sizeof(buf), "NICK %s\r\nUSER u 0 * :Real Name\r\n", nick);
    feed(s, c, buf);
    return c;
}

static void
test_registration(void)
{
    struct uircd *s = new_srv(0);
    struct uircd_client *a = reg(s, 0, "alice");

    want(0, " 001 ", "registration sends welcome 001");
    want(0, " 004 ", "registration sends 004");
    want(0, " 005 ", "registration sends ISUPPORT 005");
    want(0, "testnet", "005 advertises the network name");

    clear(0);
    feed(s, a, "FROB please\r\n");
    want(0, " 421 ", "unknown command gives 421");

    clear(0);
    feed(s, a, "PING :tok123\r\n");
    want(0, "PONG", "PING gets a PONG");
    want(0, "tok123", "PONG echoes the token");

    uircd_closed(s, a);
    uircd_free(s);
}

static void
test_channel_and_routing(void)
{
    struct uircd *s = new_srv(0);
    struct uircd_client *a = reg(s, 0, "anna");
    struct uircd_client *b;

    clear(0);
    feed(s, a, "JOIN #room\r\n");
    want(0, "JOIN", "JOIN is echoed to the joiner");
    want(0, " 353 ", "JOIN sends the names list 353");
    want(0, " 366 ", "JOIN sends end-of-names 366");

    /* second client joins: the first sees the broadcast */
    b = reg(s, 1, "bret");
    clear(0);
    clear(1);
    feed(s, b, "JOIN #room\r\n");
    want(0, "bret", "an existing member sees a new member's JOIN");
    want(0, "JOIN", "the JOIN broadcast reaches other members");

    /* channel message routing: others receive, sender does not echo */
    clear(0);
    clear(1);
    feed(s, b, "PRIVMSG #room :hello all\r\n");
    want(0, "PRIVMSG #room :hello all", "a channel message reaches other members");
    wantnot(1, "hello all", "the sender does not receive its own channel message");

    /* direct message to a nick */
    clear(0);
    feed(s, b, "PRIVMSG anna :psst\r\n");
    want(0, "PRIVMSG anna :psst", "a direct message reaches the target nick");

    /* nick collision and a valid change broadcast */
    clear(1);
    feed(s, b, "NICK anna\r\n");
    want(1, " 433 ", "a duplicate nick is refused with 433");
    clear(0);
    clear(1);
    feed(s, b, "NICK brenda\r\n");
    want(0, "NICK", "a channel peer sees a nick change");
    want(0, "brenda", "the nick change carries the new nick");

    uircd_closed(s, a);
    uircd_closed(s, b);
    uircd_free(s);
}

static void
test_operator_rules(void)
{
    struct uircd *s = new_srv(0);
    struct uircd_client *a = reg(s, 0, "op");     /* first joiner -> chan op */
    struct uircd_client *b = reg(s, 1, "reg");

    feed(s, a, "JOIN #c\r\n");
    feed(s, b, "JOIN #c\r\n");

    /* a non-op cannot set the topic on a +t channel */
    clear(1);
    feed(s, b, "TOPIC #c :mine\r\n");
    want(1, " 482 ", "a non-op setting the topic gets 482");

    /* the channel op can set it, and members see the change */
    clear(0);
    clear(1);
    feed(s, a, "TOPIC #c :welcome\r\n");
    want(1, "TOPIC #c :welcome", "the op's topic change reaches members");

    /* the op can kick the other member */
    clear(0);
    clear(1);
    feed(s, a, "KICK #c reg :out\r\n");
    want(1, "KICK #c", "a kicked member is told it was kicked");
    want(0, "KICK #c", "other members see the kick");

    uircd_closed(s, a);
    uircd_closed(s, b);
    uircd_free(s);
}

static void
test_quit_broadcast(void)
{
    struct uircd *s = new_srv(0);
    struct uircd_client *a = reg(s, 0, "stay");
    struct uircd_client *b = reg(s, 1, "goer");

    feed(s, a, "JOIN #hall\r\n");
    feed(s, b, "JOIN #hall\r\n");

    clear(0);
    feed(s, b, "QUIT :leaving\r\n"); /* frees b */
    want(0, "QUIT", "a channel peer sees a QUIT");
    want(0, "goer", "the QUIT names the departing user");

    uircd_closed(s, a);
    uircd_free(s);
}

static void
test_cloak_visibility(void)
{
    struct uircd *s = new_srv(0);
    struct uircd_client *a = reg(s, 0, "viewer");

    clear(0);
    feed(s, a, "WHO viewer\r\n");
    want(0, ".cloak", "a non-operator's WHO shows a cloak");
    wantnot(0, "198.51.100.7", "a non-operator's WHO hides the real IP");

    uircd_closed(s, a);
    uircd_free(s);
}

static void
test_whois(void)
{
    struct uircd *s;
    struct uircd_client *probe, *tgt, *op, *vic;

    /* non-operator: cloak, channels, and 401 for an unknown nick */
    s = new_srv(0);
    probe = reg(s, 0, "probe");
    tgt = reg(s, 1, "tgt");
    feed(s, tgt, "JOIN #x\r\n");
    clear(0);
    feed(s, probe, "WHOIS tgt\r\n");
    want(0, " 311 ", "WHOIS sends the user line 311");
    want(0, " 319 ", "WHOIS sends the channels line 319");
    want(0, "#x", "WHOIS lists the target's channel");
    want(0, " 318 ", "WHOIS ends with 318");
    want(0, ".cloak", "a non-operator WHOIS shows the cloak");
    wantnot(0, "198.51.100.7", "a non-operator WHOIS hides the real IP");

    clear(0);
    feed(s, probe, "WHOIS nobody\r\n");
    want(0, " 401 ", "WHOIS of an unknown nick gives 401");
    want(0, " 318 ", "WHOIS of an unknown nick still ends with 318");
    uircd_closed(s, probe);
    uircd_closed(s, tgt);
    uircd_free(s);

    /* operator: WHOIS shows the real IP */
    g_auth = AUTH_OK;
    s = new_srv(0);
    op = uircd_accept(s, (void *)0, "198.51.100.7");
    feed(s, op, "NICK op\r\nUSER u 0 * :R\r\nOPER admin pw\r\n");
    vic = reg(s, 1, "vic");
    (void)vic;
    clear(0);
    feed(s, op, "WHOIS vic\r\n");
    want(0, " 311 ", "an operator WHOIS sends 311");
    want(0, "198.51.100.7", "an operator WHOIS shows the real IP");
    uircd_closed(s, op);
    uircd_free(s);
    g_auth = AUTH_NONE;
}

static void
test_auth_accept(void)
{
    struct uircd *s;
    struct uircd_client *a;

    g_auth = AUTH_OK;
    s = new_srv(1);
    a = uircd_accept(s, (void *)0, "198.51.100.7");
    clear(0);
    feed(s, a, "PASS secret\r\nNICK user\r\nUSER u 0 * :R\r\n");
    want(0, " 001 ", "a good login registers");

    clear(0);
    feed(s, a, "OPER admin pw\r\n");
    want(0, " 381 ", "OPER grants operator on a sync accept");

    uircd_closed(s, a);
    uircd_free(s);
    g_auth = AUTH_NONE;
}

static void
test_auth_reject(void)
{
    struct uircd *s;
    struct uircd_client *a;

    g_auth = AUTH_FAIL;
    s = new_srv(1);
    a = uircd_accept(s, (void *)0, "198.51.100.7");
    clear(0);
    feed(s, a, "PASS wrong\r\n");
    want(0, " 464 ", "a bad login is refused with 464");
    wantnot(0, " 001 ", "a refused login does not register");

    uircd_closed(s, a);
    uircd_free(s);
    g_auth = AUTH_NONE;
}

int
main(void)
{
    test_registration();
    test_channel_and_routing();
    test_operator_rules();
    test_quit_broadcast();
    test_cloak_visibility();
    test_whois();
    test_auth_accept();
    test_auth_reject();

    printf("%d checks, %d failed\n", g_checks, g_fails);
    if (g_fails == 0) {
        printf("ALL TESTS PASSED\n");
        return 0;
    }
    return 1;
}
