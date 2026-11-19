/* dispatch_fuzz.c : randomized fuzzer for the engine's command dispatch
 *
 * The IRC command handlers in uircd.c are the richest untrusted-input surface:
 * every registered or unregistered client can send arbitrary lines that reach
 * JOIN/MODE/KICK/KILL/KLINE/WHO/TOPIC/... with attacker-chosen parameters. The
 * earlier rounds reviewed these by hand and with targeted harnesses (H-001,
 * H-004, H-005); this driver feeds randomized and malformed command lines at a
 * pool of clients under AddressSanitizer + UndefinedBehaviorSanitizer to shake
 * out memory errors the hand review may have missed.
 *
 * It drives the real uircd.c through its public API (uircd_recv), stubbing the
 * host. It keeps a pool of clients, registers and opers some of them, then in a
 * long loop builds a random line (a real command with random-length parameters,
 * raw bytes, over-long lines, split writes, pipelines) and feeds it to a random
 * live client. Client lifetime is tracked precisely: the engine frees a client
 * when it quits it (client_quit calls drop() then client_free()), so a slot is
 * marked dead both when drop() fires for it and when uircd_recv() returns
 * UIRCD_ERR, and the freed pointer is never touched again. It also ticks the
 * clock occasionally to exercise the ping/registration-timeout/flood paths.
 *
 * A clean run prints "survived"; a memory error aborts under the sanitizer.
 * The run is deterministic for a given seed, so a crash reproduces.
 *
 * Build:
 *   cc -fsanitize=address,undefined -fno-omit-frame-pointer -g -std=c11 \
 *      -D_GNU_SOURCE -I../.. dispatch_fuzz.c -o dispatch_fuzz
 * Run:
 *   ./dispatch_fuzz [iterations] [seed]      # defaults: 200000 iterations, seed 1
 */

#include "uircd.h"
#include "../../uircd.c"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define POOL 24

static struct uircd_client *g_cl[POOL];
static int g_alive[POOL];

/* deterministic PRNG */
static uint64_t g_rng = 1;

static uint64_t
rnd(void)
{
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 7;
    g_rng ^= g_rng << 17;
    return g_rng;
}

static unsigned
rrange(unsigned n)
{
    return n ? (unsigned)(rnd() % n) : 0;
}

/* The engine calls drop() when it quits a client; the pointer is freed right
 * after, so mark the slot dead by the host_conn index we passed to accept. */
static void
h_drop(void *ud, void *conn)
{
    intptr_t i = (intptr_t)conn;
    (void)ud;
    if (i >= 0 && i < POOL) {
        g_alive[i] = 0;
        g_cl[i] = NULL;
    }
}

static void
h_out(void *ud, void *conn, const void *data, size_t len)
{
    (void)ud; (void)conn; (void)data; (void)len;
}

static int
h_auth(void *ud, void *conn, enum uircd_auth_kind kind, const char *name,
       const char *pass)
{
    (void)ud; (void)conn; (void)kind; (void)name; (void)pass;
    return UIRCD_OK; /* accept everything so clients can register and oper */
}

static void
h_log(void *ud, const char *event, const char *detail)
{
    (void)ud; (void)event; (void)detail;
}

/* Append a random token of 0..maxlen bytes. With mode 0 use printable ASCII,
 * with mode 1 include raw control bytes, with mode 2 lean on separators that
 * stress the parser (spaces, colons, commas, bangs, at-signs). */
static size_t
tok(char *p, size_t cap, unsigned maxlen, int mode)
{
    size_t n = rrange(maxlen + 1), i;

    if (n > cap)
        n = cap;
    for (i = 0; i < n; i++) {
        unsigned char c;
        if (mode == 1) {
            c = (unsigned char)(1 + rrange(254)); /* any byte but NUL/implicit */
        } else if (mode == 2) {
            static const char sep[] = "::,, !!@@##**+-abcXYZ09";
            c = (unsigned char)sep[rrange(sizeof(sep) - 1)];
        } else {
            c = (unsigned char)(33 + rrange(94)); /* printable */
        }
        p[i] = (char)c;
    }
    return n;
}

static const char *const CMDS[] = {
    "NICK", "USER", "PASS", "QUIT", "PING", "OPER", "JOIN", "PART",
    "PRIVMSG", "NOTICE", "TOPIC", "NAMES", "LIST", "WHO", "MODE", "KICK",
    "KILL", "KLINE", "UNKLINE", "GKILL", "BANLIST", "CAP", "WHOIS", "",
};

/* Build one random line (without CRLF) into buf, return its length. */
static size_t
build_line(char *buf, size_t cap)
{
    size_t n = 0;
    unsigned nargs, a;
    int bytemode = (rrange(8) == 0) ? 1 : 0; /* sometimes raw bytes */

    if (rrange(16) == 0) {
        /* pure garbage line */
        return tok(buf, cap, (unsigned)(rrange(600)), 1);
    }

    /* command token */
    {
        const char *cmd = CMDS[rrange(sizeof(CMDS) / sizeof(CMDS[0]))];
        size_t cl = strlen(cmd);
        if (cl > cap)
            cl = cap;
        memcpy(buf, cmd, cl);
        n = cl;
    }

    nargs = rrange(6);
    for (a = 0; a < nargs && n + 1 < cap; a++) {
        buf[n++] = ' ';
        /* last arg sometimes a trailing ":..." parameter */
        if (a == nargs - 1 && rrange(2) && n + 1 < cap)
            buf[n++] = ':';
        /* occasionally a channel-ish or comma list token */
        if (rrange(3) == 0 && n + 1 < cap)
            buf[n++] = (rrange(2) ? '#' : '&');
        n += tok(buf + n, cap - n, (unsigned)(10 + rrange(320)),
                 rrange(3) == 0 ? 2 : bytemode);
    }
    return n;
}

/* (re)spawn a dead slot: accept a client, maybe register and oper it. */
static void
spawn(struct uircd *s, int i)
{
    char reg[128];
    int n;

    g_cl[i] = uircd_accept(s, (void *)(intptr_t)i, "198.51.100.1");
    if (!g_cl[i])
        return;
    g_alive[i] = 1;

    if (rrange(4) == 0)
        return; /* leave some unregistered */

    n = snprintf(reg, sizeof(reg), "NICK n%d\r\nUSER u 0 * :r\r\n", i);
    if (uircd_recv(s, g_cl[i], reg, (size_t)n) == UIRCD_ERR) {
        g_alive[i] = 0; g_cl[i] = NULL; return;
    }
    if (rrange(3) == 0) {
        const char *op = "OPER admin secret\r\n";
        if (uircd_recv(s, g_cl[i], op, strlen(op)) == UIRCD_ERR) {
            g_alive[i] = 0; g_cl[i] = NULL;
        }
    }
}

int
main(int argc, char **argv)
{
    struct uircd_config cfg;
    struct uircd *s;
    long iters = (argc > 1) ? atol(argv[1]) : 200000;
    uint64_t clock = 1000;
    long it;
    int i;

    if (argc > 2)
        g_rng = (uint64_t)strtoull(argv[2], NULL, 0);
    if (g_rng == 0)
        g_rng = 1;

    memset(&cfg, 0, sizeof(cfg));
    cfg.server_name = "fuzz.local";
    cfg.out = h_out;
    cfg.drop = h_drop;
    cfg.auth = h_auth;
    cfg.log = h_log;
    cfg.max_per_ip = 0;        /* all clients share one IP in this driver */
    s = uircd_new(&cfg);
    if (!s) {
        fprintf(stderr, "uircd_new failed\n");
        return 2;
    }

    for (i = 0; i < POOL; i++)
        spawn(s, i);

    for (it = 0; it < iters; it++) {
        char line[1200];
        size_t n;
        int w;

        i = (int)rrange(POOL);
        if (!g_alive[i] || !g_cl[i]) {
            if (rrange(2) == 0)
                spawn(s, i);
            continue;
        }

        n = build_line(line, sizeof(line) - 2);
        /* usually terminate the line; sometimes leave it dangling to test
         * inbuf accumulation across recv calls */
        if (rrange(8) != 0) {
            line[n++] = '\r';
            line[n++] = '\n';
        }

        /* sometimes split the bytes across two recv calls */
        if (n > 4 && rrange(3) == 0) {
            size_t cut = 1 + rrange((unsigned)(n - 1));
            if (uircd_recv(s, g_cl[i], line, cut) == UIRCD_ERR) {
                g_alive[i] = 0; g_cl[i] = NULL; continue;
            }
            if (!g_alive[i] || !g_cl[i])
                continue;
            if (uircd_recv(s, g_cl[i], line + cut, n - cut) == UIRCD_ERR) {
                g_alive[i] = 0; g_cl[i] = NULL; continue;
            }
        } else {
            if (uircd_recv(s, g_cl[i], line, n) == UIRCD_ERR) {
                g_alive[i] = 0; g_cl[i] = NULL; continue;
            }
        }

        /* occasionally advance the clock to exercise tick() paths */
        if (rrange(64) == 0) {
            clock += 1000 + rrange(200000);
            uircd_tick(s, clock);
        }
        /* occasionally close a live client ourselves */
        if (rrange(128) == 0) {
            w = (int)rrange(POOL);
            if (g_alive[w] && g_cl[w]) {
                uircd_closed(s, g_cl[w]);
                g_alive[w] = 0; g_cl[w] = NULL;
            }
        }
    }

    /* tear down whatever is still alive */
    for (i = 0; i < POOL; i++)
        if (g_alive[i] && g_cl[i])
            uircd_closed(s, g_cl[i]);
    uircd_free(s);

    printf("survived\n");
    return 0;
}
