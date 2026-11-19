/* kline_self_uaf.c : falsifier for UIRCD-001
 *
 * An IRC operator who KLINEs a ban that matches their own connection causes
 * uircd_ban_add() to free the operator's client, after which cmd_kline()
 * still dereferences it. This harness drives the real uircd.c through its
 * public API to that point.
 *
 * While the finding is OPEN this reproduces the use-after-free: AddressSanitizer
 * aborts inside the KLINE handling. Once fixed, the handler returns without
 * touching the freed client and the harness prints "survived".
 *
 * Build:
 *   cc -fsanitize=address,undefined -fno-omit-frame-pointer -g -std=c11 \
 *      -D_GNU_SOURCE -I../.. kline_self_uaf.c -o kline_self_uaf
 * Run:
 *   ./kline_self_uaf    # prints "survived" when UIRCD-001 is fixed
 */

#include "uircd.h"
#include "../../uircd.c"

#include <stdio.h>
#include <string.h>

static void
h_out(void *ud, void *conn, const void *data, size_t len)
{
    (void)ud; (void)conn; (void)data; (void)len;
}

static void
h_drop(void *ud, void *conn)
{
    (void)ud; (void)conn;
}

static int
h_auth(void *ud, enum uircd_auth_kind kind, const char *name, const char *pass)
{
    (void)ud; (void)name; (void)pass;
    return kind == UIRCD_AUTH_OPER ? UIRCD_OK : UIRCD_ERR;
}

static int
feed(struct uircd *s, struct uircd_client *c, const char *line)
{
    return uircd_recv(s, c, line, strlen(line));
}

int
main(void)
{
    struct uircd_config cfg;
    struct uircd *s;
    struct uircd_client *c;

    memset(&cfg, 0, sizeof(cfg));
    cfg.server_name = "test.local";
    cfg.out = h_out;
    cfg.drop = h_drop;
    cfg.auth = h_auth;
    s = uircd_new(&cfg);
    if (!s) {
        fprintf(stderr, "uircd_new failed\n");
        return 2;
    }
    c = uircd_accept(s, (void *)"conn", "203.0.113.7");
    if (!c) {
        fprintf(stderr, "accept failed\n");
        return 2;
    }

    feed(s, c, "NICK op\r\n");
    feed(s, c, "USER op 0 * :Operator\r\n");
    feed(s, c, "OPER admin secret\r\n");

    /* The operator bans their own IP. uircd_ban_add frees c; a buggy
     * cmd_kline then dereferences it. */
    if (feed(s, c, "KLINE ip=203.0.113.7 :self ban\r\n") == UIRCD_ERR) {
        /* client was (correctly) destroyed by the self-ban; do not touch c */
        printf("survived\n");
        uircd_free(s);
        return 0;
    }

    /* If we get here the client was not killed by its own ban; that is also
     * safe. */
    printf("survived\n");
    uircd_free(s);
    return 0;
}
