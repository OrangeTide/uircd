/* ban_negation.c : falsifier for UIRCD-005
 *
 * The match grammar accepts a "field!=glob" negation. GKILL/uircd_kill_match
 * honor it, but uircd_ban_add and client_banned used to match with a routine
 * that ignored the negation, so a negated KLINE spec banned the complement of
 * the intended set. This harness drives the real uircd.c through its public
 * API to check that a negated ban removes the right client.
 *
 * It adds the ban "nick!=keep" with two clients connected, keep and other, and
 * asserts that other (the one that does NOT match "keep") is the one removed.
 * Before the fix the ban removed keep instead; the assertions abort.
 *
 * Prints "survived" when the negation is applied to bans.
 *
 * Build:
 *   cc -fsanitize=address,undefined -fno-omit-frame-pointer -g -std=c11 \
 *      -D_GNU_SOURCE -I../.. ban_negation.c -o ban_negation
 * Run:
 *   ./ban_negation    # prints "survived" when UIRCD-005 is fixed
 */

#include "uircd.h"
#include "../../uircd.c"

#include <assert.h>
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

static struct uircd_client *
reg(struct uircd *s, const char *tag, const char *nick)
{
    struct uircd_client *c = uircd_accept(s, (void *)tag, "203.0.113.20");
    char line[128];
    assert(c);
    snprintf(line, sizeof(line), "NICK %s\r\n", nick);
    uircd_recv(s, c, line, strlen(line));
    snprintf(line, sizeof(line), "USER %s 0 * :%s\r\n", nick, nick);
    uircd_recv(s, c, line, strlen(line));
    assert(find_nick(s, nick) != NULL);
    return c;
}

int
main(void)
{
    struct uircd_config cfg;
    struct uircd *s;
    int killed;

    memset(&cfg, 0, sizeof(cfg));
    cfg.server_name = "test.local";
    cfg.out = h_out;
    cfg.drop = h_drop;
    s = uircd_new(&cfg);
    assert(s);

    reg(s, "k", "keep");
    reg(s, "o", "other");
    assert(uircd_client_count(s) == 2);

    /* Ban everyone whose nick is NOT "keep". Only "other" should go. */
    killed = uircd_ban_add(s, "nick!=keep", "negated");
    assert(killed == 1);
    assert(find_nick(s, "keep") != NULL);   /* keep stays */
    assert(find_nick(s, "other") == NULL);  /* other removed */
    assert(uircd_client_count(s) == 1);

    printf("survived\n");
    uircd_free(s);
    return 0;
}
