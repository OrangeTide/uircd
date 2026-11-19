/* conn_cap.c : falsifier for UIRCD-002
 *
 * One source IP must not be able to hold unlimited connection slots, and an
 * accepted connection that never registers must be reclaimed on a seconds-scale
 * deadline rather than waiting out the full ping cycle. This harness drives the
 * real uircd.c through its public API to check both.
 *
 * It discriminates:
 *   - Per-IP cap: with max_per_ip = N, the N+1th uircd_accept() from one IP
 *     returns NULL (refused) while a first connection from another IP is still
 *     accepted. Without the cap the N+1th would be accepted.
 *   - Registration deadline: an unregistered client is dropped by uircd_tick()
 *     once reg_timeout_ms has elapsed, well before ping_interval_ms. Without the
 *     deadline uircd_client_count() would not fall until the ping cycle.
 *
 * Prints "survived" when both hold; aborts via assert() otherwise.
 *
 * Build:
 *   cc -fsanitize=address,undefined -fno-omit-frame-pointer -g -std=c11 \
 *      -D_GNU_SOURCE -I../.. conn_cap.c -o conn_cap
 * Run:
 *   ./conn_cap    # prints "survived" when UIRCD-002 is fixed
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

#define CAP 4u

int
main(void)
{
    struct uircd_config cfg;
    struct uircd *s;
    struct uircd_client *c;
    unsigned i, before;

    memset(&cfg, 0, sizeof(cfg));
    cfg.server_name = "test.local";
    cfg.out = h_out;
    cfg.drop = h_drop;
    cfg.max_per_ip = CAP;
    cfg.reg_timeout_ms = 2000;
    s = uircd_new(&cfg);
    assert(s);

    /* CAP connections from one IP all succeed. */
    for (i = 0; i < CAP; i++) {
        c = uircd_accept(s, (void *)"a", "198.51.100.9");
        assert(c != NULL);
    }
    /* The next one from the same IP is refused. */
    c = uircd_accept(s, (void *)"a", "198.51.100.9");
    assert(c == NULL);

    /* A first connection from a different IP is still accepted. */
    c = uircd_accept(s, (void *)"b", "198.51.100.10");
    assert(c != NULL);

    /* None of the above registered. Advance the clock past the registration
     * deadline but not past the ping interval (default 120000ms). */
    before = uircd_client_count(s);
    assert(before == CAP + 1);
    assert(cfg.reg_timeout_ms < s->ping_interval_ms);

    uircd_tick(s, 1);                        /* stamp connect_ms */
    uircd_tick(s, cfg.reg_timeout_ms + 100); /* past the deadline */

    /* Every unregistered session was reclaimed by the deadline, not the ping
     * cycle. */
    assert(uircd_client_count(s) == 0);

    printf("survived\n");
    uircd_free(s);
    return 0;
}
