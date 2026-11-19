/* tls_fuzz.c : adversarial TLS record-layer input for miniircd (UIRCD-010).
 *
 * mode "fuzz"      : each connection sends a random malformed/partial TLS
 *                    pattern (random bytes, truncated records, oversized length
 *                    fields, drip-fed bytes, record-shaped noise) then closes.
 *                    Run the server under ASan+UBSan; it must not crash, report,
 *                    busy-loop, or stop serving legitimate clients.
 * mode "slowloris" : open N connections, send a partial TLS record header and
 *                    hold them open without completing the handshake.
 *
 * A driver, not a self-contained harness: it needs a running TLS server.
 *
 *   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
 *       -days 1 -nodes -subj /CN=localhost
 *   make SANITIZE=1
 *   ./miniircd -p 7930 -t 2 -c cert.pem -k key.pem -P 2 &   SRV=$!
 *   cc -O2 -pthread -w HARDEN/harness/tls_fuzz.c -o /tmp/tls_fuzz
 *
 *   # slowloris: half-open handshakes accumulate past the per-IP cap; count the
 *   # server's open sockets while they are held, then again after the handshake
 *   # deadline (HANDSHAKE_TIMEOUT_MS, 10s):
 *   /tmp/tls_fuzz 7930 slowloris 200 16 &
 *   sleep 3  ; ls /proc/$SRV/fd | wc -l   # ~baseline+200 (held)
 *   sleep 10 ; ls /proc/$SRV/fd | wc -l   # back to baseline after the fix
 *
 *   # malformed records: must leave no ASan/UBSan report:
 *   for r in 1 2 3 4 5; do /tmp/tls_fuzz 7930 fuzz 300; done
 *
 * Before the fix the slowloris sockets are never reclaimed (the per-IP cap and
 * registration deadline do not apply to a handshake). After the fix they drop
 * back to baseline within the handshake deadline.
 *
 * usage: tls_fuzz <port> <fuzz|slowloris> <connections> <slowloris-hold-sec>
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int g_port, g_conns, g_arg;
static const char *g_mode;

static int
tcp_connect(void)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    if (s < 0) return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)g_port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(s);
        return -1;
    }
    return s;
}

static unsigned
xrand(unsigned *st)
{
    *st = *st * 1103515245u + 12345u;
    return (*st >> 16) & 0x7fff;
}

static void *
fuzz_worker(void *arg)
{
    long id = (long)arg;
    unsigned st = (unsigned)(id * 2654435761u) ^ (unsigned)time(NULL);
    int s = tcp_connect();
    unsigned char buf[65536];
    int pattern = (int)(xrand(&st) % 6);
    size_t i, n;

    if (s < 0) return NULL;
    switch (pattern) {
    case 0: /* random bytes */
        n = 1 + xrand(&st) % 400;
        for (i = 0; i < n; i++) buf[i] = (unsigned char)xrand(&st);
        (void)!write(s, buf, n);
        break;
    case 1: /* TLS handshake record header, truncated body */
        buf[0] = 0x16; buf[1] = 0x03; buf[2] = 0x01;
        buf[3] = 0x01; buf[4] = 0x00; /* claims 256 bytes */
        n = 5 + xrand(&st) % 20;      /* send far fewer */
        for (i = 5; i < n; i++) buf[i] = (unsigned char)xrand(&st);
        (void)!write(s, buf, n);
        break;
    case 2: /* oversized length field */
        buf[0] = 0x16; buf[1] = 0x03; buf[2] = 0x01;
        buf[3] = 0xff; buf[4] = 0xff; /* claims 65535 bytes */
        (void)!write(s, buf, 5 + xrand(&st) % 8);
        break;
    case 3: /* plausible ClientHello prefix then garbage */
        buf[0] = 0x16; buf[1] = 0x03; buf[2] = 0x01; buf[3] = 0x00;
        buf[4] = 0x30; buf[5] = 0x01; buf[6] = 0x00; buf[7] = 0x00;
        for (i = 8; i < 40; i++) buf[i] = (unsigned char)xrand(&st);
        (void)!write(s, buf, 40);
        break;
    case 4: /* drip one byte at a time */
        for (i = 0; i < 12; i++) {
            unsigned char b = (i < 3)
                ? (unsigned char)((i == 0) ? 0x16 : 0x03)
                : (unsigned char)xrand(&st);
            if (write(s, &b, 1) < 0) break;
            usleep(5000);
        }
        break;
    case 5: /* large burst of record-shaped noise */
        for (i = 0; i < sizeof(buf); i += 5) {
            buf[i] = 0x16; buf[i+1] = 0x03; buf[i+2] = 0x01;
            buf[i+3] = (unsigned char)xrand(&st);
            buf[i+4] = (unsigned char)xrand(&st);
        }
        (void)!write(s, buf, sizeof(buf));
        break;
    }
    close(s);
    return NULL;
}

static void *
slow_worker(void *arg)
{
    long id = (long)arg;
    int s = tcp_connect();
    unsigned char hdr[6] = { 0x16, 0x03, 0x01, 0x00, 0x50, 0x01 };
    (void)id;
    if (s < 0) return NULL;
    (void)!write(s, hdr, sizeof(hdr)); /* partial handshake record */
    sleep(g_arg);                      /* hold open, never complete */
    close(s);
    return NULL;
}

int
main(int argc, char **argv)
{
    long i;
    pthread_t *th;
    void *(*fn)(void *);

    signal(SIGPIPE, SIG_IGN);
    g_port = argc > 1 ? atoi(argv[1]) : 7930;
    g_mode = argc > 2 ? argv[2] : "fuzz";
    g_conns = argc > 3 ? atoi(argv[3]) : 300;
    g_arg = argc > 4 ? atoi(argv[4]) : 4; /* slowloris hold seconds */

    fn = strcmp(g_mode, "slowloris") == 0 ? slow_worker : fuzz_worker;
    th = calloc((size_t)g_conns, sizeof(*th));
    for (i = 0; i < g_conns; i++)
        pthread_create(&th[i], NULL, fn, (void *)i);
    for (i = 0; i < g_conns; i++)
        pthread_join(th[i], NULL);
    free(th);
    printf("tls_fuzz: mode=%s conns=%d done\n", g_mode, g_conns);
    return 0;
}
