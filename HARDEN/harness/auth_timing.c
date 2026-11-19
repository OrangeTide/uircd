/* auth_timing.c : falsifier for the login timing side channel (H-003)
 *
 * A load driver, not a self-contained harness: it needs a running miniircd
 * started with a passwd file and require-login. It measures the response
 * latency of a rejected login for two cases:
 *
 *   known-bad : an account that EXISTS, with a wrong password. The host runs
 *               the scrypt KDF (~tens of ms) before rejecting.
 *   unknown   : a name that does NOT exist. The host runs no KDF.
 *
 * Each connection sends a single PASS and times the first response byte (the
 * 464). With asynchronous auth the verdict is delivered at a fixed deadline for
 * both cases, so the two latency distributions overlap: their medians differ by
 * much less than the KDF cost. A synchronous server (the pre-fix behavior, or
 * this server run with an auth deadline shorter than the KDF) answers the
 * unknown case immediately and the known-bad case only after the KDF, so the
 * medians separate by about the KDF time, which this harness flags.
 *
 * It prints the two distributions and a verdict, and exits 0 when they overlap
 * (the leak is closed) or 1 when they separate past the threshold.
 *
 * With -s the client speaks TLS (for a server started with -c/-k). The TLS
 * handshake is completed before the timed section, so the measurement is the
 * same request/response latency, just over an encrypted transport.
 *
 * Build:
 *   cc -O2 -g -std=c11 -D_GNU_SOURCE HARDEN/harness/auth_timing.c \
 *      -o /tmp/auth_timing -lssl -lcrypto
 *
 * Run (see HARDEN/harness/README.md for the two-sided discrimination check):
 *   ./uircdpasswd alice c secret > /tmp/t.passwd
 *   ./miniircd -p 7910 -A /tmp/t.passwd -L &
 *   /tmp/auth_timing 7910 alice ghost 200
 *   /tmp/auth_timing -s 7697 alice ghost 200    # TLS, server run with -c/-k
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

/* Measure, over one fresh connection, the time from sending a PASS line to the
 * first response byte, in milliseconds. With ctx non-NULL the connection speaks
 * TLS, handshaking before the timed section. Returns -1 on any I/O failure. */
static double
sample(int port, const char *name, SSL_CTX *ctx)
{
    int fd;
    struct sockaddr_in a;
    struct timeval tv = { 2, 0 };
    char line[128], buf[256];
    struct timespec t0, t1;
    SSL *ssl = NULL;
    ssize_t n;
    int len;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
        close(fd);
        return -1;
    }

    if (ctx) {
        /* Blocking socket: SSL_connect completes the handshake in one call.
         * Done before t0, so handshake cost is excluded from the measurement. */
        ssl = SSL_new(ctx);
        if (!ssl) {
            close(fd);
            return -1;
        }
        SSL_set_fd(ssl, fd);
        if (SSL_connect(ssl) != 1) {
            SSL_free(ssl);
            close(fd);
            return -1;
        }
    }

    len = snprintf(line, sizeof(line), "PASS %s:wrongpassword\r\n", name);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (ssl ? (SSL_write(ssl, line, len) != len)
            : (write(fd, line, (size_t)len) != len)) {
        if (ssl) SSL_free(ssl);
        close(fd);
        return -1;
    }
    /* first byte of the 464 reply */
    n = ssl ? SSL_read(ssl, buf, sizeof(buf)) : recv(fd, buf, sizeof(buf), 0);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (ssl)
        SSL_free(ssl);
    close(fd);
    if (n <= 0)
        return -1;
    return (double)(t1.tv_sec - t0.tv_sec) * 1000.0 +
           (double)(t1.tv_nsec - t0.tv_nsec) / 1e6;
}

static int
cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

struct stats {
    double median, mean, lo, hi;
    int n;
};

static struct stats
summarize(double *v, int n)
{
    struct stats s = { 0, 0, 0, 0, n };
    double sum = 0;
    int i;

    qsort(v, (size_t)n, sizeof(*v), cmp_double);
    for (i = 0; i < n; i++)
        sum += v[i];
    s.mean = sum / n;
    s.median = (n & 1) ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2.0;
    s.lo = v[0];
    s.hi = v[n - 1];
    return s;
}

int
main(int argc, char **argv)
{
    int port, want, i, opt, use_tls = 0;
    const char *known, *unknown;
    double threshold = 40.0;   /* ms; well below a KDF-sized (~60ms) leak */
    double *tk, *tu;
    int nk = 0, nu = 0;
    struct stats sk, su;
    double gap;
    SSL_CTX *ctx = NULL;

    while ((opt = getopt(argc, argv, "s")) != -1) {
        if (opt == 's')
            use_tls = 1;
        else
            return 2;
    }
    if (argc - optind < 4) {
        fprintf(stderr,
            "usage: %s [-s] PORT KNOWN_NAME UNKNOWN_NAME SAMPLES [THRESHOLD_MS]\n"
            "  -s           speak TLS (server started with -c/-k)\n"
            "  KNOWN_NAME must exist in the server's passwd file (with 'c');\n"
            "  UNKNOWN_NAME must not. The server must run with -L.\n", argv[0]);
        return 2;
    }
    port = atoi(argv[optind]);
    known = argv[optind + 1];
    unknown = argv[optind + 2];
    want = atoi(argv[optind + 3]);
    if (argc - optind > 4)
        threshold = atof(argv[optind + 4]);
    if (want < 1)
        want = 1;

    signal(SIGPIPE, SIG_IGN);
    if (use_tls) {
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            ERR_print_errors_fp(stderr);
            return 2;
        }
        /* The server's cert is self-signed in test use; we measure timing, not
         * authenticate the peer, so verification is intentionally off. */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
    tk = calloc((size_t)want, sizeof(*tk));
    tu = calloc((size_t)want, sizeof(*tu));
    if (!tk || !tu) {
        fprintf(stderr, "out of memory\n");
        return 2;
    }

    /* Interleave the two cases so any drift in load hits both equally. */
    for (i = 0; i < want; i++) {
        double a = sample(port, known, ctx);
        double b = sample(port, unknown, ctx);
        if (a >= 0)
            tk[nk++] = a;
        if (b >= 0)
            tu[nu++] = b;
    }
    if (nk < want / 2 || nu < want / 2) {
        fprintf(stderr, "too many failed samples (known %d/%d, unknown %d/%d);"
                " is the server up with -L and the passwd file?\n",
                nk, want, nu, want);
        return 2;
    }

    sk = summarize(tk, nk);
    su = summarize(tu, nu);
    gap = sk.median - su.median;
    if (gap < 0)
        gap = -gap;

    printf("known-bad (%-12s) n=%d  median=%.1fms mean=%.1fms range=[%.1f,%.1f]\n",
           known, sk.n, sk.median, sk.mean, sk.lo, sk.hi);
    printf("unknown   (%-12s) n=%d  median=%.1fms mean=%.1fms range=[%.1f,%.1f]\n",
           unknown, su.n, su.median, su.mean, su.lo, su.hi);
    printf("median gap = %.1fms  threshold = %.1fms\n", gap, threshold);

    free(tk);
    free(tu);
    if (ctx)
        SSL_CTX_free(ctx);

    if (gap <= threshold) {
        printf("PASS: distributions overlap; login timing does not separate "
               "known from unknown names\n");
        return 0;
    }
    printf("FAIL: known-bad and unknown logins separate by ~%.0fms; timing "
           "enumerates account names\n", gap);
    return 1;
}
