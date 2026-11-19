/* tls_reneg.c : TLS renegotiation / fragmentation load for miniircd.
 *
 * Exercises how the server's non-blocking SSL_read/SSL_write loops and handshake
 * driver cope with client-initiated renegotiation (TLS 1.2), TLS 1.3 key
 * updates, heavily fragmented records (smallest fragment + 3-byte writes),
 * one-byte-per-record writes, and a renegotiation flood. The record layer is
 * OpenSSL's and trusted; the target is miniircd's own I/O handling.
 *
 *   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
 *       -days 1 -nodes -subj /CN=localhost
 *   make SANITIZE=1     # and separately: make tsan
 *   setarch -R env TSAN_OPTIONS=halt_on_error=0 \
 *       ./miniircd -p 7960 -t 4 -c cert.pem -k key.pem &
 *   cc -O2 -g -pthread -w HARDEN/harness/tls_reneg.c -o /tmp/tls_reneg \
 *       -lssl -lcrypto
 *   for r in 1 2 3 4; do /tmp/tls_reneg 7960 250; done
 *
 * On the fixed tree the sanitizers report nothing, the server does not peg CPU,
 * and it keeps serving. The server also refuses renegotiation outright
 * (SSL_OP_NO_RENEGOTIATION): a TLS 1.2 SSL_renegotiate()+SSL_do_handshake() from
 * a client returns an error rather than completing a second handshake.
 *
 * usage: tls_reneg <port> <connections> */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static int g_port, g_conns;
static SSL_CTX *g_ctx12, *g_ctx13;

static int
tcp_connect(void)
{
    int s = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    struct sockaddr_in sa;
    struct timeval tv = { 2, 0 };
    if (s < 0) return -1;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)g_port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(s); return -1; }
    return s;
}

static void
reg_and_drain(SSL *ssl, long id)
{
    char buf[1024];
    snprintf(buf, sizeof(buf),
             "NICK r%ld\r\nUSER r%ld 0 * :r\r\nJOIN #r\r\n", id, id);
    SSL_write(ssl, buf, (int)strlen(buf));
    SSL_read(ssl, buf, sizeof(buf));
}

static void *
worker(void *arg)
{
    long id = (long)arg;
    int mode = (int)(id % 5);
    int s = tcp_connect();
    SSL *ssl;
    char buf[2048];
    int i;

    if (s < 0) return NULL;
    ssl = SSL_new(mode == 1 ? g_ctx13 : g_ctx12);
    if (!ssl) { close(s); return NULL; }
    SSL_set_fd(ssl, s);
    if (SSL_connect(ssl) != 1) { SSL_free(ssl); close(s); return NULL; }
    reg_and_drain(ssl, id);

    switch (mode) {
    case 0: /* TLS1.2 client-initiated renegotiation (server forbids it) */
        if (SSL_renegotiate(ssl) == 1)
            SSL_do_handshake(ssl);
        SSL_write(ssl, "PRIVMSG #r :after-reneg\r\n", 25);
        SSL_read(ssl, buf, sizeof(buf));
        break;
    case 1: /* TLS1.3 key update */
        SSL_key_update(ssl, SSL_KEY_UPDATE_REQUESTED);
        SSL_write(ssl, "PRIVMSG #r :after-keyupd\r\n", 26);
        SSL_read(ssl, buf, sizeof(buf));
        break;
    case 2: /* fragmentation: smallest record + split writes */
        SSL_set_max_send_fragment(ssl, 512);
        for (i = 0; i < 40; i++) {
            const char *m = "PRIVMSG #r :fragmented-line-of-text\r\n";
            size_t off = 0, len = strlen(m);
            while (off < len) {           /* write 3 bytes per record */
                int n = SSL_write(ssl, m + off, (len - off) > 3 ? 3 : (int)(len - off));
                if (n <= 0) break;
                off += (size_t)n;
            }
        }
        break;
    case 3: /* tiny records: one byte per SSL_write */
        {
            const char *m = "PRIVMSG #r :byte-by-byte\r\n";
            size_t len = strlen(m), k;
            for (k = 0; k < len; k++)
                if (SSL_write(ssl, m + k, 1) <= 0) break;
        }
        break;
    default: /* renegotiation flood */
        for (i = 0; i < 8; i++) {
            if (SSL_renegotiate(ssl) != 1) break;
            if (SSL_do_handshake(ssl) <= 0) break;
        }
        SSL_write(ssl, "QUIT :bye\r\n", 11);
        break;
    }
    if (id & 1) SSL_shutdown(ssl);  /* mix clean and abrupt closes */
    SSL_free(ssl);
    close(s);
    return NULL;
}

static SSL_CTX *
mkctx(int v)
{
    SSL_CTX *c = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(c, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_min_proto_version(c, v);
    SSL_CTX_set_max_proto_version(c, v);
    return c;
}

int
main(int argc, char **argv)
{
    long i;
    pthread_t *th;
    signal(SIGPIPE, SIG_IGN);
    g_port  = argc > 1 ? atoi(argv[1]) : 7960;
    g_conns = argc > 2 ? atoi(argv[2]) : 200;
    SSL_library_init();
    g_ctx12 = mkctx(TLS1_2_VERSION);
    g_ctx13 = mkctx(TLS1_3_VERSION);
    th = calloc((size_t)g_conns, sizeof(*th));
    for (i = 0; i < g_conns; i++)
        pthread_create(&th[i], NULL, worker, (void *)i);
    for (i = 0; i < g_conns; i++)
        pthread_join(th[i], NULL);
    free(th);
    SSL_CTX_free(g_ctx12);
    SSL_CTX_free(g_ctx13);
    printf("tls_reneg: %d conns done\n", g_conns);
    return 0;
}
