/* tls_load.c : concurrent TLS client load to exercise the miniircd handshake
 * and handshake-close paths under ThreadSanitizer. Mixes full handshakes with
 * aborted and garbage connections so drive_handshake's error/close paths run.
 *
 * Connection modes by thread id (id & 3):
 *   0  full TLS session, clean QUIT + SSL_shutdown
 *   1  full TLS session, socket dropped mid-flight (no clean shutdown)
 *   2  non-TLS garbage to the TLS port (handshake fails -> close during HS)
 *   3  TCP connect then immediate close (abort before the handshake completes)
 *
 * A driver, not a self-contained harness: it needs a running TLS server.
 *
 *   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
 *       -days 1 -nodes -subj /CN=localhost
 *   make tsan
 *   setarch -R env TSAN_OPTIONS=halt_on_error=0 \
 *       ./miniircd -p 7920 -t 4 -c cert.pem -k key.pem &
 *   cc -O2 -g -pthread -w HARDEN/harness/tls_load.c -o /tmp/tls_load \
 *       -lssl -lcrypto
 *   for r in 1 2 3; do /tmp/tls_load 7920 250 30; done
 *
 * On the fixed tree ThreadSanitizer reports nothing. setarch -R disables ASLR,
 * which TSan requires on some kernels.
 *
 * usage: tls_load <port> <connections> <messages-per-full-session>
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
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

static int g_port, g_conns, g_msgs;
static SSL_CTX *g_ctx;

static int
tcp_connect(void)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    struct timeval tv = { 1, 0 };
    if (s < 0) return -1;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
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

static void *
worker(void *arg)
{
    long id = (long)arg;
    int mode = (int)(id & 3);
    int s = tcp_connect();
    char buf[2048];
    int i;

    if (s < 0) return NULL;

    if (mode == 3) {            /* abort immediately, before any handshake */
        close(s);
        return NULL;
    }
    if (mode == 2) {            /* speak non-TLS garbage to the TLS port */
        (void)!write(s, "GARBAGE NOT TLS\r\n", 17);
        (void)!read(s, buf, sizeof(buf));
        close(s);
        return NULL;
    }

    /* modes 0,1: a real TLS session */
    {
        SSL *ssl = SSL_new(g_ctx);
        if (!ssl) { close(s); return NULL; }
        SSL_set_fd(ssl, s);
        if (SSL_connect(ssl) != 1) {
            SSL_free(ssl);
            close(s);
            return NULL;
        }
        snprintf(buf, sizeof(buf),
                 "NICK t%ld\r\nUSER t%ld 0 * :tls\r\nJOIN #tls\r\n", id, id);
        SSL_write(ssl, buf, (int)strlen(buf));
        for (i = 0; i < g_msgs; i++) {
            snprintf(buf, sizeof(buf), "PRIVMSG #tls :m %d\r\n", i);
            if (SSL_write(ssl, buf, (int)strlen(buf)) <= 0) break;
            if ((i & 7) == 0)
                SSL_read(ssl, buf, sizeof(buf)); /* drain a little */
        }
        if (mode == 0) {
            SSL_write(ssl, "QUIT :bye\r\n", 11);
            SSL_shutdown(ssl);
        }
        /* mode 1: skip clean shutdown, just drop the socket mid-flight */
        SSL_free(ssl);
        close(s);
    }
    return NULL;
}

int
main(int argc, char **argv)
{
    long i;
    pthread_t *th;

    signal(SIGPIPE, SIG_IGN);
    g_port  = argc > 1 ? atoi(argv[1]) : 7920;
    g_conns = argc > 2 ? atoi(argv[2]) : 200;
    g_msgs  = argc > 3 ? atoi(argv[3]) : 30;

    SSL_library_init();
    g_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(g_ctx, SSL_VERIFY_NONE, NULL);

    th = calloc((size_t)g_conns, sizeof(*th));
    for (i = 0; i < g_conns; i++)
        pthread_create(&th[i], NULL, worker, (void *)i);
    for (i = 0; i < g_conns; i++)
        pthread_join(th[i], NULL);
    free(th);
    SSL_CTX_free(g_ctx);
    printf("tls_load: %d conns x %d msgs done\n", g_conns, g_msgs);
    return 0;
}
