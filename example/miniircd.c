/* miniircd.c : a standalone threaded, TLS-capable ircd built on uircd + libiox
 *
 * Model: one worker thread per core, each with its own libiox event loop and
 * its own SO_REUSEPORT listening socket so the kernel spreads new connections
 * across workers. A single mutex (g_lock) guards the uircd engine and every
 * connection's output buffer, because IRC traffic fans out across workers
 * (a PRIVMSG read on one worker may need to write to peers owned by another).
 * Cross-worker output is queued under the lock and the owning worker is woken
 * through a self-pipe to flush it; a connection is only ever closed and freed
 * by the worker that owns it.
 */

#include "uircd.h"
#include "auth.h"
#include "daemonize.h"

#include "iox_loop.h"
#include "iox_fd.h"
#include "iox_timer.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_OUTBUF   (1u << 20)   /* 1 MiB per-connection output cap */
#define READ_CHUNK   8192
#define TICK_MS      1000

struct worker;

struct conn {
    int fd;
    struct worker *w;
    SSL *ssl;                 /* NULL for plaintext */
    int handshaking;          /* TLS handshake not yet complete */
    int rd_want_write;        /* SSL_read wants the socket writable */
    int want_close;           /* close once output has drained */
    struct uircd_client *cli; /* NULL before register / after uircd dropped */

    char *out;
    size_t outlen, outpos, outcap;

    char peer_ip[64];

    struct conn *next, *prev;
};

struct worker {
    pthread_t thread;
    struct iox_loop *loop;
    int listen_fd;
    int wake_fd[2];           /* self-pipe: [0] read end, [1] write end */
    struct conn *conns;       /* doubly linked list owned by this worker */
    int id;
    int is_ticker;            /* worker 0 drives uircd_tick */
};

static struct uircd *g_srv;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static SSL_CTX *g_tls;
static struct worker *g_workers;
static int g_nworkers;
static volatile sig_atomic_t g_stop;
static int g_daemon;

static void on_readable(struct iox_loop *, int, unsigned, void *);
static void on_writable(struct iox_loop *, int, unsigned, void *);
static void on_io(struct iox_loop *, int, unsigned, void *);

/****************************************************************
 * Small helpers
 ****************************************************************/

static uint64_t
now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static int
set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0)
        return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void
logmsg(const char *fmt, ...)
{
    va_list ap;
    if (g_daemon)
        return;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

/****************************************************************
 * Connection list and output buffer (all under g_lock)
 ****************************************************************/

static void
conn_link(struct worker *w, struct conn *c)
{
    c->w = w;
    c->prev = NULL;
    c->next = w->conns;
    if (w->conns)
        w->conns->prev = c;
    w->conns = c;
}

static void
conn_unlink(struct conn *c)
{
    if (c->prev)
        c->prev->next = c->next;
    else
        c->w->conns = c->next;
    if (c->next)
        c->next->prev = c->prev;
}

/* append to the output buffer; returns -1 if the cap would be exceeded */
static int
buf_append(struct conn *c, const void *data, size_t len)
{
    if (c->outpos > 0 && c->outpos == c->outlen)
        c->outpos = c->outlen = 0;
    if (c->outpos > 0 && c->outlen + len > c->outcap) {
        memmove(c->out, c->out + c->outpos, c->outlen - c->outpos);
        c->outlen -= c->outpos;
        c->outpos = 0;
    }
    if (c->outlen - c->outpos + len > MAX_OUTBUF)
        return -1;
    if (c->outlen + len > c->outcap) {
        size_t nc = c->outcap ? c->outcap : 4096;
        char *p;
        while (nc < c->outlen + len)
            nc *= 2;
        p = realloc(c->out, nc);
        if (!p)
            return -1;
        c->out = p;
        c->outcap = nc;
    }
    memcpy(c->out + c->outlen, data, len);
    c->outlen += len;
    return 0;
}

static void
wake(struct worker *w)
{
    char b = 1;
    ssize_t r = write(w->wake_fd[1], &b, 1);
    (void)r; /* a full pipe already means "wake pending" */
}

/* Recompute the poll interest for a connection. Owner thread only. */
static void
update_events(struct conn *c)
{
    unsigned ev;

    if (c->handshaking) {
        ev = SSL_want_write(c->ssl) ? IOX_WRITE : IOX_READ;
    } else {
        ev = IOX_READ;
        if (c->outpos < c->outlen || c->rd_want_write)
            ev |= IOX_WRITE;
    }
    iox_fd_mod(c->w->loop, c->fd, ev);
}

/* Tear down a connection. Owner thread, g_lock held. Frees c. */
static void
close_conn(struct conn *c)
{
    iox_fd_remove(c->w->loop, c->fd);
    if (c->cli) {
        uircd_closed(g_srv, c->cli);
        c->cli = NULL;
    }
    if (c->ssl)
        SSL_free(c->ssl);
    close(c->fd);
    conn_unlink(c);
    free(c->out);
    free(c);
}

/****************************************************************
 * uircd callbacks (invoked under g_lock)
 ****************************************************************/

static void
on_out(void *ud, void *conn, const void *data, size_t len)
{
    struct conn *c = conn;
    (void)ud;
    if (buf_append(c, data, len) < 0)
        c->want_close = 1;
    wake(c->w);
}

static void
on_drop(void *ud, void *conn)
{
    struct conn *c = conn;
    (void)ud;
    /* uircd is finished with the client; it frees it right after this call,
     * so forget the handle and schedule the socket close. */
    c->cli = NULL;
    c->want_close = 1;
    wake(c->w);
}

static void
on_log(void *ud, const char *event, const char *detail)
{
    (void)ud;
    logmsg("[%s] %s", event, detail ? detail : "");
}

/****************************************************************
 * Client registration and TLS handshake
 ****************************************************************/

static void
register_client(struct conn *c)
{
    pthread_mutex_lock(&g_lock);
    c->cli = uircd_accept(g_srv, c, c->peer_ip);
    /* On refusal uircd already queued an ERROR via on_out and called on_drop
     * (which set want_close). Flush then close happens via the loop. */
    if (c->want_close && c->outpos == c->outlen)
        close_conn(c);
    else
        update_events(c);
    pthread_mutex_unlock(&g_lock);
}

/* Owner thread, no lock held (SSL state is per-conn and single-threaded). */
static void
drive_handshake(struct conn *c)
{
    int r = SSL_accept(c->ssl);
    if (r == 1) {
        c->handshaking = 0;
        register_client(c);
        return;
    }
    switch (SSL_get_error(c->ssl, r)) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        pthread_mutex_lock(&g_lock);
        update_events(c);
        pthread_mutex_unlock(&g_lock);
        return;
    default:
        pthread_mutex_lock(&g_lock);
        close_conn(c);
        pthread_mutex_unlock(&g_lock);
    }
}

/****************************************************************
 * Event handlers (each runs in its worker's thread)
 ****************************************************************/

static void
on_readable(struct iox_loop *loop, int fd, unsigned events, void *arg)
{
    struct conn *c = arg;
    char buf[READ_CHUNK];
    (void)loop;
    (void)events;

    if (c->handshaking) {
        drive_handshake(c);
        return;
    }
    c->rd_want_write = 0;

    for (;;) {
        ssize_t n;
        if (c->ssl)
            n = SSL_read(c->ssl, buf, sizeof(buf));
        else
            n = recv(fd, buf, sizeof(buf), 0);

        if (n > 0) {
            int dead = 0;
            pthread_mutex_lock(&g_lock);
            if (c->cli)
                dead = uircd_recv(g_srv, c->cli, buf, (size_t)n);
            pthread_mutex_unlock(&g_lock);
            if (dead) {
                c->cli = NULL; /* uircd freed it; on_drop set want_close */
                break;
            }
            continue;
        }
        if (n == 0) {
            pthread_mutex_lock(&g_lock);
            close_conn(c);
            pthread_mutex_unlock(&g_lock);
            return;
        }
        /* n < 0 */
        if (c->ssl) {
            int e = SSL_get_error(c->ssl, (int)n);
            if (e == SSL_ERROR_WANT_READ)
                break;
            if (e == SSL_ERROR_WANT_WRITE) {
                c->rd_want_write = 1;
                break;
            }
            pthread_mutex_lock(&g_lock);
            close_conn(c);
            pthread_mutex_unlock(&g_lock);
            return;
        }
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;
        pthread_mutex_lock(&g_lock);
        close_conn(c);
        pthread_mutex_unlock(&g_lock);
        return;
    }

    pthread_mutex_lock(&g_lock);
    if (c->want_close && c->outpos == c->outlen)
        close_conn(c);
    else
        update_events(c);
    pthread_mutex_unlock(&g_lock);
}

static void
on_writable(struct iox_loop *loop, int fd, unsigned events, void *arg)
{
    struct conn *c = arg;
    (void)loop;
    (void)events;

    if (c->handshaking) {
        drive_handshake(c);
        return;
    }

    pthread_mutex_lock(&g_lock);
    while (c->outpos < c->outlen) {
        size_t chunk = c->outlen - c->outpos;
        ssize_t n;
        if (c->ssl)
            n = SSL_write(c->ssl, c->out + c->outpos, (int)chunk);
        else
            n = send(fd, c->out + c->outpos, chunk, MSG_NOSIGNAL);
        if (n > 0) {
            c->outpos += (size_t)n;
            continue;
        }
        if (c->ssl) {
            int e = SSL_get_error(c->ssl, (int)n);
            if (e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ)
                break;
            close_conn(c);
            pthread_mutex_unlock(&g_lock);
            return;
        }
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;
        close_conn(c);
        pthread_mutex_unlock(&g_lock);
        return;
    }
    if (c->outpos == c->outlen)
        c->outpos = c->outlen = 0;
    if (c->want_close && c->outlen == 0)
        close_conn(c);
    else
        update_events(c);
    pthread_mutex_unlock(&g_lock);
}

static void
on_accept(struct iox_loop *loop, int fd, unsigned events, void *arg)
{
    struct worker *w = arg;
    (void)events;

    for (;;) {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);
        int cfd = accept(fd, (struct sockaddr *)&ss, &sl);
        struct conn *c;

        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            break; /* EAGAIN or a transient error: done for now */
        }
        if (set_nonblock(cfd) < 0) {
            close(cfd);
            continue;
        }
        c = calloc(1, sizeof(*c));
        if (!c) {
            close(cfd);
            continue;
        }
        c->fd = cfd;
        if (ss.ss_family == AF_INET6) {
            struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
            inet_ntop(AF_INET6, &a->sin6_addr, c->peer_ip,
                      sizeof(c->peer_ip));
        } else {
            struct sockaddr_in *a = (struct sockaddr_in *)&ss;
            inet_ntop(AF_INET, &a->sin_addr, c->peer_ip, sizeof(c->peer_ip));
        }

        pthread_mutex_lock(&g_lock);
        conn_link(w, c);
        pthread_mutex_unlock(&g_lock);

        /* one watcher per fd; on_io splits read and write events */
        iox_fd_add(loop, cfd, IOX_READ, on_io, c);

        if (g_tls) {
            c->ssl = SSL_new(g_tls);
            if (!c->ssl) {
                pthread_mutex_lock(&g_lock);
                close_conn(c);
                pthread_mutex_unlock(&g_lock);
                continue;
            }
            SSL_set_fd(c->ssl, cfd);
            SSL_set_accept_state(c->ssl);
            c->handshaking = 1;
            drive_handshake(c);
        } else {
            register_client(c);
        }
    }
}

/* One iox fd watcher per socket cannot carry separate read and write
 * callbacks, so libiox delivers both to the same callback with an event
 * mask. Route writable events here. */
static void
on_io(struct iox_loop *loop, int fd, unsigned events, void *arg)
{
    if (events & IOX_WRITE)
        on_writable(loop, fd, events, arg);
    if (events & (IOX_READ | IOX_EXCEPT))
        on_readable(loop, fd, events, arg);
}

static void
on_wake(struct iox_loop *loop, int fd, unsigned events, void *arg)
{
    struct worker *w = arg;
    struct conn *c, *next;
    char drain[256];
    (void)events;

    while (read(fd, drain, sizeof(drain)) > 0)
        ;

    pthread_mutex_lock(&g_lock);
    if (g_stop) {
        iox_loop_stop(loop);
        pthread_mutex_unlock(&g_lock);
        return;
    }
    for (c = w->conns; c; c = next) {
        next = c->next;
        if (c->handshaking)
            continue;
        if (c->want_close && c->outpos == c->outlen)
            close_conn(c);
        else
            update_events(c);
    }
    pthread_mutex_unlock(&g_lock);
}

static void
on_tick(struct iox_loop *loop, void *arg)
{
    struct worker *w = arg;

    pthread_mutex_lock(&g_lock);
    uircd_tick(g_srv, now_ms());
    pthread_mutex_unlock(&g_lock);

    /* wake every worker so queued PINGs and timeout drops are flushed */
    {
        int i;
        for (i = 0; i < g_nworkers; i++)
            wake(&g_workers[i]);
    }
    if (!g_stop)
        iox_timer_add(loop, TICK_MS, on_tick, w);
}

/****************************************************************
 * Listener and worker setup
 ****************************************************************/

static int
make_listener(int port, int use6)
{
    int fd, on = 1;

    fd = socket(use6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));

    if (use6) {
        struct sockaddr_in6 a;
        int off = 0;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
        memset(&a, 0, sizeof(a));
        a.sin6_family = AF_INET6;
        a.sin6_addr = in6addr_any;
        a.sin6_port = htons((uint16_t)port);
        if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0)
            goto fail;
    } else {
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_ANY);
        a.sin_port = htons((uint16_t)port);
        if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0)
            goto fail;
    }
    if (listen(fd, 128) < 0)
        goto fail;
    if (set_nonblock(fd) < 0)
        goto fail;
    return fd;
fail:
    close(fd);
    return -1;
}

static void *
worker_main(void *arg)
{
    struct worker *w = arg;

    iox_fd_add(w->loop, w->listen_fd, IOX_READ, on_accept, w);
    iox_fd_add(w->loop, w->wake_fd[0], IOX_READ, on_wake, w);
    if (w->is_ticker)
        iox_timer_add(w->loop, TICK_MS, on_tick, w);

    iox_loop_run(w->loop);
    return NULL;
}

/****************************************************************
 * TLS
 ****************************************************************/

static SSL_CTX *
tls_init(const char *cert, const char *key)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
        return NULL;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx,
                        SSL_OP_NO_RENEGOTIATION |
                        SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_mode(ctx,
                     SSL_MODE_ENABLE_PARTIAL_WRITE |
                     SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

/****************************************************************
 * main
 ****************************************************************/

static char *
read_file(const char *path)
{
    FILE *fp = fopen(path, "rb");
    long sz;
    char *buf;

    if (!fp)
        return NULL;
    fseek(fp, 0, SEEK_END);
    sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz < 0 || sz > (1 << 20)) {
        fclose(fp);
        return NULL;
    }
    buf = malloc((size_t)sz + 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf);
        fclose(fp);
        return NULL;
    }
    buf[sz] = '\0';
    fclose(fp);
    return buf;
}

static void
usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s [options]\n"
        "  -p PORT      listen port (default 6667)\n"
        "  -6           bind IPv6 (dual-stack)\n"
        "  -t N         worker threads (default: online CPUs)\n"
        "  -c FILE      TLS certificate chain (PEM); enables TLS\n"
        "  -k FILE      TLS private key (PEM)\n"
        "  -A FILE      passwd file for PASS/OPER authentication\n"
        "  -L           require authentication to connect\n"
        "  -n NAME      server name (default irc.local)\n"
        "  -N NET       network name (default uircd)\n"
        "  -m FILE      message of the day file\n"
        "  -d           daemonize (background)\n"
        "  -h           this help\n",
        prog);
}

int
main(int argc, char **argv)
{
    struct uircd_config cfg;
    int port = 6667, use6 = 0, nthreads = 0, require_login = 0;
    const char *cert = NULL, *key = NULL, *passwd = NULL;
    const char *srvname = "irc.local", *network = "uircd";
    char *motd = NULL;
    sigset_t block, old;
    int sig, i, opt;

    memset(&cfg, 0, sizeof(cfg));

    while ((opt = getopt(argc, argv, "p:6t:c:k:A:Ln:N:m:dh")) != -1) {
        switch (opt) {
        case 'p': port = atoi(optarg); break;
        case '6': use6 = 1; break;
        case 't': nthreads = atoi(optarg); break;
        case 'c': cert = optarg; break;
        case 'k': key = optarg; break;
        case 'A': passwd = optarg; break;
        case 'L': require_login = 1; break;
        case 'n': srvname = optarg; break;
        case 'N': network = optarg; break;
        case 'm': motd = read_file(optarg); break;
        case 'd': g_daemon = 1; break;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 2;
        }
    }
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "invalid port\n");
        return 2;
    }
    if ((cert && !key) || (key && !cert)) {
        fprintf(stderr, "TLS needs both -c and -k\n");
        return 2;
    }
    if (nthreads <= 0) {
        long n = sysconf(_SC_NPROCESSORS_ONLN);
        nthreads = n > 0 ? (int)n : 1;
    }
    if (nthreads > 256)
        nthreads = 256;

    signal(SIGPIPE, SIG_IGN);

    if (passwd && auth_load(passwd) != 0)
        return 1;

    if (cert) {
        g_tls = tls_init(cert, key);
        if (!g_tls)
            return 1;
    }

    /* fork into the background before creating any threads */
    if (g_daemon && daemonize() != 0) {
        fprintf(stderr, "daemonize failed\n");
        return 1;
    }

    cfg.server_name = srvname;
    cfg.network = network;
    cfg.motd = motd;
    cfg.version = "uircd-1.0";
    cfg.require_login = require_login;
    cfg.out = on_out;
    cfg.drop = on_drop;
    cfg.auth = passwd ? auth_verify : NULL;
    cfg.log = on_log;
    g_srv = uircd_new(&cfg);
    if (!g_srv) {
        fprintf(stderr, "uircd_new failed\n");
        return 1;
    }

    g_nworkers = nthreads;
    g_workers = calloc((size_t)nthreads, sizeof(*g_workers));
    if (!g_workers)
        return 1;

    /* Block termination signals so every worker thread inherits the block;
     * the main thread handles them with sigwait below. */
    sigemptyset(&block);
    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &block, &old);

    for (i = 0; i < nthreads; i++) {
        struct worker *w = &g_workers[i];
        w->id = i;
        w->is_ticker = (i == 0);
        w->listen_fd = make_listener(port, use6);
        if (w->listen_fd < 0) {
            fprintf(stderr, "cannot bind port %d: %s\n", port,
                    strerror(errno));
            return 1;
        }
        if (pipe(w->wake_fd) < 0)
            return 1;
        set_nonblock(w->wake_fd[0]);
        set_nonblock(w->wake_fd[1]);
        w->loop = iox_loop_new();
        if (!w->loop) {
            fprintf(stderr, "iox_loop_new failed\n");
            return 1;
        }
    }
    for (i = 0; i < nthreads; i++) {
        if (pthread_create(&g_workers[i].thread, NULL, worker_main,
                           &g_workers[i]) != 0) {
            fprintf(stderr, "pthread_create failed\n");
            return 1;
        }
    }

    logmsg("miniircd: %s on port %d, %d worker%s, TLS %s, auth %s",
           srvname, port, nthreads, nthreads == 1 ? "" : "s",
           g_tls ? "on" : "off", passwd ? "on" : "off");

    /* wait for a termination signal */
    do {
        if (sigwait(&block, &sig) != 0)
            break;
    } while (sig != SIGINT && sig != SIGTERM);

    g_stop = 1;
    for (i = 0; i < nthreads; i++)
        wake(&g_workers[i]);
    for (i = 0; i < nthreads; i++)
        pthread_join(g_workers[i].thread, NULL);

    for (i = 0; i < nthreads; i++) {
        while (g_workers[i].conns)
            close_conn(g_workers[i].conns);
        iox_loop_free(g_workers[i].loop);
        close(g_workers[i].listen_fd);
        close(g_workers[i].wake_fd[0]);
        close(g_workers[i].wake_fd[1]);
    }
    uircd_free(g_srv);
    free(g_workers);
    free(motd);
    if (g_tls)
        SSL_CTX_free(g_tls);
    auth_free();
    pthread_sigmask(SIG_SETMASK, &old, NULL);
    return 0;
}
