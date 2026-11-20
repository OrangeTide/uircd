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
#include "version.h"

#include "iox_loop.h"
#include "iox_fd.h"
#include "iox_timer.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_OUTBUF   (1u << 20)   /* 1 MiB per-connection output cap */
#define READ_CHUNK   8192
#define TICK_MS      1000
#define DEF_ACCEPT_BACKOFF_MS 100  /* pause accepting this long on fd exhaustion */
#define DEF_HANDSHAKE_TIMEOUT_MS 10000 /* reclaim a stalled TLS handshake */

/* Asynchronous authentication (see "Async auth" below and
 * HARDEN/DESIGN-async-auth.md). A deferred login's verdict is answered at a
 * fixed deadline regardless of whether a KDF ran, so response timing carries no
 * hit/miss signal; the KDF itself runs in a bounded pool off the engine lock. */
#define DEF_AUTH_DEADLINE_MS 120   /* must exceed the slowest configured scrypt */
#define DEF_AUTH_JITTER_MS   20    /* random spread added to the deadline */
#define DEF_KDF_THREADS      2     /* scrypt worker threads */
#define KDF_QUEUE_MAX        1024  /* bounded backlog of pending KDF jobs */

/* Host-side timers, configurable (see load_config). */
static unsigned g_handshake_timeout_ms = DEF_HANDSHAKE_TIMEOUT_MS;
static unsigned g_accept_backoff_ms = DEF_ACCEPT_BACKOFF_MS;
static unsigned g_auth_deadline_ms = DEF_AUTH_DEADLINE_MS;
static unsigned g_auth_jitter_ms = DEF_AUTH_JITTER_MS;
static int g_kdf_threads = DEF_KDF_THREADS;

struct worker;

struct conn {
    int fd;
    struct worker *w;
    SSL *ssl;                 /* NULL for plaintext */
    int handshaking;          /* TLS handshake not yet complete */
    uint64_t hs_start_ms;     /* when the handshake began, for its deadline */
    int rd_want_write;        /* SSL_read wants the socket writable */
    int want_close;           /* close once output has drained */
    struct uircd_client *cli; /* NULL before register / after uircd dropped */

    uint64_t auth_id;         /* nonzero while a deferred auth is outstanding */
    int auth_have_result;     /* the KDF has latched a verdict */
    int auth_result;          /* 1 accept, 0 reject */

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

    struct conn *io_cur;      /* conn on_io is currently dispatching, or NULL */
    int io_cur_freed;         /* set if close_conn freed io_cur this dispatch */

    int spare_fd;             /* reserved fd, freed to shed load on EMFILE */
    time_t last_full_log;     /* rate-limit the descriptor-exhaustion log */
};

static struct uircd *g_srv;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static SSL_CTX *g_tls;
static struct worker *g_workers;
static int g_nworkers;
static atomic_int g_stop; /* set by main after sigwait, read by all workers */
static int g_daemon;

static void on_readable(struct iox_loop *, int, unsigned, void *);
static void on_writable(struct iox_loop *, int, unsigned, void *);
static void on_io(struct iox_loop *, int, unsigned, void *);
static void on_auth_deadline(struct iox_loop *, void *);

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
    /* If on_io is mid-dispatch on this conn, tell it not to touch c again. */
    if (c->w->io_cur == c)
        c->w->io_cur_freed = 1;
    /* Outstanding KDF results and the deadline timer find their conn by
     * auth_id among a worker's live conns; clearing it here means a result
     * that lands after this teardown, and a timer that fires later, both find
     * no match and harmlessly drop. */
    c->auth_id = 0;
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
 * Async auth: off-lock KDF pool and deadline-scheduled verdicts
 *
 * The uircd auth callback (on_auth) runs under g_lock on a connection's owner
 * thread. It does only the cheap passwd lookup, then enqueues the scrypt work
 * for the KDF pool and arms a one-shot deadline timer on the owner's loop, and
 * returns UIRCD_AUTH_PENDING. A pool thread runs scrypt with no lock held and
 * latches the verdict on the connection. At the deadline the timer delivers the
 * verdict through uircd_auth_complete. Because the answer is tied to the
 * deadline and not to when (or whether) the KDF ran, a known-bad name and an
 * unknown name are indistinguishable by timing, and the KDF never blocks the
 * engine lock. A job references its connection only by {worker, auth_id}, never
 * by pointer, so a connection that closes mid-KDF is safe: the id simply no
 * longer matches any live conn. See HARDEN/DESIGN-async-auth.md.
 ****************************************************************/

struct kdf_job {
    int worker_id;
    uint64_t auth_id;
    struct auth_job aj;
    struct kdf_job *next;
};

struct auth_timer {
    int worker_id;
    uint64_t auth_id;
    int polls;
};

static atomic_uint_least64_t g_auth_seq;
static pthread_mutex_t g_kdf_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_kdf_cond = PTHREAD_COND_INITIALIZER;
static struct kdf_job *g_kdf_head, *g_kdf_tail;
static int g_kdf_count;
static pthread_t *g_kdf_pool;
static int g_kdf_nthreads;
static int g_kdf_stop;

/* xorshift64; called only under g_lock (auth is serialized there), so the
 * single state needs no synchronization of its own. */
static uint64_t g_rng = 0x9e3779b97f4a7c15ULL;

static unsigned
jitter_ms(unsigned span)
{
    if (span == 0)
        return 0;
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 7;
    g_rng ^= g_rng << 17;
    return (unsigned)(g_rng % ((uint64_t)span + 1));
}

/* g_lock held. Latch a verdict onto the connection awaiting this auth_id. */
static void
deliver_result(int wid, uint64_t auth_id, int ok)
{
    struct conn *c;

    if (wid < 0 || wid >= g_nworkers || auth_id == 0)
        return;
    for (c = g_workers[wid].conns; c; c = c->next) {
        if (c->auth_id == auth_id) {
            c->auth_result = ok;
            c->auth_have_result = 1;
            return;
        }
    }
    /* No match: the connection closed before the KDF finished. Drop it. */
}

/* uircd auth callback, invoked under g_lock on the connection's owner thread. */
static int
on_auth(void *ud, void *conn, enum uircd_auth_kind kind, const char *name,
        const char *pass)
{
    struct conn *c = conn;
    struct kdf_job *j;
    struct auth_timer *t;
    uint64_t id;
    unsigned delay;
    (void)ud;

    j = malloc(sizeof(*j));
    if (!j)
        return UIRCD_ERR;                 /* fail closed, synchronously */
    auth_lookup(kind, name, pass, &j->aj);

    t = malloc(sizeof(*t));
    if (!t) {
        memset(j->aj.pass, 0, sizeof(j->aj.pass));
        free(j);
        return UIRCD_ERR;
    }

    id = (uint64_t)atomic_fetch_add_explicit(&g_auth_seq, 1,
                                             memory_order_relaxed) + 1;
    c->auth_id = id;
    c->auth_have_result = 0;
    c->auth_result = 0;

    j->worker_id = c->w->id;
    j->auth_id = id;
    t->worker_id = c->w->id;
    t->auth_id = id;
    t->polls = 0;

    delay = g_auth_deadline_ms + jitter_ms(g_auth_jitter_ms);
    iox_timer_add(c->w->loop, (int)delay, on_auth_deadline, t);

    pthread_mutex_lock(&g_kdf_lock);
    if (g_kdf_count >= KDF_QUEUE_MAX) {
        /* Backlog full: skip the compute and latch a rejection now. It is still
         * delivered at the deadline, so a saturated pool leaks no timing. */
        pthread_mutex_unlock(&g_kdf_lock);
        memset(j->aj.pass, 0, sizeof(j->aj.pass));
        free(j);
        c->auth_have_result = 1;
        c->auth_result = 0;
        return UIRCD_AUTH_PENDING;
    }
    j->next = NULL;
    if (g_kdf_tail)
        g_kdf_tail->next = j;
    else
        g_kdf_head = j;
    g_kdf_tail = j;
    g_kdf_count++;
    pthread_cond_signal(&g_kdf_cond);
    pthread_mutex_unlock(&g_kdf_lock);
    return UIRCD_AUTH_PENDING;
}

/* Deadline timer, owner thread. Deliver the latched verdict; if the KDF has not
 * finished (a saturated pool, not the common case), re-arm briefly rather than
 * fail a valid login, up to a bound. */
static void
on_auth_deadline(struct iox_loop *loop, void *arg)
{
    struct auth_timer *t = arg;
    struct worker *w = &g_workers[t->worker_id];
    struct conn *c;

    pthread_mutex_lock(&g_lock);
    for (c = w->conns; c; c = c->next)
        if (c->auth_id == t->auth_id)
            break;
    if (!c) {                             /* connection closed; nothing to do */
        pthread_mutex_unlock(&g_lock);
        free(t);
        return;
    }
    if (!c->auth_have_result) {
        if (t->polls++ < 50) {            /* wait out a backed-up KDF pool */
            iox_timer_add(loop, 20, on_auth_deadline, t);
            pthread_mutex_unlock(&g_lock);
            return;
        }
        c->auth_result = 0;               /* give up: fail closed */
    }
    c->auth_id = 0;
    if (c->cli)
        uircd_auth_complete(g_srv, c->cli, c->auth_result);
    if (c->want_close && c->outpos == c->outlen)
        close_conn(c);
    else
        update_events(c);
    pthread_mutex_unlock(&g_lock);
    free(t);
}

static void *
kdf_main(void *arg)
{
    (void)arg;
    for (;;) {
        struct kdf_job *j;
        int ok;

        pthread_mutex_lock(&g_kdf_lock);
        while (!g_kdf_head && !g_kdf_stop)
            pthread_cond_wait(&g_kdf_cond, &g_kdf_lock);
        if (!g_kdf_head && g_kdf_stop) {
            pthread_mutex_unlock(&g_kdf_lock);
            return NULL;
        }
        j = g_kdf_head;
        g_kdf_head = j->next;
        if (!g_kdf_head)
            g_kdf_tail = NULL;
        g_kdf_count--;
        pthread_mutex_unlock(&g_kdf_lock);

        ok = auth_compute(&j->aj);        /* no lock; wipes the password */

        pthread_mutex_lock(&g_lock);
        deliver_result(j->worker_id, j->auth_id, ok);
        pthread_mutex_unlock(&g_lock);
        free(j);
    }
}

static int
kdf_pool_start(int nthreads)
{
    int i;

    g_kdf_pool = calloc((size_t)nthreads, sizeof(*g_kdf_pool));
    if (!g_kdf_pool)
        return -1;
    for (i = 0; i < nthreads; i++) {
        if (pthread_create(&g_kdf_pool[i], NULL, kdf_main, NULL) != 0)
            return -1;
        g_kdf_nthreads = i + 1;
    }
    return 0;
}

static void
kdf_pool_stop(void)
{
    struct kdf_job *j;
    int i;

    pthread_mutex_lock(&g_kdf_lock);
    g_kdf_stop = 1;
    pthread_cond_broadcast(&g_kdf_cond);
    pthread_mutex_unlock(&g_kdf_lock);
    for (i = 0; i < g_kdf_nthreads; i++)
        pthread_join(g_kdf_pool[i], NULL);
    for (j = g_kdf_head; j; ) {
        struct kdf_job *n = j->next;
        memset(j->aj.pass, 0, sizeof(j->aj.pass));
        free(j);
        j = n;
    }
    g_kdf_head = g_kdf_tail = NULL;
    free(g_kdf_pool);
    g_kdf_pool = NULL;
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

/* Re-arm a listener that on_accept paused after fd exhaustion. */
static void
on_relisten(struct iox_loop *loop, void *arg)
{
    struct worker *w = arg;
    if (!g_stop)
        iox_fd_mod(loop, w->listen_fd, IOX_READ);
}

static void
on_accept(struct iox_loop *loop, int fd, unsigned events, void *arg)
{
    struct worker *w = arg;
    (void)events;

    /* Recover the reserved fd if a previous shed could not reopen it. */
    if (w->spare_fd < 0)
        w->spare_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);

    for (;;) {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);
        int cfd = accept(fd, (struct sockaddr *)&ss, &sl);
        struct conn *c;

        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EMFILE || errno == ENFILE ||
                errno == ENOBUFS || errno == ENOMEM) {
                /* Descriptor table exhausted. libiox is level-triggered, so a
                 * connection left in the accept queue keeps the listener
                 * readable and this handler would spin at 100% CPU. Free the
                 * reserved fd and use the slot to accept and immediately close
                 * the backlog, shedding load (each client gets a prompt close)
                 * instead of busy-looping, then reclaim the reserve. */
                time_t now = time(NULL);
                if (now != w->last_full_log) {
                    logmsg("accept: %s; shedding connections", strerror(errno));
                    w->last_full_log = now;
                }
                if (w->spare_fd >= 0) {
                    close(w->spare_fd);
                    w->spare_fd = -1;
                    for (;;) {
                        int victim = accept(fd, NULL, NULL);
                        if (victim < 0)
                            break;
                        close(victim);
                    }
                    w->spare_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
                }
                /* Shedding the current backlog is not enough: with several
                 * workers sharing one process-wide fd limit, a worker that
                 * loses the race to reopen its reserve has no slot to shed with
                 * and would spin on the still-readable listener. Stop polling
                 * the listener and re-arm it after a short backoff, so CPU is
                 * bounded no matter how long the table stays full. */
                iox_fd_mod(w->loop, fd, 0);
                iox_timer_add(w->loop, g_accept_backoff_ms, on_relisten, w);
                break;
            }
            break; /* EAGAIN or another transient error: done for now */
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
            c->hs_start_ms = now_ms();
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
    struct conn *c = arg;
    struct worker *w = c->w;

    /* A single fd can be ready for both write and read in one poll pass.
     * If handling the writable event closes the connection (write error or a
     * drained want_close), c is freed and must not be touched for the read
     * event. close_conn sets io_cur_freed when it frees the dispatched conn. */
    w->io_cur = c;
    w->io_cur_freed = 0;

    if (events & IOX_WRITE)
        on_writable(loop, fd, events, arg);
    if (!w->io_cur_freed && (events & (IOX_READ | IOX_EXCEPT)))
        on_readable(loop, fd, events, arg);

    w->io_cur = NULL;
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
    uint64_t now = now_ms();
    struct conn *c, *next;

    pthread_mutex_lock(&g_lock);
    if (w->is_ticker)
        uircd_tick(g_srv, now);
    /* Reclaim connections stuck in the TLS handshake. These are not yet
     * registered with the engine, so max_clients, the per-IP cap, and the
     * registration deadline do not apply to them; without this a slow or
     * abandoned handshake would hold an fd and an SSL object indefinitely.
     * Each worker sweeps only its own conns, which it alone may free. */
    for (c = w->conns; c; c = next) {
        next = c->next; /* close_conn unlinks c */
        if (c->handshaking && now - c->hs_start_ms >= g_handshake_timeout_ms)
            close_conn(c);
    }
    pthread_mutex_unlock(&g_lock);

    /* wake every worker so queued PINGs and timeout drops are flushed */
    if (w->is_ticker) {
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
    /* every worker ticks: the ticker also drives the engine, but all workers
     * must sweep their own stalled TLS handshakes */
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

/****************************************************************
 * Configuration
 *
 * The uircd library takes its settings as a struct (uircd_config); that is its
 * settings API. This host adds its own settings (TLS, threads, the handshake
 * deadline) and wires both to a gitconfig-style file, so the config format
 * lives in the host, not the library. Command-line flags override the file.
 ****************************************************************/

struct hostconf {
    int port, use6, nthreads, daemon, require_login;
    char *cert, *key, *passwd, *srvname, *network, *motd_path;
    unsigned handshake_timeout_s;   /* host-side TLS handshake deadline */
    unsigned accept_backoff_ms;     /* host-side accept pause on fd exhaustion */
    unsigned auth_deadline_ms;      /* deferred-login response deadline */
    unsigned auth_jitter_ms;        /* random spread added to the deadline */
    int kdf_threads;                /* scrypt worker threads */
    int host_cloak;                 /* hide client IPs from other users */

    /* Engine limits are accumulated here through the library's own string
     * setter (see the [limits] handlers), rather than poking struct fields. */
    struct uircd_config cfg;
};

static void
hostconf_defaults(struct hostconf *hc)
{
    memset(hc, 0, sizeof(*hc));
    hc->port = 6667;
    hc->srvname = strdup("irc.local");
    hc->network = strdup("uircd");
    hc->host_cloak = 1; /* cloak client IPs by default */
}

static void
hostconf_free(struct hostconf *hc)
{
    free(hc->cert);
    free(hc->key);
    free(hc->passwd);
    free(hc->srvname);
    free(hc->network);
    free(hc->motd_path);
}

static int
set_str(char **dst, const char *val)
{
    char *dup = strdup(val);
    if (!dup)
        return -1;
    free(*dst);
    *dst = dup;
    return 0;
}

static int
parse_bool(const char *v)
{
    return (!strcasecmp(v, "true") || !strcasecmp(v, "yes") ||
            !strcasecmp(v, "on") || !strcmp(v, "1"));
}

/* Apply an engine limit through the library's string setter. These dogfood
 * uircd_config_set rather than assigning struct fields directly. Counts pass
 * through unchanged; the host's friendly seconds are converted to the library's
 * millisecond keys. Returns 0, or -1 on a bad value. */
static int
engine_count(struct hostconf *hc, const char *libkey, const char *val)
{
    return uircd_config_set(&hc->cfg, libkey, val) == UIRCD_OK ? 0 : -1;
}

static int
engine_secs(struct hostconf *hc, const char *libkey_ms, const char *val)
{
    char *end, buf[32];
    unsigned long s;

    errno = 0;
    s = strtoul(val, &end, 10);
    if (!*val || errno != 0 || *end != '\0' || s > UINT_MAX / 1000u)
        return -1;
    snprintf(buf, sizeof(buf), "%lu", s * 1000u);
    return uircd_config_set(&hc->cfg, libkey_ms, buf) == UIRCD_OK ? 0 : -1;
}

/* Apply one "section.name = value" setting. Returns 0, or -1 for an unknown
 * key or a bad value. */
static int
hostconf_set(struct hostconf *hc, const char *sec, const char *name,
             const char *val)
{
#define MATCH(s, n) (!strcmp(sec, (s)) && !strcmp(name, (n)))
    if (MATCH("server", "name"))    return set_str(&hc->srvname, val);
    if (MATCH("server", "network")) return set_str(&hc->network, val);
    if (MATCH("server", "motd"))    return set_str(&hc->motd_path, val);
    if (MATCH("listen", "port"))    { hc->port = atoi(val); return 0; }
    if (MATCH("listen", "ipv6"))    { hc->use6 = parse_bool(val); return 0; }
    if (MATCH("tls", "cert"))       return set_str(&hc->cert, val);
    if (MATCH("tls", "key"))        return set_str(&hc->key, val);
    if (MATCH("tls", "handshake-timeout"))
        { hc->handshake_timeout_s = (unsigned)atoi(val); return 0; }
    if (MATCH("auth", "passwd"))    return set_str(&hc->passwd, val);
    if (MATCH("auth", "require-login"))
        { hc->require_login = parse_bool(val); return 0; }
    if (MATCH("auth", "auth-deadline-ms"))
        { hc->auth_deadline_ms = (unsigned)atoi(val); return 0; }
    if (MATCH("auth", "auth-jitter-ms"))
        { hc->auth_jitter_ms = (unsigned)atoi(val); return 0; }
    if (MATCH("auth", "kdf-threads")) { hc->kdf_threads = atoi(val); return 0; }
    if (MATCH("privacy", "host-cloak"))
        { hc->host_cloak = parse_bool(val); return 0; }
    if (MATCH("limits", "threads")) { hc->nthreads = atoi(val); return 0; }
    if (MATCH("limits", "accept-backoff-ms"))
        { hc->accept_backoff_ms = (unsigned)atoi(val); return 0; }
    if (MATCH("limits", "max-per-ip"))   return engine_count(hc, "max-per-ip", val);
    if (MATCH("limits", "max-clients"))  return engine_count(hc, "max-clients", val);
    if (MATCH("limits", "max-channels")) return engine_count(hc, "max-channels", val);
    if (MATCH("limits", "flood-lines"))  return engine_count(hc, "flood-lines", val);
    if (MATCH("limits", "reg-timeout"))  return engine_secs(hc, "reg-timeout-ms", val);
    if (MATCH("limits", "ping-interval"))return engine_secs(hc, "ping-interval-ms", val);
    if (MATCH("limits", "ping-timeout")) return engine_secs(hc, "ping-timeout-ms", val);
    if (MATCH("limits", "flood-window")) return engine_secs(hc, "flood-window-ms", val);
#undef MATCH
    return -1;
}

static char *
trim(char *s)
{
    char *e;
    while (*s && isspace((unsigned char)*s))
        s++;
    e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1]))
        *--e = '\0';
    return s;
}

/* Read a gitconfig-style file: "[section]" headers, "key = value" lines, and
 * '#'/';' comments. Returns 0, or -1 if the file cannot be read or any line is
 * malformed or names an unknown setting (those are reported, parsing goes on). */
static int
load_config(const char *path, struct hostconf *hc)
{
    char *text = read_file(path);
    char section[64] = "";
    char *line, *save;
    int lineno = 0, rc = 0;

    if (!text) {
        fprintf(stderr, "config: cannot read %s\n", path);
        return -1;
    }
    for (line = strtok_r(text, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char *s = trim(line);
        char *eq, *key, *val;
        lineno++;
        if (*s == '\0' || *s == '#' || *s == ';')
            continue;
        if (*s == '[') {
            char *close = strchr(s, ']');
            if (!close) {
                fprintf(stderr, "config %s:%d: missing ']'\n", path, lineno);
                rc = -1;
                continue;
            }
            *close = '\0';
            snprintf(section, sizeof(section), "%s", trim(s + 1));
            continue;
        }
        eq = strchr(s, '=');
        if (!eq) {
            fprintf(stderr, "config %s:%d: expected 'key = value'\n",
                    path, lineno);
            rc = -1;
            continue;
        }
        *eq = '\0';
        key = trim(s);
        val = trim(eq + 1);
        if (hostconf_set(hc, section, key, val) != 0) {
            fprintf(stderr, "config %s:%d: bad or unknown setting '%s.%s'\n",
                    path, lineno, section, key);
            rc = -1;
        }
    }
    free(text);
    return rc;
}

static void
usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s [options]\n"
        "  -f FILE      read a gitconfig-style config file (see miniircd.conf)\n"
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
        "  -P N         max connections per source IP (default 8)\n"
        "  -R SEC       drop unregistered sessions after SEC seconds"
        " (default 30)\n"
        "  -H SEC       TLS handshake deadline in seconds (default 10)\n"
        "  -b MS        accept backoff on fd exhaustion, ms (default 100)\n"
        "  -C           parse and check the configuration, then exit\n"
        "  -d           daemonize (background)\n"
        "  -h           this help\n"
        "Command-line options override settings from -f.\n",
        prog);
}

/* Apply one command-line override to the host config. */
static int
apply_opt(struct hostconf *hc, int opt, const char *arg)
{
    switch (opt) {
    case 'p': hc->port = atoi(arg); break;
    case '6': hc->use6 = 1; break;
    case 't': hc->nthreads = atoi(arg); break;
    case 'c': if (set_str(&hc->cert, arg)) return -1; break;
    case 'k': if (set_str(&hc->key, arg)) return -1; break;
    case 'A': if (set_str(&hc->passwd, arg)) return -1; break;
    case 'L': hc->require_login = 1; break;
    case 'n': if (set_str(&hc->srvname, arg)) return -1; break;
    case 'N': if (set_str(&hc->network, arg)) return -1; break;
    case 'm': if (set_str(&hc->motd_path, arg)) return -1; break;
    case 'P': if (engine_count(hc, "max-per-ip", arg)) return -1; break;
    case 'R': if (engine_secs(hc, "reg-timeout-ms", arg)) return -1; break;
    case 'H': hc->handshake_timeout_s = (unsigned)atoi(arg); break;
    case 'b': hc->accept_backoff_ms = (unsigned)atoi(arg); break;
    case 'd': hc->daemon = 1; break;
    default: return -1;
    }
    return 0;
}

int
main(int argc, char **argv)
{
    static const char *optstr = "f:p:6t:c:k:A:Ln:N:m:P:R:H:b:Cdh";
    struct uircd_config cfg;
    struct hostconf hc;
    const char *cfgpath = NULL;
    char *motd = NULL;
    sigset_t block, old;
    int sig, i, opt, check_only = 0;

    hostconf_defaults(&hc);

    /* First pass: find -f (and -h) before loading the file, with getopt's own
     * error messages suppressed so unknown options are reported once, below. */
    opterr = 0;
    while ((opt = getopt(argc, argv, optstr)) != -1) {
        if (opt == 'f')
            cfgpath = optarg;
        else if (opt == 'h') {
            usage(argv[0]);
            hostconf_free(&hc);
            return 0;
        }
    }
    if (cfgpath && load_config(cfgpath, &hc) != 0) {
        hostconf_free(&hc);
        return 2;
    }

    /* Second pass: command-line options override the file. */
    opterr = 1;
    optind = 1;
    while ((opt = getopt(argc, argv, optstr)) != -1) {
        if (opt == 'f')
            continue;
        if (opt == 'h') {
            usage(argv[0]);
            hostconf_free(&hc);
            return 0;
        }
        if (opt == 'C') {
            check_only = 1;
            continue;
        }
        if (apply_opt(&hc, opt, optarg) != 0) {
            usage(argv[0]);
            hostconf_free(&hc);
            return 2;
        }
    }

    if (hc.port <= 0 || hc.port > 65535) {
        fprintf(stderr, "invalid port\n");
        hostconf_free(&hc);
        return 2;
    }
    if ((hc.cert && !hc.key) || (hc.key && !hc.cert)) {
        fprintf(stderr, "TLS needs both a cert and a key\n");
        hostconf_free(&hc);
        return 2;
    }
    if (hc.nthreads <= 0) {
        long n = sysconf(_SC_NPROCESSORS_ONLN);
        hc.nthreads = n > 0 ? (int)n : 1;
    }
    if (hc.nthreads > 256)
        hc.nthreads = 256;
    if (hc.handshake_timeout_s > 0)
        g_handshake_timeout_ms = hc.handshake_timeout_s * 1000u;
    if (hc.accept_backoff_ms > 0)
        g_accept_backoff_ms = hc.accept_backoff_ms;
    if (hc.auth_deadline_ms > 0)
        g_auth_deadline_ms = hc.auth_deadline_ms;
    if (hc.auth_jitter_ms > 0)
        g_auth_jitter_ms = hc.auth_jitter_ms;
    if (hc.kdf_threads > 0)
        g_kdf_threads = hc.kdf_threads;
    if (g_kdf_threads > 64)
        g_kdf_threads = 64;

    if (check_only) {
        /* configuration parsed and validated; do not bind or start threads */
        fprintf(stderr, "config OK\n");
        hostconf_free(&hc);
        return 0;
    }

    signal(SIGPIPE, SIG_IGN);

    if (hc.motd_path) {
        motd = read_file(hc.motd_path);
        if (!motd)
            fprintf(stderr, "cannot read motd %s\n", hc.motd_path);
    }
    if (hc.passwd && auth_load(hc.passwd) != 0) {
        hostconf_free(&hc);
        free(motd);
        return 1;
    }
    if (hc.cert) {
        g_tls = tls_init(hc.cert, hc.key);
        if (!g_tls) {
            hostconf_free(&hc);
            free(motd);
            return 1;
        }
    }
    g_daemon = hc.daemon;

    /* fork into the background before creating any threads */
    if (g_daemon && daemonize() != 0) {
        fprintf(stderr, "daemonize failed\n");
        hostconf_free(&hc);
        free(motd);
        return 1;
    }

    /* start from the engine limits accumulated through uircd_config_set, then
     * fill in the fields the host owns directly */
    cfg = hc.cfg;
    cfg.server_name = hc.srvname;
    cfg.network = hc.network;
    cfg.motd = motd;
    cfg.version = "uircd-" UIRCD_VERSION;
    cfg.require_login = hc.require_login;
    cfg.host_cloak = hc.host_cloak;
    /* A per-run secret so cloaks cannot be reversed to the real address. */
    if (getrandom(&cfg.cloak_key, sizeof(cfg.cloak_key), 0) !=
        (ssize_t)sizeof(cfg.cloak_key))
        cfg.cloak_key = ((uint64_t)now_ms() << 20) ^ (uint64_t)getpid();
    cfg.out = on_out;
    cfg.drop = on_drop;
    cfg.auth = hc.passwd ? on_auth : NULL;
    cfg.log = on_log;
    g_rng ^= now_ms();
    g_srv = uircd_new(&cfg);
    if (!g_srv) {
        fprintf(stderr, "uircd_new failed\n");
        hostconf_free(&hc);
        free(motd);
        return 1;
    }

    g_nworkers = hc.nthreads;
    g_workers = calloc((size_t)hc.nthreads, sizeof(*g_workers));
    if (!g_workers) {
        hostconf_free(&hc);
        free(motd);
        uircd_free(g_srv);
        return 1;
    }

    /* Block termination signals so every worker thread inherits the block;
     * the main thread handles them with sigwait below. */
    sigemptyset(&block);
    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &block, &old);

    for (i = 0; i < hc.nthreads; i++) {
        struct worker *w = &g_workers[i];
        w->id = i;
        w->is_ticker = (i == 0);
        w->spare_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        w->listen_fd = make_listener(hc.port, hc.use6);
        if (w->listen_fd < 0) {
            fprintf(stderr, "cannot bind port %d: %s\n", hc.port,
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
    /* Start the KDF pool before any worker accepts, so a login that arrives
     * immediately has a thread to run its scrypt. Only needed when auth is on.
     * Warm the vendored scrypt's lazy CPU-feature selection on this thread
     * first, so the pool threads never race to initialize it. */
    if (hc.passwd) {
        auth_warmup();
        if (kdf_pool_start(g_kdf_threads) != 0) {
            fprintf(stderr, "cannot start KDF pool\n");
            return 1;
        }
    }

    for (i = 0; i < hc.nthreads; i++) {
        if (pthread_create(&g_workers[i].thread, NULL, worker_main,
                           &g_workers[i]) != 0) {
            fprintf(stderr, "pthread_create failed\n");
            return 1;
        }
    }

    logmsg("miniircd: %s on port %d, %d worker%s, TLS %s, auth %s",
           hc.srvname, hc.port, hc.nthreads, hc.nthreads == 1 ? "" : "s",
           g_tls ? "on" : "off", hc.passwd ? "on" : "off");

    /* wait for a termination signal */
    do {
        if (sigwait(&block, &sig) != 0)
            break;
    } while (sig != SIGINT && sig != SIGTERM);

    g_stop = 1;
    for (i = 0; i < hc.nthreads; i++)
        wake(&g_workers[i]);
    for (i = 0; i < hc.nthreads; i++)
        pthread_join(g_workers[i].thread, NULL);

    /* Workers are stopped; drain and join the KDF pool before tearing down the
     * connections and engine its threads may still reference. */
    if (hc.passwd)
        kdf_pool_stop();

    for (i = 0; i < hc.nthreads; i++) {
        while (g_workers[i].conns)
            close_conn(g_workers[i].conns);
        iox_loop_free(g_workers[i].loop);
        close(g_workers[i].listen_fd);
        close(g_workers[i].wake_fd[0]);
        close(g_workers[i].wake_fd[1]);
        if (g_workers[i].spare_fd >= 0)
            close(g_workers[i].spare_fd);
    }
    uircd_free(g_srv);
    free(g_workers);
    free(motd);
    hostconf_free(&hc);
    if (g_tls)
        SSL_CTX_free(g_tls);
    auth_free();
    pthread_sigmask(SIG_SETMASK, &old, NULL);
    return 0;
}
