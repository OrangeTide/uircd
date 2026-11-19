/* tsan_load.c : concurrent IRC client load for the TSan verification of the
 * threaded host (UIRCD-007 and UIRCD-008).
 *
 * Many connections across threads join one busy channel and blast messages.
 * Clients barely drain, so the server accumulates fan-out output: a single fd
 * is frequently ready for both read and write at once, and QUIT/close races
 * the server's flush. A recv timeout guarantees no thread blocks forever.
 *
 * This is a driver, not a self-contained falsifier: it needs a running server.
 * Build the server under ThreadSanitizer and drive it with this program:
 *
 *   make tsan
 *   setarch -R env TSAN_OPTIONS=halt_on_error=0 ./miniircd -p 7903 -t 4 &
 *   cc -O2 -g -pthread -w HARDEN/harness/tsan_load.c -o /tmp/tsan_load
 *   for r in 1 2 3 4; do /tmp/tsan_load 7903 300 50; done
 *
 * On the fixed tree ThreadSanitizer reports nothing. Before the fixes it
 * reports a heap-use-after-free (on_readable touching a conn that on_writable
 * freed on the same fd, UIRCD-007) and a data race on g_stop (UIRCD-008).
 * setarch -R disables ASLR, which TSan requires on some kernels. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_port, g_conns, g_msgs;

static void *
worker(void *arg)
{
    long id = (long)arg;
    int s, i;
    struct sockaddr_in sa;
    struct timeval tv = { 0, 100000 }; /* 100ms recv timeout */
    char buf[2048];

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return NULL;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)g_port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(s);
        return NULL;
    }
    snprintf(buf, sizeof(buf),
             "NICK n%ld\r\nUSER n%ld 0 * :load\r\nJOIN #stress\r\n", id, id);
    if (write(s, buf, strlen(buf)) < 0) { close(s); return NULL; }
    for (i = 0; i < g_msgs; i++) {
        snprintf(buf, sizeof(buf), "PRIVMSG #stress :msg %d from %ld\r\n",
                 i, id);
        if (write(s, buf, strlen(buf)) < 0) break;
        if ((i & 7) == 0)
            (void)!read(s, buf, sizeof(buf)); /* drain a little, not all */
    }
    (void)!write(s, "QUIT :done\r\n", 12);
    close(s); /* abrupt close while server may still be flushing */
    return NULL;
}

int
main(int argc, char **argv)
{
    long i;
    pthread_t *th;

    g_port  = argc > 1 ? atoi(argv[1]) : 7900;
    g_conns = argc > 2 ? atoi(argv[2]) : 200;
    g_msgs  = argc > 3 ? atoi(argv[3]) : 40;

    th = calloc((size_t)g_conns, sizeof(*th));
    for (i = 0; i < g_conns; i++)
        pthread_create(&th[i], NULL, worker, (void *)i);
    for (i = 0; i < g_conns; i++)
        pthread_join(th[i], NULL);
    free(th);
    printf("loadgen: %d conns x %d msgs done\n", g_conns, g_msgs);
    return 0;
}
