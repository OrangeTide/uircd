/* emfile_load.c : driver for the descriptor-exhaustion falsifier (UIRCD-009).
 *
 * Opens many connections and holds them (it leaks the fds on purpose) to
 * exhaust a server running under a low RLIMIT_NOFILE. It needs a running
 * server, so it is a driver, not a self-contained harness.
 *
 *   make
 *   bash -c 'ulimit -n 64; exec ./miniircd -p 7910 -t 1 -P 5000' &
 *   SRV=$!
 *   cc -O2 -w HARDEN/harness/emfile_load.c -o /tmp/emfile_load
 *   # sample server CPU (utime+stime, fields 14/15 of /proc/PID/stat) over the
 *   # window the backlog is exhausted:
 *   read u1 s1 < <(awk '{print $14,$15}' /proc/$SRV/stat)
 *   /tmp/emfile_load 7910 300 3 ; sleep 3
 *   read u2 s2 < <(awk '{print $14,$15}' /proc/$SRV/stat)
 *   echo $(( (u2+s2)-(u1+s1) ))   # ~300 (a pegged core) pre-fix, ~1 post-fix
 *
 * usage: emfile_load <port> <connections> <hold-seconds>
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv){
    int port = argc>1?atoi(argv[1]):7910;
    int n = argc>2?atoi(argv[2]):200;
    int hold = argc>3?atoi(argv[3]):4;
    struct sockaddr_in sa; int i, ok=0;
    memset(&sa,0,sizeof sa); sa.sin_family=AF_INET;
    sa.sin_port=htons(port); inet_pton(AF_INET,"127.0.0.1",&sa.sin_addr);
    for(i=0;i<n;i++){
        int s=socket(AF_INET,SOCK_STREAM,0);
        if(s<0) continue;
        if(connect(s,(struct sockaddr*)&sa,sizeof sa)==0) ok++;
        /* leak fd on purpose: hold the connection open */
    }
    printf("holder: connected %d/%d\n", ok, n);
    sleep(hold);
    return 0;
}
