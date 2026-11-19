/* conf_fuzz.c : generate one adversarial miniircd config file, to fuzz the
 * gitconfig-style config lexer (load_config/hostconf_set/uircd_config_set).
 *
 * usage: conf_fuzz <seed> <outpath>
 *
 * It emits one of a dozen hostile shapes chosen by the seed: random bytes with
 * embedded NULs, a single huge line past the 1 MiB read cap, hundreds of
 * thousands of lines, unbalanced brackets, giant section names and key/value
 * pairs, numeric overflow and edge values on real keys, CR/tab/whitespace
 * noise, a UTF-8 BOM, and pathological separators.
 *
 * Drive the real lexer in the shipped binary via its config-check mode:
 *
 *   make SANITIZE=1
 *   cc -O2 -w HARDEN/harness/conf_fuzz.c -o /tmp/conf_fuzz
 *   export ASAN_OPTIONS=detect_leaks=1:abort_on_error=1:exitcode=99
 *   for s in $(seq 1 3000); do
 *       /tmp/conf_fuzz $s /tmp/f.conf
 *       timeout 10 ./miniircd -C -f /tmp/f.conf >/dev/null 2>err || true
 *       grep -qiE "Sanitizer|runtime error|memory leaks" err && echo "BUG seed=$s"
 *   done
 *
 * The lexer must never crash, hang, leak, or report under the sanitizers; a
 * malformed file is rejected with a file:line message and a nonzero exit. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned st;
static unsigned r(void){ st = st*1103515245u + 12345u; return (st>>16)&0x7fff; }
static unsigned rr(unsigned n){ return n ? r() % n : 0; }

static const char *keys[] = {
    "port","ipv6","name","network","motd","cert","key","handshake-timeout",
    "passwd","require-login","threads","max-per-ip","reg-timeout","max-clients",
    "max-channels","ping-interval","ping-timeout","flood-lines","flood-window",
    "bogus","","=","[","]"
};
static const char *secs[] = {
    "server","listen","tls","auth","limits","","nope","[nested","x=y"
};
static const char *vals[] = {
    "","0","1","-1","+5","99999999999999999999","0x10","  7 ","\t3\t","true",
    "FALSE","maybe","4294967296","4294967295","abc","12x","3.14"
};

static void emit_weird(FILE *f){
    int n = (int)rr(2000), i;
    for(i=0;i<n;i++){
        unsigned c = rr(300);
        if(c<256) fputc((int)c, f); /* includes NUL and control bytes */
        else fputs(keys[rr(sizeof keys/sizeof*keys)], f);
    }
}

int main(int argc, char **argv){
    int pattern, i, lines;
    FILE *f;
    st = argc>1 ? (unsigned)strtoul(argv[1],0,10) : 1;
    f = fopen(argc>2?argv[2]:"/dev/stdout","wb");
    if(!f) return 1;
    pattern = (int)rr(12);
    switch(pattern){
    case 0: /* random bytes incl NUL */
        for(i=0;i<(int)rr(65536);i++) fputc((int)rr(256), f);
        break;
    case 1: { /* one huge line, may exceed the 1 MiB read cap */
        int big = (int)rr(1<<21);
        for(i=0;i<big;i++) fputc('a'+(int)rr(26), f);
        break; }
    case 2: /* very many lines */
        lines = (int)rr(200000);
        for(i=0;i<lines;i++)
            fprintf(f, "%s = %s\n", keys[rr(24)], vals[rr(17)]);
        break;
    case 3: /* embedded NULs amid plausible text */
        for(i=0;i<500;i++){
            fprintf(f, "[%s]\n%s", secs[rr(9)], keys[rr(24)]);
            fputc(0, f);
            fprintf(f, " = %s\n", vals[rr(17)]);
        }
        break;
    case 4: /* many unbalanced brackets */
        for(i=0;i<(int)rr(100000);i++) fputc('[', f);
        break;
    case 5: { /* giant section name */
        int n=(int)rr(100000); fputc('[',f);
        for(i=0;i<n;i++) fputc('s',f);
        fputc(']',f); fputc('\n',f);
        break; }
    case 6: { /* giant key and value */
        int n=(int)rr(100000);
        for(i=0;i<n;i++) fputc('k',f);
        fputs(" = ", f);
        for(i=0;i<n;i++) fputc('v',f);
        break; }
    case 7: /* real keys, overflow/edge values, no newline at EOF */
        fprintf(f, "[limits]\nreg-timeout = %s\nmax-clients = %s\n"
                   "ping-interval = %s\nflood-window = %s",
                vals[rr(17)], vals[rr(17)], vals[rr(17)], vals[rr(17)]);
        break;
    case 8: /* weird whitespace and CR */
        for(i=0;i<300;i++)
            fprintf(f, " \t[%s]\r\n\t%s\t=\t%s \r\n",
                    secs[rr(9)], keys[rr(24)], vals[rr(17)]);
        break;
    case 9: /* BOM then junk */
        fputc(0xEF,f); fputc(0xBB,f); fputc(0xBF,f);
        emit_weird(f);
        break;
    case 10: /* pathological separators */
        for(i=0;i<1000;i++){
            const char *opt[] = {"=","==","[]","[","]","   ","#c",";c","\t=\t","a=","=b"};
            fprintf(f, "%s\n", opt[rr(11)]);
        }
        break;
    default: /* fully random structured-ish */
        emit_weird(f);
        break;
    }
    fclose(f);
    return 0;
}
