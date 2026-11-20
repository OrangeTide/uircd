/* uircd.c : compact, network-agnostic IRC server core */

#include "uircd.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <arpa/inet.h>
#include <sys/socket.h>

/****************************************************************
 * Limits
 ****************************************************************/

#define NICK_MAX     30
#define USER_MAX     16
#define HOST_MAX     63
#define REAL_MAX     64
#define ACCT_MAX     32
#define CHAN_MAX     50
#define TOPIC_MAX    307
#define KEY_MAX      32
#define INBUF_MAX    512   /* an IRC line is at most 512 bytes incl CRLF */
#define MAXPARAMS    16
#define CHANS_PER_CLIENT 20
#define PATLEN       128
#define MAXTERMS     12

#define DEF_PING_INTERVAL  120000u
#define DEF_PING_TIMEOUT   60000u
#define DEF_MAX_CLIENTS    1024u
#define DEF_MAX_CHANNELS   1024u
#define DEF_FLOOD_LINES    20u
#define DEF_FLOOD_WINDOW   10000u
#define DEF_MAX_PER_IP     8u
#define DEF_REG_TIMEOUT    30000u

/* user modes */
#define UMODE_INVISIBLE  (1u << 0)
#define UMODE_OPER       (1u << 1)

/* channel modes */
#define CMODE_TOPICLOCK  (1u << 0)
#define CMODE_NOEXTERNAL (1u << 1)
#define CMODE_MODERATED  (1u << 2)
#define CMODE_KEYED      (1u << 3)

/* per-member channel flags */
#define MEMB_OP     (1u << 0)
#define MEMB_VOICE  (1u << 1)

/****************************************************************
 * Internal structures
 ****************************************************************/

struct member {
    struct uircd_client *c;
    unsigned flags;
};

struct uircd_channel {
    char name[CHAN_MAX + 1];
    char topic[TOPIC_MAX + 1];
    char topic_by[NICK_MAX + 1];
    uint64_t topic_at;
    int has_topic;
    char key[KEY_MAX + 1];
    unsigned modes;
    struct member *members;
    unsigned n_members, cap_members;
};

enum field {
    F_NICK, F_USER, F_HOST, F_IP, F_REAL, F_CHAN, F_ACCOUNT, F_INVALID,
};

struct term {
    enum field field;
    int negate;
    char pat[PATLEN];
};

struct ban {
    char spec[PATLEN + 8];
    char reason[128];
    struct term term;
};

struct uircd_client {
    void *host_conn;
    struct uircd *srv;

    int registered;
    int got_nick, got_user;
    int authed;             /* passed user auth (or none required) */

    int auth_pending;       /* a deferred auth verdict is outstanding */
    enum uircd_auth_kind auth_kind; /* which credential is pending */
    char auth_acct[ACCT_MAX + 1];   /* account name to set on a USER accept */
    char *hold;             /* input received while the verdict is pending */
    size_t hold_len, hold_cap;

    char nick[NICK_MAX + 1];
    char user[USER_MAX + 1];
    char real[REAL_MAX + 1];
    char host[HOST_MAX + 1]; /* printable peer ip, used as host */
    char cloak[HOST_MAX + 1]; /* display host shown to others when cloaking */
    char acct[ACCT_MAX + 1]; /* account name if logged in, else empty */
    unsigned umodes;

    struct uircd_channel *chans[CHANS_PER_CLIENT];
    unsigned n_chans;

    char inbuf[INBUF_MAX];
    size_t inlen;
    int skipping;           /* discarding an over-long line */
    int scrub_line;         /* last dispatched line held a credential; wipe it */

    uint64_t connect_ms;    /* first tick seen; 0 until then */
    uint64_t last_active_ms;
    int ping_sent;
    int active;             /* saw input since the last tick */

    unsigned flood_count;
    uint64_t flood_reset_ms;

    int dead;               /* marked for destruction */
};

struct uircd {
    struct uircd_config cfg;

    struct uircd_client **clients;
    unsigned n_clients, cap_clients;

    struct uircd_channel **channels;
    unsigned n_channels, cap_channels;

    struct ban *bans;
    unsigned n_bans, cap_bans;

    /* resolved config with defaults applied */
    unsigned ping_interval_ms, ping_timeout_ms;
    unsigned max_clients, max_channels;
    unsigned flood_lines, flood_window_ms;
    unsigned max_per_ip, reg_timeout_ms;
};

/****************************************************************
 * Small utilities
 ****************************************************************/

/* RFC1459 case folding: {}|~ are the lowercase of []\^ . */
static int
rfc_tolower(int c)
{
    switch (c) {
    case '[': return '{';
    case ']': return '}';
    case '\\': return '|';
    case '^': return '~';
    default:
        if (c >= 'A' && c <= 'Z')
            return c - 'A' + 'a';
        return c;
    }
}

static int
rfc_ieq(const char *a, const char *b)
{
    while (*a && *b) {
        if (rfc_tolower((unsigned char)*a) != rfc_tolower((unsigned char)*b))
            return 0;
        a++; b++;
    }
    return *a == *b;
}

/* bounded copy that always NUL-terminates */
static void
copy_str(char *dst, size_t dstsz, const char *src)
{
    size_t i = 0;
    if (dstsz == 0)
        return;
    if (src) {
        for (; i + 1 < dstsz && src[i]; i++)
            dst[i] = src[i];
    }
    dst[i] = '\0';
}

/* case-insensitive (RFC1459) glob with '*' and '?' */
static int
glob_match(const char *pat, const char *str, int fold)
{
    const char *star_pat = NULL, *star_str = NULL;

    while (*str) {
        if (*pat == '?' ||
            (fold ? rfc_tolower((unsigned char)*pat) ==
                        rfc_tolower((unsigned char)*str)
                  : *pat == *str)) {
            pat++; str++;
        } else if (*pat == '*') {
            star_pat = pat++;
            star_str = str;
        } else if (star_pat) {
            pat = star_pat + 1;
            str = ++star_str;
        } else {
            return 0;
        }
    }
    while (*pat == '*')
        pat++;
    return *pat == '\0';
}

/* Match an ip string against a pattern that may be a glob or CIDR. */
static int
ip_match(const char *pat, const char *ip)
{
    const char *slash = strchr(pat, '/');
    unsigned char net[16], addr[16];
    int bits, fam_net, fam_addr, nbytes, i;
    char base[64];
    size_t blen;

    if (!slash)
        return glob_match(pat, ip, 0);

    blen = (size_t)(slash - pat);
    if (blen >= sizeof(base))
        return 0;
    memcpy(base, pat, blen);
    base[blen] = '\0';
    bits = atoi(slash + 1);
    if (bits < 0)
        return 0;

    if (inet_pton(AF_INET, base, net) == 1)
        fam_net = AF_INET;
    else if (inet_pton(AF_INET6, base, net) == 1)
        fam_net = AF_INET6;
    else
        return 0;

    if (inet_pton(AF_INET, ip, addr) == 1)
        fam_addr = AF_INET;
    else if (inet_pton(AF_INET6, ip, addr) == 1)
        fam_addr = AF_INET6;
    else
        return 0;

    if (fam_net != fam_addr)
        return 0;

    nbytes = (fam_net == AF_INET) ? 4 : 16;
    if (bits > nbytes * 8)
        bits = nbytes * 8;

    for (i = 0; i < nbytes && bits > 0; i++) {
        int take = bits >= 8 ? 8 : bits;
        unsigned char mask = (unsigned char)(0xff << (8 - take));
        if ((net[i] & mask) != (addr[i] & mask))
            return 0;
        bits -= take;
    }
    return 1;
}

/****************************************************************
 * Output helpers
 ****************************************************************/

static void
send_raw(struct uircd *s, struct uircd_client *c, const char *buf, size_t len)
{
    if (c->dead)
        return;
    s->cfg.out(s->cfg.ud, c->host_conn, buf, len);
}

static void
sendf(struct uircd *s, struct uircd_client *c, const char *fmt, ...)
{
    char buf[560];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(buf, 510, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if (n > 509)
        n = 509;
    buf[n++] = '\r';
    buf[n++] = '\n';
    send_raw(s, c, buf, (size_t)n);
}

static const char *
srv_name(struct uircd *s)
{
    return s->cfg.server_name ? s->cfg.server_name : "uircd";
}

static const char *
cli_target(struct uircd_client *c)
{
    return c->registered ? c->nick : "*";
}

/* numeric reply: ":server NNN target ..." */
static void
numeric(struct uircd *s, struct uircd_client *c, int code, const char *fmt, ...)
{
    char tail[512];
    va_list ap;

    tail[0] = '\0';
    if (fmt) {
        va_start(ap, fmt);
        vsnprintf(tail, sizeof(tail), fmt, ap);
        va_end(ap);
    }
    sendf(s, c, ":%s %03d %s %s", srv_name(s), code, cli_target(c), tail);
}

/* Zero memory so the compiler does not elide the write as a dead store (as it
 * may for a plain memset on a buffer that is not read again). Kept self
 * contained so the library stays portable; the host example uses explicit_bzero
 * where _GNU_SOURCE provides it. */
static void
secure_wipe(void *p, size_t n)
{
    volatile unsigned char *v = p;

    while (n--)
        *v++ = 0;
}

/* Keyed hash of a real host into a display cloak "<hex>.cloak". The secret key
 * (per server run) keeps the mapping non-reversible, so an observer cannot
 * recover the real address from the cloak. */
static void
compute_cloak(struct uircd *s, const char *host, char *out, size_t outsz)
{
    uint64_t h = 1469598103934665603ULL ^ s->cfg.cloak_key;
    const unsigned char *p = (const unsigned char *)host;

    while (*p) {
        h ^= *p++;
        h *= 1099511628211ULL;
    }
    h ^= s->cfg.cloak_key;
    h *= 1099511628211ULL;
    snprintf(out, outsz, "%08x%08x.cloak",
             (unsigned)(h >> 32), (unsigned)(h & 0xffffffffu));
}

/* The host to show to other users: the cloak when cloaking is on, else the
 * real host. Operators are shown the real host through cmd_who directly. */
static const char *
vis_host(struct uircd_client *c)
{
    if (c->srv->cfg.host_cloak && c->cloak[0])
        return c->cloak;
    return c->host;
}

static void
cli_prefix(struct uircd_client *c, char *buf, size_t sz)
{
    const char *host = vis_host(c);

    snprintf(buf, sz, "%s!%s@%s",
             c->nick[0] ? c->nick : "*",
             c->user[0] ? c->user : "*",
             host[0] ? host : "*");
}

static void
logevt(struct uircd *s, const char *event, const char *detail)
{
    if (s->cfg.log)
        s->cfg.log(s->cfg.ud, event, detail);
}

/****************************************************************
 * Lookup
 ****************************************************************/

static struct uircd_client *
find_nick(struct uircd *s, const char *nick)
{
    unsigned i;
    for (i = 0; i < s->n_clients; i++) {
        struct uircd_client *c = s->clients[i];
        if (c->registered && rfc_ieq(c->nick, nick))
            return c;
    }
    return NULL;
}

static struct uircd_channel *
find_chan(struct uircd *s, const char *name)
{
    unsigned i;
    for (i = 0; i < s->n_channels; i++)
        if (rfc_ieq(s->channels[i]->name, name))
            return s->channels[i];
    return NULL;
}

static struct member *
chan_member(struct uircd_channel *ch, struct uircd_client *c)
{
    unsigned i;
    for (i = 0; i < ch->n_members; i++)
        if (ch->members[i].c == c)
            return &ch->members[i];
    return NULL;
}

static int
is_channel_name(const char *s)
{
    return s && (s[0] == '#' || s[0] == '&');
}

/****************************************************************
 * Channel membership
 ****************************************************************/

static void
chan_destroy(struct uircd *s, struct uircd_channel *ch)
{
    unsigned i;
    for (i = 0; i < s->n_channels; i++) {
        if (s->channels[i] == ch) {
            s->channels[i] = s->channels[s->n_channels - 1];
            s->n_channels--;
            break;
        }
    }
    free(ch->members);
    free(ch);
}

static struct uircd_channel *
chan_create(struct uircd *s, const char *name)
{
    struct uircd_channel *ch;

    if (s->n_channels >= s->max_channels)
        return NULL;
    if (s->n_channels == s->cap_channels) {
        unsigned nc = s->cap_channels ? s->cap_channels * 2 : 16;
        struct uircd_channel **p = realloc(s->channels, nc * sizeof(*p));
        if (!p)
            return NULL;
        s->channels = p;
        s->cap_channels = nc;
    }
    ch = calloc(1, sizeof(*ch));
    if (!ch)
        return NULL;
    copy_str(ch->name, sizeof(ch->name), name);
    ch->modes = CMODE_NOEXTERNAL | CMODE_TOPICLOCK;
    s->channels[s->n_channels++] = ch;
    return ch;
}

/* broadcast to all members; skip 'except' if non-NULL */
static void
chan_broadcast(struct uircd *s, struct uircd_channel *ch,
               struct uircd_client *except, const char *line)
{
    unsigned i;
    for (i = 0; i < ch->n_members; i++) {
        struct uircd_client *m = ch->members[i].c;
        if (m == except)
            continue;
        sendf(s, m, "%s", line);
    }
}

static int
client_in_chan(struct uircd_client *c, struct uircd_channel *ch)
{
    unsigned i;
    for (i = 0; i < c->n_chans; i++)
        if (c->chans[i] == ch)
            return 1;
    return 0;
}

static void
chan_remove_member(struct uircd *s, struct uircd_channel *ch,
                   struct uircd_client *c)
{
    unsigned i;

    for (i = 0; i < ch->n_members; i++) {
        if (ch->members[i].c == c) {
            ch->members[i] = ch->members[ch->n_members - 1];
            ch->n_members--;
            break;
        }
    }
    for (i = 0; i < c->n_chans; i++) {
        if (c->chans[i] == ch) {
            c->chans[i] = c->chans[c->n_chans - 1];
            c->n_chans--;
            break;
        }
    }
    if (ch->n_members == 0)
        chan_destroy(s, ch);
}

static int
chan_add_member(struct uircd *s, struct uircd_channel *ch,
                struct uircd_client *c, unsigned flags)
{
    (void)s;
    if (c->n_chans >= CHANS_PER_CLIENT)
        return -1;
    if (ch->n_members == ch->cap_members) {
        unsigned nc = ch->cap_members ? ch->cap_members * 2 : 8;
        struct member *p = realloc(ch->members, nc * sizeof(*p));
        if (!p)
            return -1;
        ch->members = p;
        ch->cap_members = nc;
    }
    ch->members[ch->n_members].c = c;
    ch->members[ch->n_members].flags = flags;
    ch->n_members++;
    c->chans[c->n_chans++] = ch;
    return 0;
}

/****************************************************************
 * Query / match engine
 ****************************************************************/

static enum field
field_from_name(const char *name, size_t len)
{
    if (len == 4 && !strncasecmp(name, "nick", 4)) return F_NICK;
    if (len == 4 && !strncasecmp(name, "user", 4)) return F_USER;
    if (len == 4 && !strncasecmp(name, "host", 4)) return F_HOST;
    if (len == 2 && !strncasecmp(name, "ip", 2)) return F_IP;
    if (len == 4 && !strncasecmp(name, "real", 4)) return F_REAL;
    if (len == 4 && !strncasecmp(name, "chan", 4)) return F_CHAN;
    if (len == 7 && !strncasecmp(name, "account", 7)) return F_ACCOUNT;
    return F_INVALID;
}

/* parse one term "field=glob" or "field!=glob" */
static int
parse_term(const char *tok, struct term *t)
{
    const char *eq = strchr(tok, '=');
    const char *name_end;
    size_t plen;

    if (!eq || eq == tok)
        return -1;
    name_end = eq;
    t->negate = 0;
    if (eq > tok && eq[-1] == '!') {
        t->negate = 1;
        name_end = eq - 1;
        if (name_end == tok)
            return -1;
    }
    t->field = field_from_name(tok, (size_t)(name_end - tok));
    if (t->field == F_INVALID)
        return -1;
    plen = strlen(eq + 1);
    if (plen == 0 || plen >= PATLEN)
        return -1;
    memcpy(t->pat, eq + 1, plen + 1);
    return 0;
}

/* split a query on spaces into terms; returns count or -1 on error */
static int
parse_query(const char *q, struct term *terms, int maxterms)
{
    int n = 0;
    const char *p = q;

    while (*p) {
        const char *start;
        char tok[PATLEN + 32];
        size_t len;

        while (*p == ' ')
            p++;
        if (!*p)
            break;
        start = p;
        while (*p && *p != ' ')
            p++;
        len = (size_t)(p - start);
        if (len >= sizeof(tok))
            return -1;
        memcpy(tok, start, len);
        tok[len] = '\0';
        if (n >= maxterms)
            return -1;
        if (parse_term(tok, &terms[n]) < 0)
            return -1;
        n++;
    }
    return n;
}

static int
client_field_match(struct uircd_client *c, const struct term *t)
{
    unsigned i;

    switch (t->field) {
    case F_NICK: return glob_match(t->pat, c->nick, 1);
    case F_USER: return glob_match(t->pat, c->user, 1);
    case F_HOST: return glob_match(t->pat, c->host, 1);
    case F_IP:   return ip_match(t->pat, c->host);
    case F_REAL: return glob_match(t->pat, c->real, 0);
    case F_ACCOUNT: return glob_match(t->pat, c->acct, 1);
    case F_CHAN:
        for (i = 0; i < c->n_chans; i++)
            if (glob_match(t->pat, c->chans[i]->name, 1))
                return 1;
        return 0;
    default:
        return 0;
    }
}

/* A single term's verdict, honoring a '!=' negation. */
static int
term_matches(struct uircd_client *c, const struct term *t)
{
    int m = client_field_match(c, t);
    return t->negate ? !m : m;
}

static int
client_matches(struct uircd_client *c, const struct term *terms, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        if (!term_matches(c, &terms[i]))
            return 0;
    }
    return n > 0;
}

/****************************************************************
 * Client destruction
 ****************************************************************/

static void
part_all_channels(struct uircd *s, struct uircd_client *c, const char *reason)
{
    char prefix[NICK_MAX + USER_MAX + HOST_MAX + 4];
    char line[560];

    cli_prefix(c, prefix, sizeof(prefix));
    snprintf(line, sizeof(line), ":%s QUIT :%s", prefix,
             reason ? reason : "Client exited");

    /* Notify every channel peer once. Walk a copy of membership because
     * removing members mutates c->chans. */
    while (c->n_chans > 0) {
        struct uircd_channel *ch = c->chans[0];
        unsigned i;
        for (i = 0; i < ch->n_members; i++) {
            struct uircd_client *m = ch->members[i].c;
            if (m != c)
                sendf(s, m, "%s", line);
        }
        chan_remove_member(s, ch, c);
    }
}

/* Remove a client from the server. Does not notify the host; the caller or
 * uircd_closed()/drop() handles the socket. */
static void
client_free(struct uircd *s, struct uircd_client *c)
{
    unsigned i;

    for (i = 0; i < s->n_clients; i++) {
        if (s->clients[i] == c) {
            s->clients[i] = s->clients[s->n_clients - 1];
            s->n_clients--;
            break;
        }
    }
    /* The client struct and its hold buffer may still hold plaintext
     * credential bytes (a connection closed mid-authentication); wipe both
     * before freeing so they do not linger on the heap. */
    if (c->hold)
        secure_wipe(c->hold, c->hold_cap);
    free(c->hold);
    secure_wipe(c, sizeof(*c));
    free(c);
}

/* Fully quit a client: notify peers, drop the socket, free. After this the
 * handle is invalid. */
static void
client_quit(struct uircd *s, struct uircd_client *c, const char *reason)
{
    if (c->dead)
        return;
    c->dead = 1;
    if (c->registered)
        part_all_channels(s, c, reason);
    else {
        while (c->n_chans > 0)
            chan_remove_member(s, c->chans[0], c);
    }
    logevt(s, "quit", c->nick[0] ? c->nick : c->host);
    s->cfg.drop(s->cfg.ud, c->host_conn);
    client_free(s, c);
}

/****************************************************************
 * Registration
 ****************************************************************/

static void
send_isupport(struct uircd *s, struct uircd_client *c)
{
    numeric(s, c, 5,
            "CASEMAPPING=rfc1459 CHANTYPES=#& NICKLEN=%d CHANNELLEN=%d "
            "TOPICLEN=%d NETWORK=%s :are supported by this server",
            NICK_MAX, CHAN_MAX, TOPIC_MAX,
            s->cfg.network ? s->cfg.network : "uircd");
}

static void
send_motd(struct uircd *s, struct uircd_client *c)
{
    const char *motd = s->cfg.motd;

    if (!motd) {
        numeric(s, c, 422, ":MOTD File is missing");
        return;
    }
    numeric(s, c, 375, ":- %s Message of the day -", srv_name(s));
    while (*motd) {
        const char *nl = strchr(motd, '\n');
        size_t len = nl ? (size_t)(nl - motd) : strlen(motd);
        if (len > 400)
            len = 400;
        numeric(s, c, 372, ":- %.*s", (int)len, motd);
        if (!nl)
            break;
        motd = nl + 1;
    }
    numeric(s, c, 376, ":End of /MOTD command");
}

static void
complete_registration(struct uircd *s, struct uircd_client *c)
{
    const char *ver = s->cfg.version ? s->cfg.version : "uircd";

    c->registered = 1;
    numeric(s, c, 1, ":Welcome to the %s IRC Network %s",
            s->cfg.network ? s->cfg.network : "uircd", c->nick);
    numeric(s, c, 2, ":Your host is %s, running version %s",
            srv_name(s), ver);
    numeric(s, c, 3, ":This server is running uircd");
    numeric(s, c, 4, "%s %s io ont", srv_name(s), ver);
    send_isupport(s, c);
    numeric(s, c, 251, ":There are %u users on the server",
            s->n_clients);
    send_motd(s, c);
    logevt(s, "register", c->nick);
}

static int
nick_in_use(struct uircd *s, const char *nick, struct uircd_client *self)
{
    struct uircd_client *o = find_nick(s, nick);
    return o && o != self;
}

static int
valid_nick(const char *nick)
{
    size_t i, len = strlen(nick);
    if (len == 0 || len > NICK_MAX)
        return 0;
    if (isdigit((unsigned char)nick[0]) || nick[0] == '-')
        return 0;
    for (i = 0; i < len; i++) {
        char ch = nick[i];
        if (!(isalnum((unsigned char)ch) || strchr("[]\\`_^{|}-", ch)))
            return 0;
    }
    return 1;
}

static int
valid_chan(const char *name)
{
    size_t i, len = strlen(name);
    if (len < 2 || len > CHAN_MAX)
        return 0;
    if (!is_channel_name(name))
        return 0;
    for (i = 1; i < len; i++)
        if (name[i] == ' ' || name[i] == ',' || name[i] == 7)
            return 0;
    return 1;
}

/* returns 1 if the client was killed */
static int
try_register(struct uircd *s, struct uircd_client *c)
{
    if (c->registered)
        return 0;
    if (!c->got_nick || !c->got_user)
        return 0;
    if (s->cfg.require_login && !c->authed) {
        numeric(s, c, 464, ":You must authenticate (PASS) to connect");
        client_quit(s, c, "Authentication required");
        return 1;
    }
    complete_registration(s, c);
    return 0;
}

/****************************************************************
 * Command handlers
 *
 * Each returns 1 if the client was destroyed, else 0.
 ****************************************************************/

struct msg {
    const char *cmd;
    char *argv[MAXPARAMS];
    int argc;
};

static int need_params(struct uircd *s, struct uircd_client *c,
                       struct msg *m, int n)
{
    if (m->argc < n) {
        numeric(s, c, 461, "%s :Not enough parameters", m->cmd);
        return 1;
    }
    return 0;
}

static int
cmd_nick(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    char old[NICK_MAX + 1];
    char prefix[128];

    if (m->argc < 1) {
        numeric(s, c, 431, ":No nickname given");
        return 0;
    }
    if (!valid_nick(m->argv[0])) {
        numeric(s, c, 432, "%s :Erroneous nickname", m->argv[0]);
        return 0;
    }
    if (nick_in_use(s, m->argv[0], c)) {
        numeric(s, c, 433, "%s :Nickname is already in use", m->argv[0]);
        return 0;
    }
    copy_str(old, sizeof(old), c->nick);
    if (c->registered && old[0]) {
        unsigned i, j;
        cli_prefix(c, prefix, sizeof(prefix));
        /* tell the user; a peer in several shared channels may see it more
         * than once, which clients tolerate -- de-duping is not worth the
         * per-client marking a minimal server avoids. */
        sendf(s, c, ":%s NICK :%s", prefix, m->argv[0]);
        for (i = 0; i < c->n_chans; i++) {
            struct uircd_channel *ch = c->chans[i];
            for (j = 0; j < ch->n_members; j++) {
                struct uircd_client *peer = ch->members[j].c;
                if (peer != c)
                    sendf(s, peer, ":%s NICK :%s", prefix, m->argv[0]);
            }
        }
    }
    copy_str(c->nick, sizeof(c->nick), m->argv[0]);
    c->got_nick = 1;
    return try_register(s, c);
}

static int
cmd_user(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    if (c->registered) {
        numeric(s, c, 462, ":You may not reregister");
        return 0;
    }
    if (need_params(s, c, m, 4))
        return 0;
    /* user[0] = username, user[3] = realname */
    if (c->user[0] == '\0') {
        c->user[0] = '~';
        copy_str(c->user + 1, sizeof(c->user) - 1, m->argv[0]);
    }
    copy_str(c->real, sizeof(c->real), m->argv[3]);
    c->got_user = 1;
    return try_register(s, c);
}

static void
grant_oper(struct uircd *s, struct uircd_client *c)
{
    c->umodes |= UMODE_OPER;
    numeric(s, c, 381, ":You are now an IRC operator");
    sendf(s, c, ":%s MODE %s :+o", srv_name(s), c->nick);
    logevt(s, "oper", c->nick);
}

static int
cmd_pass(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    char *colon;
    const char *name = NULL, *secret;

    c->scrub_line = 1; /* this line carries a password; wipe it after dispatch */
    if (c->registered) {
        numeric(s, c, 462, ":You may not reregister");
        return 0;
    }
    if (c->auth_pending)
        return 0; /* one auth in flight per client; ignore until it resolves */
    if (need_params(s, c, m, 1))
        return 0;
    secret = m->argv[0];
    colon = strchr(m->argv[0], ':');
    if (colon) {
        *colon = '\0';
        name = m->argv[0];
        secret = colon + 1;
    }
    if (s->cfg.auth) {
        int rc = s->cfg.auth(s->cfg.ud, c->host_conn, UIRCD_AUTH_USER,
                             name, secret);
        if (rc == UIRCD_OK) {
            c->authed = 1;
            if (name)
                copy_str(c->acct, sizeof(c->acct), name);
            return 0;
        }
        if (rc == UIRCD_AUTH_PENDING) {
            c->auth_pending = 1;
            c->auth_kind = UIRCD_AUTH_USER;
            if (name)
                copy_str(c->auth_acct, sizeof(c->auth_acct), name);
            else
                c->auth_acct[0] = '\0';
            return 0;
        }
    }
    if (s->cfg.require_login)
        numeric(s, c, 464, ":Password incorrect");
    return 0;
}

static int
cmd_oper(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    c->scrub_line = 1; /* this line carries a password; wipe it after dispatch */
    if (need_params(s, c, m, 2))
        return 0;
    if (c->auth_pending)
        return 0; /* one auth in flight per client */
    if (s->cfg.auth) {
        int rc = s->cfg.auth(s->cfg.ud, c->host_conn, UIRCD_AUTH_OPER,
                             m->argv[0], m->argv[1]);
        if (rc == UIRCD_AUTH_PENDING) {
            c->auth_pending = 1;
            c->auth_kind = UIRCD_AUTH_OPER;
            return 0;
        }
        if (rc == UIRCD_OK) {
            grant_oper(s, c);
            return 0;
        }
    }
    numeric(s, c, 491, ":No O-lines for your host");
    return 0;
}

static int
cmd_join(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    char list[512];
    char *name, *save = NULL;
    const char *keys;
    char keybuf[256];
    char *keyp = NULL, *keysave = NULL;

    if (need_params(s, c, m, 1))
        return 0;
    copy_str(list, sizeof(list), m->argv[0]);
    keys = m->argc > 1 ? m->argv[1] : "";
    copy_str(keybuf, sizeof(keybuf), keys);
    keyp = strtok_r(keybuf, ",", &keysave);

    for (name = strtok_r(list, ",", &save); name;
         name = strtok_r(NULL, ",", &save)) {
        struct uircd_channel *ch;
        char prefix[128];
        unsigned i;
        const char *thiskey = keyp;

        if (keyp)
            keyp = strtok_r(NULL, ",", &keysave);

        if (!valid_chan(name)) {
            numeric(s, c, 403, "%s :No such channel", name);
            continue;
        }
        ch = find_chan(s, name);
        if (ch && client_in_chan(c, ch))
            continue;
        if (!ch) {
            ch = chan_create(s, name);
            if (!ch) {
                numeric(s, c, 405, "%s :You have joined too many channels",
                        name);
                continue;
            }
            if (chan_add_member(s, ch, c, MEMB_OP) < 0) {
                chan_destroy(s, ch);
                numeric(s, c, 405, "%s :You have joined too many channels",
                        name);
                continue;
            }
        } else {
            if ((ch->modes & CMODE_KEYED) &&
                !(c->umodes & UMODE_OPER) &&
                strcmp(ch->key, thiskey ? thiskey : "") != 0) {
                numeric(s, c, 475, "%s :Cannot join channel (+k)", name);
                continue;
            }
            if (chan_add_member(s, ch, c, 0) < 0) {
                numeric(s, c, 405, "%s :You have joined too many channels",
                        name);
                continue;
            }
        }
        cli_prefix(c, prefix, sizeof(prefix));
        /* announce join to all members including self */
        for (i = 0; i < ch->n_members; i++)
            sendf(s, ch->members[i].c, ":%s JOIN :%s", prefix, ch->name);
        if (ch->has_topic)
            numeric(s, c, 332, "%s :%s", ch->name, ch->topic);
        else
            numeric(s, c, 331, "%s :No topic is set", ch->name);
        /* NAMES */
        {
            char names[512];
            size_t off = 0;
            names[0] = '\0';
            for (i = 0; i < ch->n_members; i++) {
                struct member *mm = &ch->members[i];
                const char *pfx = (mm->flags & MEMB_OP) ? "@" :
                                  (mm->flags & MEMB_VOICE) ? "+" : "";
                int n = snprintf(names + off, sizeof(names) - off,
                                 "%s%s%s", off ? " " : "", pfx, mm->c->nick);
                if (n < 0 || (size_t)n >= sizeof(names) - off)
                    break;
                off += (size_t)n;
            }
            numeric(s, c, 353, "= %s :%s", ch->name, names);
            numeric(s, c, 366, "%s :End of /NAMES list", ch->name);
        }
    }
    return 0;
}

static int
cmd_part(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    char list[512];
    char *name, *save = NULL;
    const char *reason = m->argc > 1 ? m->argv[1] : "Leaving";
    char prefix[128];

    if (need_params(s, c, m, 1))
        return 0;
    cli_prefix(c, prefix, sizeof(prefix));
    copy_str(list, sizeof(list), m->argv[0]);
    for (name = strtok_r(list, ",", &save); name;
         name = strtok_r(NULL, ",", &save)) {
        struct uircd_channel *ch = find_chan(s, name);
        if (!ch) {
            numeric(s, c, 403, "%s :No such channel", name);
            continue;
        }
        if (!client_in_chan(c, ch)) {
            numeric(s, c, 442, "%s :You're not on that channel", name);
            continue;
        }
        {
            char line[560];
            snprintf(line, sizeof(line), ":%s PART %s :%s",
                     prefix, ch->name, reason);
            chan_broadcast(s, ch, NULL, line);
        }
        chan_remove_member(s, ch, c);
    }
    return 0;
}

static int
deliver_message(struct uircd *s, struct uircd_client *c, struct msg *m,
                const char *cmd, int notice)
{
    const char *target = m->argv[0];
    const char *text = m->argv[1];
    char prefix[128];

    cli_prefix(c, prefix, sizeof(prefix));

    if (is_channel_name(target)) {
        struct uircd_channel *ch = find_chan(s, target);
        struct member *mem;
        char line[560];
        if (!ch) {
            if (!notice)
                numeric(s, c, 403, "%s :No such channel", target);
            return 0;
        }
        mem = chan_member(ch, c);
        if (!mem && (ch->modes & CMODE_NOEXTERNAL)) {
            if (!notice)
                numeric(s, c, 404, "%s :Cannot send to channel", target);
            return 0;
        }
        if ((ch->modes & CMODE_MODERATED) && !(c->umodes & UMODE_OPER) &&
            !(mem && (mem->flags & (MEMB_OP | MEMB_VOICE)))) {
            if (!notice)
                numeric(s, c, 404, "%s :Cannot send to channel (+m)", target);
            return 0;
        }
        snprintf(line, sizeof(line), ":%s %s %s :%s",
                 prefix, cmd, ch->name, text ? text : "");
        chan_broadcast(s, ch, c, line);
        return 0;
    }

    {
        struct uircd_client *dst = find_nick(s, target);
        if (!dst) {
            if (!notice)
                numeric(s, c, 401, "%s :No such nick/channel", target);
            return 0;
        }
        sendf(s, dst, ":%s %s %s :%s", prefix, cmd, dst->nick,
              text ? text : "");
    }
    return 0;
}

static int
cmd_privmsg(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    if (m->argc < 1) {
        numeric(s, c, 411, ":No recipient given (PRIVMSG)");
        return 0;
    }
    if (m->argc < 2) {
        numeric(s, c, 412, ":No text to send");
        return 0;
    }
    return deliver_message(s, c, m, "PRIVMSG", 0);
}

static int
cmd_notice(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    if (m->argc < 2)
        return 0;
    return deliver_message(s, c, m, "NOTICE", 1);
}

static int
cmd_topic(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    struct uircd_channel *ch;
    struct member *mem;
    char prefix[128];
    char line[560];

    if (need_params(s, c, m, 1))
        return 0;
    ch = find_chan(s, m->argv[0]);
    if (!ch) {
        numeric(s, c, 403, "%s :No such channel", m->argv[0]);
        return 0;
    }
    if (m->argc < 2) {
        if (ch->has_topic)
            numeric(s, c, 332, "%s :%s", ch->name, ch->topic);
        else
            numeric(s, c, 331, "%s :No topic is set", ch->name);
        return 0;
    }
    mem = chan_member(ch, c);
    if (!mem) {
        numeric(s, c, 442, "%s :You're not on that channel", ch->name);
        return 0;
    }
    if ((ch->modes & CMODE_TOPICLOCK) && !(mem->flags & MEMB_OP) &&
        !(c->umodes & UMODE_OPER)) {
        numeric(s, c, 482, "%s :You're not channel operator", ch->name);
        return 0;
    }
    copy_str(ch->topic, sizeof(ch->topic), m->argv[1]);
    ch->has_topic = ch->topic[0] != '\0';
    copy_str(ch->topic_by, sizeof(ch->topic_by), c->nick);
    cli_prefix(c, prefix, sizeof(prefix));
    snprintf(line, sizeof(line), ":%s TOPIC %s :%s",
             prefix, ch->name, ch->topic);
    chan_broadcast(s, ch, NULL, line);
    return 0;
}

static int
cmd_names(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    struct uircd_channel *ch;
    char names[512];
    size_t off = 0;
    unsigned i;

    if (m->argc < 1) {
        numeric(s, c, 366, "* :End of /NAMES list");
        return 0;
    }
    ch = find_chan(s, m->argv[0]);
    if (!ch) {
        numeric(s, c, 366, "%s :End of /NAMES list", m->argv[0]);
        return 0;
    }
    names[0] = '\0';
    for (i = 0; i < ch->n_members; i++) {
        struct member *mm = &ch->members[i];
        const char *pfx = (mm->flags & MEMB_OP) ? "@" :
                          (mm->flags & MEMB_VOICE) ? "+" : "";
        int n = snprintf(names + off, sizeof(names) - off,
                         "%s%s%s", off ? " " : "", pfx, mm->c->nick);
        if (n < 0 || (size_t)n >= sizeof(names) - off)
            break;
        off += (size_t)n;
    }
    numeric(s, c, 353, "= %s :%s", ch->name, names);
    numeric(s, c, 366, "%s :End of /NAMES list", ch->name);
    return 0;
}

static int
cmd_list(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    unsigned i;
    (void)m;
    numeric(s, c, 321, "Channel :Users  Name");
    for (i = 0; i < s->n_channels; i++) {
        struct uircd_channel *ch = s->channels[i];
        numeric(s, c, 322, "%s %u :%s", ch->name, ch->n_members,
                ch->has_topic ? ch->topic : "");
    }
    numeric(s, c, 323, ":End of /LIST");
    return 0;
}

static int
cmd_who(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    const char *mask = m->argc > 0 ? m->argv[0] : "*";
    struct uircd_channel *ch = is_channel_name(mask) ? find_chan(s, mask)
                                                     : NULL;
    unsigned i;

    if (ch) {
        for (i = 0; i < ch->n_members; i++) {
            struct uircd_client *t = ch->members[i].c;
            const char *fl = (ch->members[i].flags & MEMB_OP) ? "H@" :
                             (ch->members[i].flags & MEMB_VOICE) ? "H+" : "H";
            const char *wh = (c->umodes & UMODE_OPER) ? t->host : vis_host(t);
            numeric(s, c, 352, "%s %s %s %s %s %s :0 %s",
                    ch->name, t->user, wh, srv_name(s), t->nick, fl,
                    t->real);
        }
    } else {
        for (i = 0; i < s->n_clients; i++) {
            struct uircd_client *t = s->clients[i];
            if (!t->registered)
                continue;
            if (!glob_match(mask, t->nick, 1) && strcmp(mask, "*") != 0)
                continue;
            numeric(s, c, 352, "* %s %s %s %s H :0 %s",
                    t->user, (c->umodes & UMODE_OPER) ? t->host : vis_host(t),
                    srv_name(s), t->nick, t->real);
        }
    }
    numeric(s, c, 315, "%s :End of /WHO list", mask);
    return 0;
}

static int
cmd_whois(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    struct uircd_client *t;
    const char *nick, *host;
    char chans[400];
    size_t cl = 0;
    unsigned i;

    if (need_params(s, c, m, 1))
        return 0;
    /* "WHOIS <nick>" or "WHOIS <server> <nick>": the target is the last arg. */
    nick = m->argv[m->argc - 1];
    t = find_nick(s, nick);
    if (!t || !t->registered) {
        numeric(s, c, 401, "%s :No such nick/channel", nick);
        numeric(s, c, 318, "%s :End of /WHOIS list", nick);
        return 0;
    }

    /* 311: an operator sees the real host, others see the cloak (as in WHO). */
    host = (c->umodes & UMODE_OPER) ? t->host : vis_host(t);
    numeric(s, c, 311, "%s %s %s * :%s", t->nick, t->user, host, t->real);

    /* 319: the channels the target is on, each with the viewer-agnostic prefix. */
    for (i = 0; i < t->n_chans; i++) {
        struct uircd_channel *ch = t->chans[i];
        struct member *mm = chan_member(ch, t);
        const char *pfx = "";
        int n;

        if (mm)
            pfx = (mm->flags & MEMB_OP) ? "@" :
                  (mm->flags & MEMB_VOICE) ? "+" : "";
        n = snprintf(chans + cl, sizeof(chans) - cl, "%s%s ", pfx, ch->name);
        if (n < 0 || (size_t)n >= sizeof(chans) - cl)
            break; /* stop at the buffer bound rather than truncate mid-name */
        cl += (size_t)n;
    }
    if (cl > 0) {
        chans[cl - 1] = '\0'; /* drop the trailing space */
        numeric(s, c, 319, "%s :%s", t->nick, chans);
    }

    numeric(s, c, 312, "%s %s :%s", t->nick, srv_name(s), srv_name(s));
    if (t->umodes & UMODE_OPER)
        numeric(s, c, 313, "%s :is an IRC operator", t->nick);
    numeric(s, c, 318, "%s :End of /WHOIS list", t->nick);
    return 0;
}

/* Minimal IRCv3 capability negotiation. The server offers no capabilities, so
 * it answers CAP LS/LIST with an empty list and NAKs any request; this lets a
 * client (which sends CAP LS on connect) finish negotiation at once instead of
 * waiting for a reply that never comes. END and the rest need no action. */
static int
cmd_cap(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    const char *sub, *tgt;

    if (m->argc < 1)
        return 0;
    sub = m->argv[0];
    tgt = c->nick[0] ? c->nick : "*";
    if (!strcasecmp(sub, "LS"))
        sendf(s, c, ":%s CAP %s LS :", srv_name(s), tgt);
    else if (!strcasecmp(sub, "LIST"))
        sendf(s, c, ":%s CAP %s LIST :", srv_name(s), tgt);
    else if (!strcasecmp(sub, "REQ"))
        sendf(s, c, ":%s CAP %s NAK :%s", srv_name(s), tgt,
              m->argc > 1 ? m->argv[1] : "");
    return 0;
}

static void
apply_chan_mode(struct uircd *s, struct uircd_client *c,
                struct uircd_channel *ch, struct msg *m)
{
    const char *spec = m->argv[1];
    int adding = 1;
    int argi = 2;
    char applied[64];
    char args_out[256];
    size_t ao = 0, go = 0;
    char prefix[128];

    applied[0] = '\0';
    args_out[0] = '\0';

    for (; *spec; spec++) {
        unsigned bit = 0;
        char ch2 = *spec;
        if (ch2 == '+') { adding = 1; if (ao < 60) applied[ao++] = '+'; continue; }
        if (ch2 == '-') { adding = 0; if (ao < 60) applied[ao++] = '-'; continue; }
        switch (ch2) {
        case 't': bit = CMODE_TOPICLOCK; break;
        case 'n': bit = CMODE_NOEXTERNAL; break;
        case 'm': bit = CMODE_MODERATED; break;
        case 'k': {
            const char *key = argi < m->argc ? m->argv[argi++] : "";
            if (adding) {
                copy_str(ch->key, sizeof(ch->key), key);
                ch->modes |= CMODE_KEYED;
            } else {
                ch->modes &= ~CMODE_KEYED;
                ch->key[0] = '\0';
            }
            if (ao < 60) applied[ao++] = 'k';
            go += (size_t)snprintf(args_out + go, sizeof(args_out) - go,
                                   " %s", adding ? ch->key : "*");
            continue;
        }
        case 'o':
        case 'v': {
            unsigned mf = (ch2 == 'o') ? MEMB_OP : MEMB_VOICE;
            struct uircd_client *t;
            struct member *tm;
            if (argi >= m->argc)
                continue;
            t = find_nick(s, m->argv[argi]);
            tm = t ? chan_member(ch, t) : NULL;
            if (!tm) {
                numeric(s, c, 441, "%s %s :They aren't on that channel",
                        m->argv[argi], ch->name);
                argi++;
                continue;
            }
            if (adding)
                tm->flags |= mf;
            else
                tm->flags &= ~mf;
            if (ao < 60) applied[ao++] = ch2;
            go += (size_t)snprintf(args_out + go, sizeof(args_out) - go,
                                   " %s", m->argv[argi]);
            argi++;
            continue;
        }
        default:
            numeric(s, c, 472, "%c :is unknown mode char to me", ch2);
            continue;
        }
        if (bit) {
            if (adding) ch->modes |= bit;
            else ch->modes &= ~bit;
            if (ao < 60) applied[ao++] = ch2;
        }
    }
    applied[ao] = '\0';
    if (ao == 0 || (ao == 1 && (applied[0] == '+' || applied[0] == '-')))
        return;
    (void)go;
    cli_prefix(c, prefix, sizeof(prefix));
    {
        char line[560];
        snprintf(line, sizeof(line), ":%s MODE %s %s%s",
                 prefix, ch->name, applied, args_out);
        chan_broadcast(s, ch, NULL, line);
    }
}

static int
cmd_mode(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    if (need_params(s, c, m, 1))
        return 0;

    if (is_channel_name(m->argv[0])) {
        struct uircd_channel *ch = find_chan(s, m->argv[0]);
        struct member *mem;
        if (!ch) {
            numeric(s, c, 403, "%s :No such channel", m->argv[0]);
            return 0;
        }
        if (m->argc < 2) {
            char buf[32];
            size_t k = 0;
            buf[k++] = '+';
            if (ch->modes & CMODE_TOPICLOCK) buf[k++] = 't';
            if (ch->modes & CMODE_NOEXTERNAL) buf[k++] = 'n';
            if (ch->modes & CMODE_MODERATED) buf[k++] = 'm';
            if (ch->modes & CMODE_KEYED) buf[k++] = 'k';
            buf[k] = '\0';
            numeric(s, c, 324, "%s %s", ch->name, buf);
            return 0;
        }
        /* A bare list-mode letter (e.g. "MODE #c b") is a query, not a change:
         * a client sends it on join. Return the (empty) list rather than 482.
         * These lists are not implemented, so only the end numerics are sent. */
        if (m->argc == 2) {
            const char *q = m->argv[1];
            if (*q == '+')
                q++;
            if (q[0] && !q[1]) {
                if (*q == 'b') {
                    numeric(s, c, 368, "%s :End of channel ban list", ch->name);
                    return 0;
                }
                if (*q == 'e') {
                    numeric(s, c, 349, "%s :End of channel exception list",
                            ch->name);
                    return 0;
                }
                if (*q == 'I') {
                    numeric(s, c, 347, "%s :End of channel invite list",
                            ch->name);
                    return 0;
                }
            }
        }
        mem = chan_member(ch, c);
        if ((!mem || !(mem->flags & MEMB_OP)) && !(c->umodes & UMODE_OPER)) {
            numeric(s, c, 482, "%s :You're not channel operator", ch->name);
            return 0;
        }
        apply_chan_mode(s, c, ch, m);
        return 0;
    }

    /* user mode: only self */
    if (!rfc_ieq(m->argv[0], c->nick)) {
        numeric(s, c, 502, ":Cannot change mode for other users");
        return 0;
    }
    if (m->argc < 2) {
        char buf[8];
        size_t k = 0;
        buf[k++] = '+';
        if (c->umodes & UMODE_INVISIBLE) buf[k++] = 'i';
        if (c->umodes & UMODE_OPER) buf[k++] = 'o';
        buf[k] = '\0';
        numeric(s, c, 221, "%s", buf);
        return 0;
    }
    {
        const char *p = m->argv[1];
        int adding = 1;
        for (; *p; p++) {
            if (*p == '+') adding = 1;
            else if (*p == '-') adding = 0;
            else if (*p == 'i') {
                if (adding) c->umodes |= UMODE_INVISIBLE;
                else c->umodes &= ~UMODE_INVISIBLE;
            } else if (*p == 'o') {
                if (!adding) c->umodes &= ~UMODE_OPER; /* cannot self-oper */
            }
        }
        sendf(s, c, ":%s MODE %s :%s", c->nick, c->nick, m->argv[1]);
    }
    return 0;
}

static int
cmd_kick(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    struct uircd_channel *ch;
    struct member *mem;
    struct uircd_client *victim;
    const char *reason;
    char prefix[128];
    char line[560];

    if (need_params(s, c, m, 2))
        return 0;
    ch = find_chan(s, m->argv[0]);
    if (!ch) {
        numeric(s, c, 403, "%s :No such channel", m->argv[0]);
        return 0;
    }
    mem = chan_member(ch, c);
    if ((!mem || !(mem->flags & MEMB_OP)) && !(c->umodes & UMODE_OPER)) {
        numeric(s, c, 482, "%s :You're not channel operator", ch->name);
        return 0;
    }
    victim = find_nick(s, m->argv[1]);
    if (!victim || !client_in_chan(victim, ch)) {
        numeric(s, c, 441, "%s %s :They aren't on that channel",
                m->argv[1], ch->name);
        return 0;
    }
    reason = m->argc > 2 ? m->argv[2] : c->nick;
    cli_prefix(c, prefix, sizeof(prefix));
    snprintf(line, sizeof(line), ":%s KICK %s %s :%s",
             prefix, ch->name, victim->nick, reason);
    chan_broadcast(s, ch, NULL, line);
    chan_remove_member(s, ch, victim);
    return 0;
}

static int
cmd_ping(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    sendf(s, c, ":%s PONG %s :%s", srv_name(s), srv_name(s),
          m->argc > 0 ? m->argv[0] : srv_name(s));
    return 0;
}

static int
cmd_quit(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    char reason[256];
    snprintf(reason, sizeof(reason), "Quit: %s",
             m->argc > 0 ? m->argv[0] : "Client Quit");
    sendf(s, c, "ERROR :Closing link: %s", reason);
    client_quit(s, c, reason);
    return 1;
}

/****************************************************************
 * Operator / administrative commands
 ****************************************************************/

static int
require_oper(struct uircd *s, struct uircd_client *c)
{
    if (!(c->umodes & UMODE_OPER)) {
        numeric(s, c, 481, ":Permission Denied - You're not an IRC operator");
        return 0;
    }
    return 1;
}

static int
cmd_kill(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    struct uircd_client *victim;
    const char *reason;
    int self;

    if (!require_oper(s, c))
        return 0;
    if (need_params(s, c, m, 1))
        return 0;
    victim = find_nick(s, m->argv[0]);
    if (!victim) {
        numeric(s, c, 401, "%s :No such nick/channel", m->argv[0]);
        return 0;
    }
    reason = m->argc > 1 ? m->argv[1] : "Killed";
    self = (victim == c);
    sendf(s, victim, "ERROR :Closing link: Killed by %s (%s)",
          c->nick, reason);
    {
        char detail[128];
        snprintf(detail, sizeof(detail), "%s killed %s", c->nick,
                 victim->nick);
        logevt(s, "kill", detail);
    }
    client_quit(s, victim, reason);
    return self;
}

/* KLINE <term> [:reason]  -- ban and disconnect matches */
static int
cmd_kline(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    int killed;
    const char *reason;
    struct term t;
    int self_dead = 0;

    if (!require_oper(s, c))
        return 0;
    if (need_params(s, c, m, 1))
        return 0;
    reason = m->argc > 1 ? m->argv[1] : "Banned";
    /* A ban that matches the operator's own connection makes uircd_ban_add()
     * free this client. Detect that first so we never touch c afterwards. */
    if (parse_term(m->argv[0], &t) == 0 && client_field_match(c, &t))
        self_dead = 1;
    killed = uircd_ban_add(s, m->argv[0], reason);
    if (killed < 0) {
        numeric(s, c, 461, "KLINE :Malformed ban spec (use field=glob)");
        return 0;
    }
    if (!self_dead)
        numeric(s, c, 257, ":Added ban %s (%d client%s removed)",
                m->argv[0], killed, killed == 1 ? "" : "s");
    return self_dead;
}

static int
cmd_unkline(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    if (!require_oper(s, c))
        return 0;
    if (need_params(s, c, m, 1))
        return 0;
    if (uircd_ban_del(s, m->argv[0]) == UIRCD_OK)
        numeric(s, c, 257, ":Removed ban %s", m->argv[0]);
    else
        numeric(s, c, 257, ":No such ban %s", m->argv[0]);
    return 0;
}

/* GKILL <query> [:reason] -- mass disconnect by query language */
static int
cmd_gkill(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    int killed;
    int self_dead = 0;
    unsigned before;

    if (!require_oper(s, c))
        return 0;
    if (need_params(s, c, m, 1))
        return 0;
    before = s->n_clients;
    /* Detect if the caller matches, so we can report destruction. */
    {
        struct term terms[MAXTERMS];
        int nt = parse_query(m->argv[0], terms, MAXTERMS);
        if (nt > 0 && client_matches(c, terms, nt))
            self_dead = 1;
    }
    killed = uircd_kill_match(s, m->argv[0],
                              m->argc > 1 ? m->argv[1] : "Mass removal");
    if (killed < 0) {
        numeric(s, c, 461, "GKILL :Malformed query");
        return 0;
    }
    if (!self_dead)
        numeric(s, c, 257, ":GKILL matched %d client%s (of %u)",
                killed, killed == 1 ? "" : "s", before);
    return self_dead;
}

static int
cmd_banlist(struct uircd *s, struct uircd_client *c, struct msg *m)
{
    unsigned i;
    (void)m;
    if (!require_oper(s, c))
        return 0;
    for (i = 0; i < s->n_bans; i++)
        numeric(s, c, 257, ":ban %s :%s", s->bans[i].spec,
                s->bans[i].reason);
    numeric(s, c, 257, ":End of ban list (%u)", s->n_bans);
    return 0;
}

/****************************************************************
 * Dispatch
 ****************************************************************/

struct handler {
    const char *name;
    int (*fn)(struct uircd *, struct uircd_client *, struct msg *);
    int needs_registration;
};

static const struct handler handlers[] = {
    { "NICK", cmd_nick, 0 },
    { "USER", cmd_user, 0 },
    { "PASS", cmd_pass, 0 },
    { "QUIT", cmd_quit, 0 },
    { "PING", cmd_ping, 0 },
    { "PONG", NULL, 0 },
    { "CAP", cmd_cap, 0 },
    { "OPER", cmd_oper, 1 },
    { "JOIN", cmd_join, 1 },
    { "PART", cmd_part, 1 },
    { "PRIVMSG", cmd_privmsg, 1 },
    { "NOTICE", cmd_notice, 1 },
    { "TOPIC", cmd_topic, 1 },
    { "NAMES", cmd_names, 1 },
    { "LIST", cmd_list, 1 },
    { "WHO", cmd_who, 1 },
    { "WHOIS", cmd_whois, 1 },
    { "MODE", cmd_mode, 1 },
    { "KICK", cmd_kick, 1 },
    { "KILL", cmd_kill, 1 },
    { "KLINE", cmd_kline, 1 },
    { "UNKLINE", cmd_unkline, 1 },
    { "GKILL", cmd_gkill, 1 },
    { "BANLIST", cmd_banlist, 1 },
};

/* Parse one line (NUL-terminated, no CRLF) into a msg. Returns 0 on success,
 * -1 if there is no command. The line buffer is modified in place. */
static int
parse_line(char *line, struct msg *m)
{
    char *p = line;

    m->argc = 0;
    /* skip optional client prefix */
    if (*p == ':') {
        while (*p && *p != ' ')
            p++;
        while (*p == ' ')
            p++;
    }
    if (!*p)
        return -1;
    m->cmd = p;
    while (*p && *p != ' ')
        p++;
    if (*p) {
        *p++ = '\0';
        while (*p == ' ')
            p++;
    }
    while (*p && m->argc < MAXPARAMS) {
        if (*p == ':') {
            m->argv[m->argc++] = p + 1;
            break;
        }
        m->argv[m->argc++] = p;
        while (*p && *p != ' ')
            p++;
        if (*p) {
            *p++ = '\0';
            while (*p == ' ')
                p++;
        }
    }
    return 0;
}

/* returns 1 if the client was destroyed */
static int
dispatch(struct uircd *s, struct uircd_client *c, char *line)
{
    struct msg m;
    size_t i;

    if (parse_line(line, &m) < 0)
        return 0;

    for (i = 0; i < sizeof(handlers) / sizeof(handlers[0]); i++) {
        if (strcasecmp(m.cmd, handlers[i].name) != 0)
            continue;
        if (!handlers[i].fn)
            return 0; /* silently accepted (PONG, CAP) */
        if (handlers[i].needs_registration && !c->registered) {
            numeric(s, c, 451, ":You have not registered");
            return 0;
        }
        return handlers[i].fn(s, c, &m);
    }
    numeric(s, c, 421, "%s :Unknown command", m.cmd);
    return 0;
}

/****************************************************************
 * Public API
 ****************************************************************/

struct uircd *
uircd_new(const struct uircd_config *cfg)
{
    struct uircd *s;

    if (!cfg || !cfg->out || !cfg->drop)
        return NULL;
    s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;
    s->cfg = *cfg;
    s->ping_interval_ms = cfg->ping_interval_ms ? cfg->ping_interval_ms
                                                : DEF_PING_INTERVAL;
    s->ping_timeout_ms = cfg->ping_timeout_ms ? cfg->ping_timeout_ms
                                              : DEF_PING_TIMEOUT;
    s->max_clients = cfg->max_clients ? cfg->max_clients : DEF_MAX_CLIENTS;
    s->max_channels = cfg->max_channels ? cfg->max_channels
                                        : DEF_MAX_CHANNELS;
    s->flood_lines = cfg->flood_lines ? cfg->flood_lines : DEF_FLOOD_LINES;
    s->flood_window_ms = cfg->flood_window_ms ? cfg->flood_window_ms
                                              : DEF_FLOOD_WINDOW;
    s->max_per_ip = cfg->max_per_ip ? cfg->max_per_ip : DEF_MAX_PER_IP;
    s->reg_timeout_ms = cfg->reg_timeout_ms ? cfg->reg_timeout_ms
                                            : DEF_REG_TIMEOUT;
    return s;
}

static int
cfg_parse_uint(const char *s, unsigned *out)
{
    char *end;
    unsigned long v;

    if (!s || !*s)
        return -1;
    errno = 0;
    v = strtoul(s, &end, 10);
    if (errno != 0 || *end != '\0' || v > UINT_MAX)
        return -1;
    *out = (unsigned)v;
    return 0;
}

static int
cfg_parse_bool(const char *s, int *out)
{
    unsigned u;

    if (cfg_parse_uint(s, &u) == 0) {
        *out = (u != 0);
        return 0;
    }
    if (!strcasecmp(s, "true") || !strcasecmp(s, "yes") ||
        !strcasecmp(s, "on")) {
        *out = 1;
        return 0;
    }
    if (!strcasecmp(s, "false") || !strcasecmp(s, "no") ||
        !strcasecmp(s, "off")) {
        *out = 0;
        return 0;
    }
    return -1;
}

int
uircd_config_set(struct uircd_config *cfg, const char *key, const char *value)
{
    if (!cfg || !key || !value)
        return UIRCD_ERR;

    /* String keys store the pointer, not a copy: value must stay valid for the
     * engine's lifetime, exactly as the config struct's string fields require. */
    if (!strcmp(key, "server-name")) { cfg->server_name = value; return UIRCD_OK; }
    if (!strcmp(key, "network"))     { cfg->network = value;     return UIRCD_OK; }
    if (!strcmp(key, "motd"))        { cfg->motd = value;        return UIRCD_OK; }
    if (!strcmp(key, "version"))     { cfg->version = value;     return UIRCD_OK; }

    if (!strcmp(key, "require-login"))
        return cfg_parse_bool(value, &cfg->require_login) ? UIRCD_ERR : UIRCD_OK;

#define UINT_KEY(name, field) \
    if (!strcmp(key, (name))) \
        return cfg_parse_uint(value, &cfg->field) ? UIRCD_ERR : UIRCD_OK
    UINT_KEY("ping-interval-ms", ping_interval_ms);
    UINT_KEY("ping-timeout-ms", ping_timeout_ms);
    UINT_KEY("max-clients", max_clients);
    UINT_KEY("max-channels", max_channels);
    UINT_KEY("flood-lines", flood_lines);
    UINT_KEY("flood-window-ms", flood_window_ms);
    UINT_KEY("max-per-ip", max_per_ip);
    UINT_KEY("reg-timeout-ms", reg_timeout_ms);
#undef UINT_KEY

    return UIRCD_ERR; /* unknown key */
}

void
uircd_free(struct uircd *s)
{
    if (!s)
        return;
    while (s->n_clients > 0) {
        struct uircd_client *c = s->clients[0];
        c->dead = 1;
        while (c->n_chans > 0)
            chan_remove_member(s, c->chans[0], c);
        client_free(s, c);
    }
    while (s->n_channels > 0)
        chan_destroy(s, s->channels[0]);
    free(s->clients);
    free(s->channels);
    free(s->bans);
    free(s);
}

static int
client_banned(struct uircd *s, struct uircd_client *c, const char **why)
{
    unsigned i;
    for (i = 0; i < s->n_bans; i++) {
        if (term_matches(c, &s->bans[i].term)) {
            if (why)
                *why = s->bans[i].reason;
            return 1;
        }
    }
    return 0;
}

struct uircd_client *
uircd_accept(struct uircd *s, void *host_conn, const char *peer_ip)
{
    struct uircd_client *c;
    const char *why = NULL;

    if (s->n_clients >= s->max_clients) {
        /* synthesize a throwaway to emit ERROR then drop */
        char buf[64];
        int n = snprintf(buf, sizeof(buf),
                         "ERROR :Server full\r\n");
        s->cfg.out(s->cfg.ud, host_conn, buf, (size_t)n);
        s->cfg.drop(s->cfg.ud, host_conn);
        return NULL;
    }
    if (peer_ip && s->max_per_ip) {
        unsigned i, same = 0;
        for (i = 0; i < s->n_clients; i++) {
            if (strcmp(s->clients[i]->host, peer_ip) == 0 &&
                ++same >= s->max_per_ip)
                break;
        }
        if (same >= s->max_per_ip) {
            char buf[80];
            int n = snprintf(buf, sizeof(buf),
                             "ERROR :Too many connections from your host\r\n");
            s->cfg.out(s->cfg.ud, host_conn, buf, (size_t)n);
            s->cfg.drop(s->cfg.ud, host_conn);
            return NULL;
        }
    }
    if (s->n_clients == s->cap_clients) {
        unsigned nc = s->cap_clients ? s->cap_clients * 2 : 64;
        struct uircd_client **p = realloc(s->clients, nc * sizeof(*p));
        if (!p)
            return NULL;
        s->clients = p;
        s->cap_clients = nc;
    }
    c = calloc(1, sizeof(*c));
    if (!c)
        return NULL;
    c->host_conn = host_conn;
    c->srv = s;
    copy_str(c->host, sizeof(c->host), peer_ip ? peer_ip : "unknown");
    if (s->cfg.host_cloak)
        compute_cloak(s, c->host, c->cloak, sizeof(c->cloak));
    s->clients[s->n_clients++] = c;

    if (client_banned(s, c, &why)) {
        sendf(s, c, "ERROR :Banned: %s", why ? why : "no reason");
        c->dead = 1;
        s->cfg.drop(s->cfg.ud, host_conn);
        client_free(s, c);
        return NULL;
    }
    logevt(s, "connect", c->host);
    return c;
}

/* Buffer input that arrives while a deferred auth verdict is outstanding, to be
 * replayed by uircd_auth_complete(). Bounded so a flood during the auth window
 * cannot grow memory without limit. Returns 0, or -1 if the cap is exceeded. */
#define HOLD_MAX 4096

static int
hold_append(struct uircd_client *c, const unsigned char *data, size_t len)
{
    if (len == 0)
        return 0;
    if (c->hold_len + len > HOLD_MAX)
        return -1;
    if (c->hold_len + len > c->hold_cap) {
        size_t nc = c->hold_cap ? c->hold_cap : 512;
        char *p;
        while (nc < c->hold_len + len)
            nc *= 2;
        p = realloc(c->hold, nc);
        if (!p)
            return -1;
        c->hold = p;
        c->hold_cap = nc;
    }
    memcpy(c->hold + c->hold_len, data, len);
    c->hold_len += len;
    return 0;
}

/* Parse and dispatch a run of received bytes. Returns UIRCD_ERR if the client
 * was destroyed, else UIRCD_OK. If a command defers authentication mid-run, the
 * remaining bytes are held and processing stops until the verdict arrives. */
static int
feed_bytes(struct uircd *s, struct uircd_client *c, const unsigned char *p,
           size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        unsigned char b = p[i];

        if (b == '\n') {
            char line[INBUF_MAX + 1];
            size_t llen = c->inlen;

            if (c->skipping) {
                c->skipping = 0;
                c->inlen = 0;
                continue;
            }
            if (llen > 0 && c->inbuf[llen - 1] == '\r')
                llen--;
            memcpy(line, c->inbuf, llen);
            line[llen] = '\0';
            c->inlen = 0;

            /* simple flood accounting */
            c->flood_count++;
            if (c->flood_count > s->flood_lines) {
                secure_wipe(line, sizeof(line));
                sendf(s, c, "ERROR :Excess flood");
                client_quit(s, c, "Excess flood");
                return UIRCD_ERR;
            }

            if (llen == 0)
                continue;
            if (dispatch(s, c, line)) {
                secure_wipe(line, sizeof(line));
                return UIRCD_ERR;
            }
            /* A PASS/OPER line leaves the plaintext password in this stack
             * buffer and in c->inbuf; wipe both so it does not linger in
             * memory after the credential has been handled. */
            if (c->scrub_line) {
                secure_wipe(line, sizeof(line));
                secure_wipe(c->inbuf, sizeof(c->inbuf));
                c->scrub_line = 0;
            }
            if (c->auth_pending) {
                /* Hold the rest of this buffer until the verdict arrives. */
                if (hold_append(c, p + i + 1, len - (i + 1)) < 0) {
                    sendf(s, c, "ERROR :Input flood during authentication");
                    client_quit(s, c, "Input flood during authentication");
                    return UIRCD_ERR;
                }
                return UIRCD_OK;
            }
        } else if (c->inlen < INBUF_MAX) {
            c->inbuf[c->inlen++] = (char)b;
        } else {
            /* line too long: discard until the next newline */
            c->skipping = 1;
            c->inlen = 0;
        }
    }
    return UIRCD_OK;
}

int
uircd_recv(struct uircd *s, struct uircd_client *c, const void *data,
           size_t len)
{
    c->active = 1; /* tick() converts this to a fresh last_active_ms */

    if (c->auth_pending) {
        if (hold_append(c, data, len) < 0) {
            sendf(s, c, "ERROR :Input flood during authentication");
            client_quit(s, c, "Input flood during authentication");
            return UIRCD_ERR;
        }
        return UIRCD_OK;
    }
    return feed_bytes(s, c, data, len);
}

void
uircd_auth_complete(struct uircd *s, struct uircd_client *c, int ok)
{
    char *held;
    size_t heldlen;

    if (!c || c->dead || !c->auth_pending)
        return;
    c->auth_pending = 0;

    if (c->auth_kind == UIRCD_AUTH_OPER) {
        if (ok)
            grant_oper(s, c);
        else
            numeric(s, c, 491, ":No O-lines for your host");
    } else {
        if (ok) {
            c->authed = 1;
            if (c->auth_acct[0])
                copy_str(c->acct, sizeof(c->acct), c->auth_acct);
        } else if (s->cfg.require_login) {
            numeric(s, c, 464, ":Password incorrect");
        }
    }
    c->auth_acct[0] = '\0';

    /* Replay input held while the verdict was outstanding. Detach the buffer
     * first so a command that defers again during the replay can refill it. A
     * held NICK/USER completes registration through the normal path. */
    held = c->hold;
    heldlen = c->hold_len;
    c->hold = NULL;
    c->hold_len = c->hold_cap = 0;
    if (held) {
        feed_bytes(s, c, (const unsigned char *)held, heldlen);
        /* held input may have carried a pipelined credential; wipe before free */
        secure_wipe(held, heldlen);
        free(held);
    }
}

void
uircd_closed(struct uircd *s, struct uircd_client *c)
{
    if (!c || c->dead)
        return;
    c->dead = 1;
    if (c->registered)
        part_all_channels(s, c, "Connection closed");
    else {
        while (c->n_chans > 0)
            chan_remove_member(s, c->chans[0], c);
    }
    logevt(s, "quit", c->nick[0] ? c->nick : c->host);
    client_free(s, c);
}

void
uircd_tick(struct uircd *s, uint64_t now_ms)
{
    unsigned i;

    for (i = 0; i < s->n_clients; i++) {
        struct uircd_client *c = s->clients[i];

        if (c->connect_ms == 0)
            c->connect_ms = now_ms ? now_ms : 1;

        /* reset flood window */
        if (now_ms - c->flood_reset_ms >= s->flood_window_ms) {
            c->flood_reset_ms = now_ms;
            c->flood_count = 0;
        }

        /* an unregistered session must complete registration within the
         * deadline; it does not get to idle out the full ping cycle */
        if (!c->registered && now_ms > c->connect_ms &&
            now_ms - c->connect_ms >= s->reg_timeout_ms) {
            sendf(s, c, "ERROR :Registration timeout");
            client_quit(s, c, "Registration timeout");
            i--; /* slot now holds a different client */
            continue;
        }

        if (c->active || c->last_active_ms == 0) {
            c->active = 0;
            c->last_active_ms = now_ms;
            c->ping_sent = 0;
        }

        if (!c->ping_sent &&
            now_ms - c->last_active_ms >= s->ping_interval_ms) {
            sendf(s, c, "PING :%s", srv_name(s));
            c->ping_sent = 1;
            c->last_active_ms = now_ms;
        } else if (c->ping_sent &&
                   now_ms - c->last_active_ms >= s->ping_timeout_ms) {
            sendf(s, c, "ERROR :Ping timeout");
            client_quit(s, c, "Ping timeout");
            i--; /* slot now holds a different client */
        }
    }
}

/****************************************************************
 * Admin API
 ****************************************************************/

int
uircd_ban_add(struct uircd *s, const char *spec, const char *reason)
{
    struct ban b;
    unsigned i;
    int killed = 0;
    struct uircd_client **victims;
    int nv = 0;

    memset(&b, 0, sizeof(b));
    if (!spec || parse_term(spec, &b.term) < 0)
        return UIRCD_ERR;
    copy_str(b.spec, sizeof(b.spec), spec);
    copy_str(b.reason, sizeof(b.reason), reason ? reason : "Banned");

    if (s->n_bans == s->cap_bans) {
        unsigned nc = s->cap_bans ? s->cap_bans * 2 : 16;
        struct ban *p = realloc(s->bans, nc * sizeof(*p));
        if (!p)
            return UIRCD_ERR;
        s->bans = p;
        s->cap_bans = nc;
    }
    s->bans[s->n_bans++] = b;

    /* collect then kill, so destruction does not disturb iteration; every
     * match is removed, not a capped subset */
    victims = calloc(s->n_clients ? s->n_clients : 1, sizeof(*victims));
    if (!victims)
        return killed; /* ban is recorded; matches drop on reconnect */
    for (i = 0; i < s->n_clients; i++) {
        if (term_matches(s->clients[i], &b.term))
            victims[nv++] = s->clients[i];
    }
    for (i = 0; i < (unsigned)nv; i++) {
        sendf(s, victims[i], "ERROR :Banned: %s", b.reason);
        client_quit(s, victims[i], "Banned");
        killed++;
    }
    free(victims);
    {
        char detail[160];
        snprintf(detail, sizeof(detail), "%s (%d removed)", spec, killed);
        logevt(s, "ban", detail);
    }
    return killed;
}

int
uircd_ban_del(struct uircd *s, const char *spec)
{
    unsigned i;
    for (i = 0; i < s->n_bans; i++) {
        if (strcmp(s->bans[i].spec, spec) == 0) {
            s->bans[i] = s->bans[s->n_bans - 1];
            s->n_bans--;
            return UIRCD_OK;
        }
    }
    return UIRCD_ERR;
}

int
uircd_ban_list(struct uircd *s, const char **out, int max)
{
    int i;
    for (i = 0; i < (int)s->n_bans && i < max; i++)
        out[i] = s->bans[i].spec;
    return (int)s->n_bans;
}

int
uircd_kill_match(struct uircd *s, const char *query, const char *reason)
{
    struct term terms[MAXTERMS];
    int nt;
    unsigned i;
    int killed = 0;
    struct uircd_client **victims;
    int nv = 0;

    nt = parse_query(query, terms, MAXTERMS);
    if (nt <= 0)
        return UIRCD_ERR;

    victims = calloc(s->n_clients ? s->n_clients : 1, sizeof(*victims));
    if (!victims)
        return UIRCD_ERR;
    for (i = 0; i < s->n_clients; i++)
        if (client_matches(s->clients[i], terms, nt))
            victims[nv++] = s->clients[i];
    for (i = 0; i < (unsigned)nv; i++) {
        sendf(s, victims[i], "ERROR :Closing link: %s",
              reason ? reason : "Killed");
        client_quit(s, victims[i], reason ? reason : "Killed");
        killed++;
    }
    free(victims);
    return killed;
}

unsigned
uircd_client_count(const struct uircd *s)
{
    return s->n_clients;
}
