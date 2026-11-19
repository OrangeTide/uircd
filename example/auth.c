/* auth.c : scrypt passwd-file authentication for miniircd */

#include "auth.h"
#include "b64.h"
#include "crypto_scrypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ENTRIES   256
#define SALT_MAX      64
#define HASH_LEN      32
#define FLAG_CONNECT  (1u << 0)
#define FLAG_OPER     (1u << 1)

struct entry {
    char name[64];
    uint64_t n;
    uint32_t r, p;
    unsigned char salt[SALT_MAX];
    size_t saltlen;
    unsigned char hash[HASH_LEN];
    unsigned flags;
};

static struct entry entries[MAX_ENTRIES];
static int n_entries;

/* constant-time comparison */
static int
ct_equal(const unsigned char *a, const unsigned char *b, size_t n)
{
    unsigned char diff = 0;
    size_t i;
    for (i = 0; i < n; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

/* split s into fields by ':' in place; returns field count, pointers in f */
static int
split_fields(char *s, char **f, int maxf)
{
    int n = 0;
    char *p = s;
    f[n++] = p;
    for (; *p; p++) {
        if (*p == ':') {
            if (n >= maxf)
                return -1;
            *p = '\0';
            f[n++] = p + 1;
        }
    }
    return n;
}

static int
parse_line(char *line, struct entry *e)
{
    char *f[8];
    int nf;
    size_t sl, hl;

    nf = split_fields(line, f, 8);
    if (nf != 8)
        return -1;
    if (strcmp(f[1], "scrypt") != 0)
        return -1;

    memset(e, 0, sizeof(*e));
    if (strlen(f[0]) >= sizeof(e->name))
        return -1;
    strcpy(e->name, f[0]);
    e->n = strtoull(f[2], NULL, 10);
    e->r = (uint32_t)strtoul(f[3], NULL, 10);
    e->p = (uint32_t)strtoul(f[4], NULL, 10);
    if (e->n < 2 || (e->n & (e->n - 1)) != 0 || e->r == 0 || e->p == 0)
        return -1;

    sl = b64_decode(e->salt, sizeof(e->salt), f[5]);
    if (sl == (size_t)-1 || sl == 0)
        return -1;
    e->saltlen = sl;
    hl = b64_decode(e->hash, sizeof(e->hash), f[6]);
    if (hl != HASH_LEN)
        return -1;

    for (; *f[7]; f[7]++) {
        if (*f[7] == 'c') e->flags |= FLAG_CONNECT;
        else if (*f[7] == 'o') e->flags |= FLAG_OPER;
    }
    return 0;
}

int
auth_load(const char *path)
{
    FILE *fp = fopen(path, "r");
    char buf[1024];

    if (!fp) {
        fprintf(stderr, "auth: cannot open %s\n", path);
        return -1;
    }
    n_entries = 0;
    while (fgets(buf, sizeof(buf), fp)) {
        char *nl = strpbrk(buf, "\r\n");
        if (nl)
            *nl = '\0';
        if (buf[0] == '\0' || buf[0] == '#')
            continue;
        if (n_entries >= MAX_ENTRIES) {
            fprintf(stderr, "auth: too many entries (max %d)\n", MAX_ENTRIES);
            break;
        }
        if (parse_line(buf, &entries[n_entries]) == 0)
            n_entries++;
        else
            fprintf(stderr, "auth: skipping malformed line\n");
    }
    fclose(fp);
    return 0;
}

void
auth_free(void)
{
    memset(entries, 0, sizeof(entries));
    n_entries = 0;
}

static struct entry *
find_entry(const char *name)
{
    int i;
    for (i = 0; i < n_entries; i++)
        if (strcmp(entries[i].name, name) == 0)
            return &entries[i];
    return NULL;
}

void
auth_lookup(enum uircd_auth_kind kind, const char *name, const char *pass,
            struct auth_job *j)
{
    struct entry *e;
    unsigned need = (kind == UIRCD_AUTH_OPER) ? FLAG_OPER : FLAG_CONNECT;

    memset(j, 0, sizeof(*j));
    if (!pass) {
        j->miss = 1;
        return;
    }
    j->passlen = strlen(pass);
    if (j->passlen >= sizeof(j->pass))
        j->passlen = sizeof(j->pass) - 1;
    memcpy(j->pass, pass, j->passlen);
    j->pass[j->passlen] = '\0';

    e = find_entry(name ? name : "*");
    if (!e || !(e->flags & need)) {
        j->miss = 1;
        return;
    }
    j->n = e->n;
    j->r = e->r;
    j->p = e->p;
    memcpy(j->salt, e->salt, e->saltlen);
    j->saltlen = e->saltlen;
    memcpy(j->hash, e->hash, HASH_LEN);
}

int
auth_compute(struct auth_job *j)
{
    unsigned char out[HASH_LEN];
    int ok = 0;

    if (!j->miss &&
        crypto_scrypt((const uint8_t *)j->pass, j->passlen,
                      j->salt, j->saltlen, j->n, j->r, j->p,
                      out, sizeof(out)) == 0)
        ok = ct_equal(out, j->hash, HASH_LEN);

    /* wipe sensitive material regardless of the outcome; explicit_bzero
     * resists the dead-store elimination that -O2 may apply to a plain
     * memset on a buffer that is not read again */
    explicit_bzero(j->pass, sizeof(j->pass));
    explicit_bzero(out, sizeof(out));
    return ok;
}

void
auth_warmup(void)
{
    unsigned char salt[1] = { 0 };
    unsigned char out[HASH_LEN];

    /* N=2 (smallest legal power of two) with r=p=1 keeps this cheap; its only
     * purpose is to resolve the vendored scrypt's internal smix function
     * pointer on this thread before the KDF pool runs it from several. */
    crypto_scrypt((const uint8_t *)"", 0, salt, sizeof(salt), 2, 1, 1,
                  out, sizeof(out));
    memset(out, 0, sizeof(out));
}
