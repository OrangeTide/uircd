/* auth.h : scrypt passwd-file authentication for miniircd */

#ifndef AUTH_H
#define AUTH_H

#include "uircd.h"

#include <stddef.h>
#include <stdint.h>

/* Load a passwd file. Each non-comment line is:
 *
 *   name:scrypt:N:r:p:salt_b64:hash_b64:flags
 *
 * where N r p are the scrypt work factors, the hash is scrypt() of the
 * password with the given salt, and flags is a string that may contain
 * 'c' (may connect / user login) and 'o' (may become IRC operator).
 *
 * The special name "*" is a shared connection password: it matches a bare
 * PASS with no account. Returns 0 on success, -1 on error. Safe to call once
 * at startup. */
int auth_load(const char *path);

void auth_free(void);

/* A credential verification split into a cheap lookup and the expensive KDF, so
 * the host can run the KDF off its lock and off the event thread. auth_lookup
 * snapshots the stored parameters for a name (or marks a miss); auth_compute
 * runs scrypt and compares, taking no lock and touching no shared state. */
struct auth_job {
    int miss;                   /* no matching entry/flag: fail, no scrypt */
    uint64_t n;                 /* scrypt work factors for the matched entry */
    uint32_t r, p;
    unsigned char salt[64];
    size_t saltlen;
    unsigned char hash[32];     /* stored hash to compare against */
    char pass[256];             /* copy of the client password */
    size_t passlen;
};

/* Cheap: fill *j for (kind, name, pass) from the loaded passwd table. May run
 * under a lock. A miss (unknown name or wrong flag) is encoded in j->miss; the
 * password is still copied so the timing of the fill does not vary. */
void auth_lookup(enum uircd_auth_kind kind, const char *name,
                 const char *pass, struct auth_job *j);

/* Expensive: run scrypt and compare. Takes no lock. Returns 1 to accept, 0 to
 * reject. A miss returns 0 without running scrypt. Wipes j->pass before it
 * returns. */
int auth_compute(struct auth_job *j);

/* Run one trivial scrypt on the calling thread to force the vendored code's
 * one-time, lazily-initialized CPU-feature selection to happen now. Call it
 * once before starting threads that run auth_compute concurrently; otherwise
 * their first calls race on that initialization. */
void auth_warmup(void);

#endif /* AUTH_H */
