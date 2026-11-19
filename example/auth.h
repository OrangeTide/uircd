/* auth.h : scrypt passwd-file authentication for miniircd */

#ifndef AUTH_H
#define AUTH_H

#include "uircd.h"

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

/* uircd_auth_cb: verify a credential. Returns UIRCD_OK or UIRCD_ERR. */
int auth_verify(void *ud, enum uircd_auth_kind kind, const char *name,
                const char *pass);

#endif /* AUTH_H */
