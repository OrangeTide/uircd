# Vendored scrypt (libcperciva / Colin Percival)

Minimal subset used only for password hashing (scrypt KDF over SHA-256):
crypto_scrypt, crypto_scrypt_smix, sha256/PBKDF2, sysendian.

## Upstream

Tarsnap's scrypt, which bundles libcperciva in its own tree
(https://github.com/Tarsnap/scrypt). The subset matches release **1.2.0** (the
portable code, before upstream added hardware-accelerated SHA-256 and the
later smix refactor). Each vendored file comes from scrypt 1.2.0 at:

| vendored file           | scrypt 1.2.0 path                 |
| ----------------------- | --------------------------------- |
| crypto_scrypt.c/.h      | lib/crypto/                       |
| crypto_scrypt_smix.c/.h | lib/crypto/                       |
| sha256.c/.h             | libcperciva/alg/                  |
| sysendian.h             | libcperciva/util/                 |

Salt entropy comes from the host OS (getrandom), not this subset's DRBG, so
crypto_entropy/entropy are intentionally not vendored.

## Local changes

The subset is 1.2.0 with the edits needed to build standalone, plus one
hardening restored by the HARDEN review. Diffing against the 1.2.0 files above
shows exactly:

- Build-framework includes stubbed out so the files compile without Tarsnap's
  configure/cpusupport machinery: `crypto_scrypt.c` comments out
  `scrypt_platform.h`, `cpusupport.h`, `warnp.h`, and
  `crypto_scrypt_smix_sse2.h`, adds `<stdio.h>`, and replaces the two `warn0(...)`
  calls with `fprintf(stderr, "WARNING:...")`; `crypto_scrypt_smix.c` drops its
  `sha256.h` include; `sha256.c` drops `insecure_memzero.h`.
- `sha256.c` secret-zeroing: upstream uses `insecure_memzero`, which resists
  dead-store elimination. The vendoring substituted plain `bzero`, dropping that
  guarantee. The HARDEN review (finding H-017) restored it with `explicit_bzero`
  (available here via `-D_GNU_SOURCE`), which is not elided at `-O2`.

## Integrity pin

The vendored subset hashes to a single value, so drift from this baseline is
detectable without a network fetch. Recompute it over the source and header
files (this note excluded) in a fixed order:

    find . -type f ! -name 'VENDORED.md' ! -name '*.o' \
        | LC_ALL=C sort | sed 's|^\./||' | xargs sha256sum | LC_ALL=C sha256sum

Expected (subset SHA-256):

    5742275258030bec4afcd9a0e39d7d6b75673fd4fc979410f6f45f151c5bb905

A different value means a file was added, removed, or modified since this pin
was recorded. Update the value here in the same commit that changes the subset,
and record the reason under "Local changes". Do not edit in place for an
upgrade; re-vendor from a newer scrypt release and re-list the diffs.
