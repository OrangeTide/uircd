# Vendored scrypt (libcperciva / Colin Percival)

Minimal subset used only for password hashing (scrypt KDF over SHA-256):
crypto_scrypt, crypto_scrypt_smix, sha256/PBKDF2, sysendian.

- Upstream: Colin Percival's scrypt reference implementation
  (https://github.com/Tarsnap/scrypt), the lib/crypto and libcperciva
  sources it shares. Public-domain-grade BSD-2.
- Vendored from a local checkout (~/boris/src/scrypt); the exact upstream
  commit it was taken at is not recorded here. To re-verify or upgrade,
  diff this subset against the upstream files of the same names.
- Salt entropy comes from the host OS (getrandom), not this subset's DRBG,
  so crypto_entropy/entropy are intentionally not vendored.
- Local changes: none. Do not edit in place; re-vendor to upgrade.

## Integrity pin

The vendored subset hashes to a single value, so drift from this baseline
is detectable without a network fetch. Recompute it over the source and
header files (this note excluded) in a fixed order:

    find . -type f ! -name 'VENDORED.md' ! -name '*.o' \
        | LC_ALL=C sort | sed 's|^\./||' | xargs sha256sum | LC_ALL=C sha256sum

Expected (subset SHA-256):

    1fd4bcc0a4e5b9d3c9aa2d80ffd9bc70153217f58f4e70fe02d63275ff7e4f3e

A different value means a file was added, removed, or modified since this
pin was recorded. Update the value here in the same commit that changes the
subset, and note the reason under "Local changes" above.
