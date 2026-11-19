# Vendored scrypt (libcperciva / Colin Percival)

Minimal subset used only for password hashing (scrypt KDF over SHA-256):
crypto_scrypt, crypto_scrypt_smix, sha256/PBKDF2, sysendian.

- Origin: ~/boris/src/scrypt (libcperciva, public-domain-grade BSD-2).
- Salt entropy comes from the host OS (getrandom), not this subset's DRBG,
  so crypto_entropy/entropy are intentionally not vendored.
- Local changes: none.
