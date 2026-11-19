# HARDEN surface: supply chain and build (third_party/, vendor/, Makefile)

What the build pulls in and what ships in the artifact. The project vendors two
dependencies in-tree (`third_party/libiox`, `third_party/scrypt`), carries one
first-party helper (`vendor/daemonize.c`), and builds with a plain Makefile. The
question for this surface is whether a reader, packager, or stranger can trust
that the sources that build are the sources that were reviewed, and whether the
build fetches anything it does not verify.

## Round 1 (2026-11-19)

### Observed

- The build fetches nothing. The Makefile compiles only in-tree sources and
  links them; there is no `curl`, `wget`, `git clone`, or download step, so
  there is no build-time network trust to verify. Grep over `Makefile` for fetch
  verbs returns only `$(SCRYPT_DIR)/sha256.o`, a local object.
- `*.o`, `/miniircd`, and `/uircdpasswd` are in `.gitignore`; `git ls-files`
  returns no `.o`, `.a`, `.so`, or binary artifacts, so no prebuilt object is
  committed. The `vendor/daemonize.o` seen on disk is an untracked build output.
- `third_party/libiox/VENDORED.md` pins provenance precisely: upstream URL,
  version (0.1.2 / IOX_VERSION 102), the exact commit
  (677d9954060e70171db9105c338820493171234c), the file subset, and "Local
  changes: none."
- `third_party/scrypt/VENDORED.md` (as found) named the component (libcperciva /
  Colin Percival, BSD-2) but recorded Origin as a local path
  (`~/boris/src/scrypt`) with no upstream URL, no commit, and no content hash.
  The vendored subset is 7 files (crypto_scrypt, crypto_scrypt_smix, sha256,
  sysendian and their headers) and is deterministically hashable.
- `vendor/daemonize.c` carries `Copyright (c) 2026 Jon Mayo`, MIT-0 OR PUBLIC
  DOMAIN. It is first-party code, not a vendored dependency, so it is not a
  third-party provenance concern.
- Salt entropy for password hashing comes from the host OS (`getrandom` in
  `tools/uircdpasswd.c`), not from the vendored scrypt DRBG, so the entropy
  sources of the vendored subset are not on the trust path.

### Judged

#### 1. The vendored scrypt had no verifiable provenance pin  [H-015]

- **Claim:** `third_party/scrypt/VENDORED.md` recorded only a local checkout path
  for the vendored crypto, with no upstream URL, no pinned commit, and no content
  hash. A reader or packager therefore could not tell whether the in-tree scrypt
  matched a known upstream or had drifted since it was vendored. libiox, in the
  same tree, pins an exact commit; scrypt did not, so the asymmetry was a gap,
  not a project-wide absence of the practice.
- **Lines:** `third_party/scrypt/VENDORED.md` (the `Origin:` line);
  contrast `third_party/libiox/VENDORED.md` (pinned commit).
- **Scenario:** a packager re-vendoring or auditing the tree has no anchor to
  diff the crypto against. A silent modification to a vendored scrypt file (by a
  bad actor with commit access, or an honest mistake during a re-vendor) leaves
  no recorded baseline to catch it.
- **Falsifier:** recomputing the documented subset hash over the vendored files
  reproduces the value recorded in `VENDORED.md`; any added, removed, or modified
  file changes it. The recipe and expected value now live in that file:

      cd third_party/scrypt
      find . -type f ! -name 'VENDORED.md' ! -name '*.o' \
          | LC_ALL=C sort | sed 's|^\./||' | xargs sha256sum | LC_ALL=C sha256sum
      # -> 1fd4bcc0a4e5b9d3c9aa2d80ffd9bc70153217f58f4e70fe02d63275ff7e4f3e

  Reasoned and run this round: the recipe was executed and matches.
- **Fix shape:** record in `VENDORED.md` the upstream project URL, a reproducible
  content-hash pin of the subset, and the recipe to recompute it, so drift from
  the vendored baseline is detectable offline. **Fixed** this round for the
  baseline-integrity property. The residual (binding the subset to one exact
  upstream commit, as libiox does) needs the commit the maintainer vendored from
  and is noted in `VENDORED.md` as the re-verify step, not claimed closed.

### Not checked this round

- The vendored scrypt and libiox sources were not re-audited for correctness or
  compared line-by-line against upstream; this round is about provenance and
  drift detection, not a crypto review. The scrypt subset was taken as a trusted
  upstream public-domain implementation in the auth-surface rounds and remains so.
- The content pin detects drift from the recorded baseline. It does not by itself
  prove the baseline equals a trusted upstream release; that still requires the
  maintainer to record the exact upstream commit and diff against it.
- The build toolchain itself (compiler, libc, OpenSSL, pthreads) is the host's,
  not vendored, and its provenance is the operator's responsibility, noted here
  but not enforced.
