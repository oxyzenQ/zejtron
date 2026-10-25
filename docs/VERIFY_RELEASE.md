<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# Verifying Release Artifacts

Every release ships **three** checksum files per archive, covering
three independent hash families, and - when the release GPG key is
configured - one detached ASCII-armored GPG signature per archive.
Verify at least one checksum before trusting a downloaded binary, and
the signature whenever one ships.

## Checksum files

| File | Algorithm | Family | Quantum-safe? |
|------|-----------|--------|---------------|
| `*.sha512sum` | SHA-512 | SHA-2 | 256-bit (borderline) |
| `*.b3sum` | BLAKE3 | BLAKE3 | 128-bit |
| `*.shake256` | SHAKE256 | SHA-3 XOF (NIST PQ) | 256-bit |

## How to verify

All three commands print `<filename>: OK` on success (or `FAILED` on
mismatch). No manual hash comparison needed.

```bash
# Classical (universal, every Linux has this)
sha512sum -c project-vX.Y.Z-linux-amd64-v3-musl.tar.gz.sha512sum

# The fast modern lane — BLAKE3 (the official b3sum utility)
b3sum -c project-vX.Y.Z-linux-amd64-v3-musl.tar.gz.b3sum

# Quantum-resistant — SHAKE256 (NIST PQ standard, via Python)
# openssl's -shake256 default output length varies by version/distro;
# Python hashlib.shake_256 is consistent (64 bytes = 128 hex chars)
COMPUTED=$(python3 -c "import hashlib; print(hashlib.shake_256(open('project-vX.Y.Z-linux-amd64-v3-musl.tar.gz','rb').read()).hexdigest(64))")
EXPECTED=$(awk '{print $1}' project-vX.Y.Z-linux-amd64-v3-musl.tar.gz.shake256)
[ "$COMPUTED" = "$EXPECTED" ] && echo "project-vX.Y.Z-linux-amd64-v3-musl.tar.gz: OK" || echo "FAILED"
```

Replace `project-vX.Y.Z-linux-amd64-v3-musl` with the actual archive name
- the release matrix ships exactly two shapes:
`zejtron-vX.Y.Z-linux-amd64-v3-musl`,
`zejtron-vX.Y.Z-linux-amd64-v4-musl` (the x86-64-v3/v4 microarch
levels, both fully static musl - night-badass-1 retired the gnu
pair).

## GPG signature (when the release ships .asc files)

```bash
# One-time: fetch the release key (the key id is on the release page
# and pinned in docs/BRANDING.md, section 8 - the in-repo anchor).
gpg --keyserver keyserver.ubuntu.com --recv-keys <KEY_FINGERPRINT>

# Verify the detached signature (the .asc rides the same asset list).
gpg --verify zejtron-vX.Y.Z-linux-amd64-v3-musl.tar.gz.asc \
           zejtron-vX.Y.Z-linux-amd64-v3-musl.tar.gz
```

`Good signature` from the release key means the archive bytes are the
ones the release pipeline signed - pair it with one checksum check
for a complete verification.

## Why three algorithms

Defense in depth across three independent hash families
(SHA-2, BLAKE3, SHA-3 XOF). A future cryptanalytic break of any
single family does not invalidate verification via the other two.
GPG signatures add an authenticity layer the checksums cannot give
on their own: a checksum proves integrity against the published
hash file, the signature proves the bytes came from the release
key (a compromised mirror cannot forge either pair together).

## Verification tools required

- `sha512sum` — GNU coreutils (preinstalled on every Linux)
- `b3sum` — the official BLAKE3 utility (not in coreutils):
  Debian 13+ and Ubuntu 24.04+ ship it as the `b3sum` package
  (`apt install b3sum`); anywhere with a Rust toolchain,
  `cargo install b3sum` builds the same binary
- `python3` — for the SHAKE256 lane (hashlib is stdlib)
- `gpg` — GnuPG 2.x, for the signature lane (preinstalled on
  virtually every Linux)

`sha512sum`, `python3`, and `gpg` ship by default on every major
Linux and macOS; `b3sum` is one small package install where it is
not preinstalled (the lanes above name the two commands).

<!-- ZEJTRON-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every doc — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
