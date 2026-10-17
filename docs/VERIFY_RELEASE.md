<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# Verifying Release Artifacts

Every release ships **three** checksum files per archive, covering
classical + post-quantum algorithms, and - when the release GPG key is
configured - one detached ASCII-armored GPG signature per archive.
Verify at least one checksum before trusting a downloaded binary, and
the signature whenever one ships.

## Checksum files

| File | Algorithm | Family | Quantum-safe? |
|------|-----------|--------|---------------|
| `*.sha512sum` | SHA-512 | SHA-2 | 256-bit (borderline) |
| `*.b2sum` | BLAKE2b-512 | BLAKE2 | 256-bit |
| `*.shake256` | SHAKE256 | SHA-3 XOF (NIST PQ) | 256-bit |

## How to verify

All three commands print `<filename>: OK` on success (or `FAILED` on
mismatch). No manual hash comparison needed.

```bash
# Classical (universal, every Linux has this)
sha512sum -c project-vX.Y.Z-linux-amd64-gnu.tar.gz.sha512sum

# Quantum-resistant — BLAKE2b (fastest, in coreutils)
b2sum -c project-vX.Y.Z-linux-amd64-gnu.tar.gz.b2sum

# Quantum-resistant — SHAKE256 (NIST PQ standard, via Python)
# openssl's -shake256 default output length varies by version/distro;
# Python hashlib.shake_256 is consistent (64 bytes = 128 hex chars)
COMPUTED=$(python3 -c "import hashlib; print(hashlib.shake_256(open('project-vX.Y.Z-linux-amd64-gnu.tar.gz','rb').read()).hexdigest(64))")
EXPECTED=$(awk '{print $1}' project-vX.Y.Z-linux-amd64-gnu.tar.gz.shake256)
[ "$COMPUTED" = "$EXPECTED" ] && echo "project-vX.Y.Z-linux-amd64-gnu.tar.gz: OK" || echo "FAILED"
```

Replace `project-vX.Y.Z-linux-amd64-gnu` with the actual archive name
- the release matrix ships exactly four shapes:
`zejtron-vX.Y.Z-linux-amd64-v3-gnu`,
`zejtron-vX.Y.Z-linux-amd64-v4-gnu`,
`zejtron-vX.Y.Z-linux-amd64-v3-musl`,
`zejtron-vX.Y.Z-linux-amd64-v4-musl` (the x86-64-v3/v4 microarch
levels x the glibc/musl libc flavors).

## GPG signature (when the release ships .asc files)

```bash
# One-time: fetch the release key (the key id is on the release page
# and in docs/BRANDING.md's verification section once configured).
gpg --keyserver keyserver.ubuntu.com --recv-keys <KEY_FINGERPRINT>

# Verify the detached signature (the .asc rides the same asset list).
gpg --verify zejtron-vX.Y.Z-linux-amd64-v3-gnu.tar.gz.asc \
           zejtron-vX.Y.Z-linux-amd64-v3-gnu.tar.gz
```

`Good signature` from the release key means the archive bytes are the
ones the release pipeline signed - pair it with one checksum check
for a complete verification.

## Why three algorithms

Defense in depth across three independent hash families
(SHA-2, BLAKE2, SHA-3 XOF). A future cryptanalytic break of any
single family does not invalidate verification via the other two.
GPG signatures add an authenticity layer the checksums cannot give
on their own: a checksum proves integrity against the published
hash file, the signature proves the bytes came from the release
key (a compromised mirror cannot forge either pair together).

## Verification tools required

- `sha512sum` — GNU coreutils (preinstalled on every Linux)
- `b2sum` — GNU coreutils ≥ 8.x (preinstalled on modern distros)
- `python3` — for the SHAKE256 lane (hashlib is stdlib)
- `gpg` — GnuPG 2.x, for the signature lane (preinstalled on
  virtually every Linux)

All tools ship with Arch Linux, Debian, Ubuntu, Fedora, Alpine,
and macOS by default — no extra install needed.
