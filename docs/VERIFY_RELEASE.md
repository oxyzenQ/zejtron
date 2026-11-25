<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->

# Verifying Release Artifacts

Every release ships **three** checksum files per archive, covering
three independent hash families, and - when the release GPG key is
configured - one detached ASCII-armored GPG signature per archive.
Verify at least one checksum before trusting a downloaded binary, and
the signature whenever one ships.

## The Build: line names the artifact (night-dragon-maintenance-T1)

`zejtron -V` answers which exact artifact you are holding, through
the estate-wide build-label contract:

- `Build: pro-linux-amd64-v3-musl (...)` - a release binary from the
  download page: the `pro-` prefix plus the platform id, the same id
  the tarball name encodes, and never the `local-` marker (a release
  binary is not a local build).
- `Build: local-pro-native-musl (...)` - built on this machine
  through the `cargo pro-native-musl` alias (the alias name under
  the `local-` marker); likewise `local-pro-linux-amd64-v3-musl` /
  `local-pro-linux-amd64-v4-musl` for the arch-baseline aliases.
- `Build: local-linux-amd64-gnu (...)` - a plain local build (a
  `cargo build`, a `cargo install --path .`, a crates.io install):
  the compile-time arch+os+libc detection under the `local-` marker.

The parenthesized token is the commit sha (the three-step chain in
`build.rs`: git, `GITHUB_SHA`, then the registry tarball's
`.cargo_vcs_info.json` - a registry install recovers the real commit,
never an `unknown`). The `Signature:` line states the eBPF lane's
honest claim ("Pure eBPF builtin" - the objects ride inside the
binary on both lanes) followed by the identity manifest materialized
from the masked words at render time (night-pro-1, the family -V
shape; the artifact bytes carry the claim const only). The release
lane's own Verify step greps these literals as bytes out of every
matrix artifact before it ships.

## The depth-matrix signature (night-signature-1, the masked night-signature-advanced-1 scheme)

Every build embeds a verifiable signature chain, and the binary
verifies itself. The ownership claim is embedded MASKED - opaque
64-bit words no `strings(1)` or `rg` scan can find - and materializes
to plaintext only at runtime. Six depths, each checkable on its own:

| Depth | What it proves | How to check |
|---|---|---|
| D0 runtime identity | The masked manifest materializes to the owner's claim `Official Build by rezky_nightky (oxyzenQ)` (night-ux-orion-3: the claim carries no year tail - years render at the front, in the Copyright line's range); the D0 row renders the identity core `rezky_nightky (oxyzenQ)` and the facts block carries the contact line `oxyzenQ@proton.me` (night-remake-2) | `zejtron sig` (the D0 row) |
| D1 embedded marker | The masked authors layer binds to the manifest identity (two independent encodings of one identity) | `zejtron sig` (the D1 row) |
| D2 anchor integrity | The BLAKE3 anchor over the framed masked payload recomputes, and both FNV-64 fingerprints agree with the compile-time digests | `zejtron sig` (the D2 row) |
| D3 binary self-hash | The BLAKE3 of the exact bytes the process runs from | `zejtron sig` (compare against `b3sum <binary>` or the pinned release hash) |
| D4 camera object (night-frontier-Z5) | The embedded eBPF probe object recomputes the digest the build stamped over the same bytes as it staged them - a camera patched after the build refuses, from the binary alone | `zejtron sig` (the D4 row) |
| D5 commit signature (night-netrunner-Z1) | The commit the binary claims carries a GPG signature by the pinned maintainer key `47A50AEF4B65AAC2` (full fingerprint in `assets/gpg/pinned-maintainer-fpr.txt`), verified at build time against the repo's own pinned public key in an isolated keyring - the row that binds the provenance claim to the release channel: with the maintainer key verified out-of-band and releases cut from signed tags, the chain key -> tag -> commit -> binary closes with no channel left to MITM silently. Fail-closed: every state except a verified match refuses the row - and the verdict class splits the shapes (night-hit-2): an unsigned dev HEAD reads UNSIGNED (a missing provenance link, not a modification), while a foreign key, a broken signature, or any integrity break stays TAMPERED | `zejtron sig` (the D5 row) |

The at-rest contract (the anti-grep law): `grep -a rezky_nightky
<binary>` and `strings <binary> | grep rezky` find NOTHING on an
honest artifact - the release lane's Verify step asserts this absence
on every matrix artifact, and a plaintext identity hit in an artifact
is itself evidence the mask was stripped.

`zejtron sig` (alias `zejtron signature`) renders the whole matrix -
the facts block names the identity core (`rezky_nightky (oxyzenQ)`)
and the contact line (`oxyzenQ@proton.me`, night-remake-2) - and
closes with `verdict: SIGNATURE: AUTHENTIC (6/6 depths verified)`
on an intact release build. A build from an unsigned dev HEAD
(a plain dev commit, a CI lane) reads
`verdict: SIGNATURE: UNSIGNED (5/6 depths verified)` with its own
note - `a missing provenance link, not a modification - every
integrity depth above verifies; releases still bind to signed
commits/tags` (night-hit-2): the D5 row still refuses, the exit code
stays 1 (the any-failed-depth contract), and the verdict never
pretends a no-GPG build is tampered. A tampered, hand-patched, or
foreign-rebuilt binary gets `SIGNATURE: TAMPERED (...)` naming the
contradicting depth, exit 1; `--print-json` speaks the same matrix
as one jq-ready line (`payload_tag` = the anchor's domain tag,
`zejtron/depth-matrix/v1`). The anchor is a BLAKE3 digest over
`zejtron/depth-matrix/v1` plus the length-prefixed clear bytes of the
two masked layers - the same hash family the release checksum files
use. The constants (masked words, seeds, fingerprints, anchor) are
generated by `scripts/release/generate-provenance-words.py`, the
committed truth source; the generator self-checks its pure-Python
BLAKE3 mirror against pinned official vectors before it emits.

### What the fp= token hashes (night-pro-1)

`fp=` on the Depth-matrix line is the FNV-1a 64-bit digest of the
CLEAR manifest bytes only - the identity claim text, never the
artifact bytes (artifact identity is D3's seat). zejtron's masked
manifest is the identity clause alone: `Official Build by
rezky_nightky (oxyzenQ)` (41 UTF-8 bytes - night-ux-orion-3 removed
the year tail from the claim, and the fingerprint rotates with it;
the "Pure eBPF builtin" voice is a separate claim const, rendered
ahead of the manifest on the Signature line but never hashed),
digest `7e9ff677aac06508`. That framing is why zejtron's `fp=` differs from
its siblings: zylaxion and zelynic embed the full Signature line
including the voice (68 bytes) and share `fp=` `a60dfb6a39745f34`,
and cosmostrix (the "Cosmic Dragon" voice, 64 bytes) reports
`fe0d7239f86e7c1b`. Differently framed claims hash differently by
design; identical claim bytes share a fingerprint. The authors layer
was byte-identical estate-wide (57 bytes, fingerprint `c97b13f816035d55`)
until the night-remake-1 contact rekey: zejtron's authors claim now
carries `rezky_nightky (oxyzenQ) <oxyzenQ@proton.me>` (43 bytes) and
reports the zejtron-specific fingerprint (`66771e5f273b9cae`) on every
`sig` report, pending the estate-wide sweep that rekeys the sibling
tools. A fingerprint mismatch between tools with the same claim
framing would be a tampering signal; a difference between different
framings is the design working.

### Verify an artifact without executing it

The masked scheme's no-execution story is the D3 pin plus the absence
probe (the v4 legs' shape - the runner may lack the AVX-512
baseline):

```bash
# the artifact carries NO greppable identity (the at-rest contract)
grep -a rezky_nightky <binary>   # must find nothing

# the whole-image fingerprint: compare against the pinned release hash
b3sum <binary>
```

An executed check closes the loop on an executable host: `zejtron
sig` must answer 6/6 AUTHENTIC on a release artifact (a depth that
genuinely cannot run on the host - an out-of-tree build without the
camera stamp, an unreadable self-image - is named `unavailable` in
the verdict, never guessed; a build whose HEAD commit is not signed
by the pinned maintainer key reads UNSIGNED at D5 instead - release
commits are signed, dev commits may not be), and `-V`'s
Depth-matrix line must carry
`status=verified` - a rebuilt or patched artifact refuses by name.
The line names where the last two depths verify: the artifact-byte
depths (d0-d3) are what `-V` can prove on its own, and the hint
`(runtime depths; d4/d5 ride zejtron sig)` appends after the layers
so the hand-off is printed, not implied (night-hit-2).

### What AUTHENTIC proves, and what it does not

The D0-D2 chain proves the binary carries one coherent, unmasked
identity story: the masked layers decode to the owner's claim, the
two layers bind to each other, and the cryptographic anchor seals
the bytes. It does not by itself prove WHO built the artifact - any
rebuild of the same sources materializes the same owner claim. That
has two seats now. D3: every build hashes uniquely (the commit and
build-time ride the `Build:`/`Build-time:` lines, and any code
difference moves the hash), and the owner pins the expected D3 hash
per release. Compare the pinned hash with `zejtron sig`'s D3 line
(or `b3sum` of the installed binary) - a mismatch is a rebuilt,
hacked, or fake binary, whatever its report claims. And D5
(night-netrunner-Z1): the commit the binary claims was verified at
build time against the pinned maintainer public key in an isolated
keyring, so a passing D5 row proves the binary was built from a
commit the maintainer's key signed - the out-of-band twin closes
the chain: verify the maintainer key (keyservers, GitHub), verify
the signed tag the release was cut from (`git tag -v`), and the tag
names the very commit D5 bound. A swapped binary on the wire can
still replay claims - but it cannot forge the D5 verdict's
signature evidence, and a consumer who follows the chain catches
the swap.

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

## 4a. The reproducible release chain - rebuild the published hash yourself

(night-depth-hardening-Z1, the cosmostrix D4 lineage) Checksums and
signatures prove WHO shipped an artifact; reproducibility proves WHAT
it is: the published hash must be the hash anyone can rebuild from
source. The CI carries the standing proof on every push
(`.github/workflows/reproducible-release.yml`: `reproducible_build` +
`reproducible_verify`) - two INDEPENDENT runners build the pinned
release shape (`linux-amd64-v3-musl`: static musl, x86-64-v3) from
the same commit with the same `SOURCE_DATE_EPOCH` pin (the commit
timestamp build.rs honors in `ZEJTRON_BUILD_TIME`), the release lane's
exact flag composition plus the redacted path prefixes
(`--remap-path-prefix` folds the builder's HOME and checkout path to
`redacted`, so the embedded path strings cannot leak a host), and NO
shared cache - and the verify job requires byte identity (`cmp`).

To re-verify locally on one host (two cold builds, byte-identical):

```bash
bash scripts/release/repro-build.sh
```

The build time embedded in the binary (`ZEJTRON_BUILD_TIME`, shown by
`zejtron -V`) honors `SOURCE_DATE_EPOCH` - set it to the commit
timestamp (`git log -1 --format=%ct`) and your rebuild embeds the same
minute as the published artifact. Without the variable (plain dev
builds) the wall clock is used, exactly as before.

What is NOT yet claimed honestly: the local two-pass proof shares one
checkout path and one host (the CI two-runner job is the stronger
cross-host proof), and the standing proof covers the
linux-amd64-v3-musl lane - the flagship static shape the release page
leads with. The nested eBPF object is part of the release bytes on a
git checkout, so its determinism (the pinned nightly + bpf-linker) is
part of what the lane proves. This kills, permanently, the class of
"builds modified without a trace": there is no such thing as a
silent divergent build of a released zejtron shape - anyone can name
the exact bytes the release page hashes, from source, on their own
machine.

## GPG signature (when the release ships .asc files)

```bash
# One-time: fetch the release key (the fingerprint is pinned in
# docs/BRANDING.md, section 8 - the in-repo anchor - and on the
# release page).
gpg --keyserver keyserver.ubuntu.com --recv-keys 3EE4A49C78630A16E176DB2B3C9EB25BF0407781

# Verify the imported primary's fingerprint equals the pin BEFORE
# trusting any signature from it.
gpg --fingerprint 3EE4A49C78630A16E176DB2B3C9EB25BF0407781

# Verify the detached signature (the .asc rides the same asset list).
gpg --verify zejtron-vX.Y.Z-linux-amd64-v3-musl.tar.gz.asc \
           zejtron-vX.Y.Z-linux-amd64-v3-musl.tar.gz
```

`Good signature` means the archive bytes are the ones the release
pipeline signed. The identity line reads `Good signature from
"rezky_nightky (oxyzenQ) <oxyzenQ@proton.me>"` with
`Rezky Cahya Sahputra (cosmic dragon)
<130107241+oxyzenQ@users.noreply.github.com>` listed as an aka. The
`using EDDSA key` line gpg prints names a signing subkey, not the
primary - subkeys sign and rotate; the pinned primary fingerprint
above is the anchor to compare. Pair the signature with one checksum
check for a complete verification.

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
