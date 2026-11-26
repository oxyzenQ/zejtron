<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->

# Asset Signature Registry

Every image under `assets/` - and the D5 GPG trust anchors under
`assets/gpg/` - carries a blake3 (b3sum) signature digest in this
registry. The digest pins the exact bytes of the brand surface - the
logo, the demo captures, the donation QR codes - so a duplicated,
edited, or re-encoded copy can never pass as the original asset in
the LTS lifetime of the project, and the same run pins the
maintainer key itself: a swapped or re-keyed
`maintainer-47A50AEF4B65AAC2.asc` fails by name before it can vouch
for anything. The contract is the same one
`ebpf-prebuilt/manifest.toml` applies to the staged eBPF object: the
bytes are the pin.

The image digests were computed with the pinned `b3sum` 1.8.7 (the
Gate-keepers CI lane installs the same); the two `assets/gpg/`
trust anchors joined the signed set on 2026-11-23 as the
night-netrunner-Z1 follow-up, same tool, same tracked-bytes rule.
The machine-readable sidecar is [signature.b3sum](signature.b3sum),
kept in `b3sum -c` format so the check below is the whole protocol.

## The registry

| Asset | Role | Size (bytes) |
|---|---|---|
| `assets/gpg/maintainer-47A50AEF4B65AAC2.asc` | the pinned maintainer public key - the D5 verifier's import | 4,918 |
| `assets/gpg/pinned-maintainer-fpr.txt` | the pinned primary fingerprint - build and runtime read the same bytes | 40 |
| `assets/qr/bitcoin.png` | bitcoin receive-address QR | 575 |
| `assets/qr/ethereum.png` | ethereum receive-address QR | 591 |
| `assets/qr/solana.png` | solana receive-address QR | 595 |
| `assets/zejtron-demo-doctor.png` | the doctor surface demo capture | 549,752 |
| `assets/zejtron-demo-why.png` | the why surface demo capture | 471,442 |
| `assets/zejtron-original-logo-2026.png` | the official logo | 1,436,337 |

The canonical digests, in `b3sum -c` checksum format (paths relative to
the repository root, byte-for-byte the sidecar):

```text
639b5d94603e14fa9022cad8e26efff7711bdaedd92f08723ffa96c0b2d90d77  assets/gpg/maintainer-47A50AEF4B65AAC2.asc
dc6108d809afdbbb41756c37ef3ce3eec4b674ed1c8c225678c0103c1e4cfa3b  assets/gpg/pinned-maintainer-fpr.txt
09ec09fcdc4815e23373cb266bb120aa4e1af140fb9d598e117d05478a791b47  assets/qr/bitcoin.png
4eb520de0fe258d2c82ba07ccba8d9e48bafc63904d022a83cc42b59d1ed2ac7  assets/qr/ethereum.png
bca56b0a454daf06ff2d57fe401719553e28733e73479de2652a0740a9e87d1a  assets/qr/solana.png
08bc6533734aa4a0f34e995016849f79af5f9bdf11ee43053f645bdecb1edd63  assets/zejtron-demo-doctor.png
d01fdbd049cf1b49a47d91c3ad793e25e618f5fe4ead01bb408c68e994aee16b  assets/zejtron-demo-why.png
517a96e06b2276021263a7cbd239c1dac9f828ab1937dd6f05153ecade5cf7d8  assets/zejtron-original-logo-2026.png
```

## Verify

From the repository root, with `b3sum` on PATH:

```sh
b3sum -c assets/signature.b3sum
```

Every line must answer OK. A missing file, a modified byte, or an
unregistered file under `assets/` breaks the verdict. The doc-side
twin proves this registry and the sidecar never disagree:

```sh
grep -E '^[0-9a-f]{64}  ' assets/signature-assets.md | b3sum -c
```

## Registration law

- An image added under `assets/` must be registered here in the same
  change that adds it - an unregistered image is exactly the
  duplicate/fake surface this registry exists to catch.
- The two `assets/gpg/` files are the deliberate exception to the
  image rule: not images, but trust anchors (`build/gpg.rs` imports
  the key into its isolated keyring and `src/info/commit_sig.rs`
  reads the pinned fingerprint through `include_str!`), so their
  bytes belong in the record exactly the same way.
- Replacing an asset rewrites its digest line deliberately in the same
  change; a silent byte drift fails the verify verdict. One caveat
  travels with the key: re-exporting the maintainer key with a new
  UID or a pushed-out expiry changes the armored bytes and moves the
  `.asc` digest - a legitimate change, but the commit message must
  say so, same as a re-encoded logo.
- Digests are computed with the pinned `b3sum` (the Gate-keepers CI
  lane installs 1.8.7); any standard blake3 implementation agrees -
  the digest is the raw hash, no key, no length prefix.
- The sidecar regenerates deterministically over the signed set
  (raster images, plus everything under `assets/gpg/` as trust
  anchors), sorted so a no-op regeneration is a no-diff:

```sh
find assets -type f \( \( -name '*.png' -o -name '*.webp' \
    -o -name '*.jpg' -o -name '*.jpeg' \) \
    -o -path 'assets/gpg/*' \) | sort | xargs b3sum \
    > assets/signature.b3sum
```

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
