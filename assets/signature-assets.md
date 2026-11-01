<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Asset Signature Registry

Every image under `assets/` carries a blake3 (b3sum) signature digest in
this registry. The digest pins the exact bytes of the brand surface - the
logo, the demo captures, the donation QR codes - so a duplicated, edited,
or re-encoded copy can never pass as the original asset in the LTS
lifetime of the project. The contract is the same one
`ebpf-prebuilt/manifest.toml` applies to the staged eBPF object: the
bytes are the pin.

## The registry

| Asset | Role | Size (bytes) |
|---|---|---|
| `assets/zejtron-original-logo-2026.png` | the official logo | 1598124 |
| `assets/zejtron-demo-doctor.png` | the doctor surface demo capture | 85795 |
| `assets/zejtron-demo-why.png` | the why surface demo capture | 75297 |
| `assets/qr/bitcoin.png` | bitcoin receive-address QR | 575 |
| `assets/qr/ethereum.png` | ethereum receive-address QR | 591 |
| `assets/qr/solana.png` | solana receive-address QR | 595 |

The canonical digests, in `b3sum -c` checksum format (paths relative to
the repository root):

```text
09ec09fcdc4815e23373cb266bb120aa4e1af140fb9d598e117d05478a791b47  assets/qr/bitcoin.png
4eb520de0fe258d2c82ba07ccba8d9e48bafc63904d022a83cc42b59d1ed2ac7  assets/qr/ethereum.png
bca56b0a454daf06ff2d57fe401719553e28733e73479de2652a0740a9e87d1a  assets/qr/solana.png
a35d491703315e7f4132598bbf90ca65765f1f6a51e8c0783e1df4230b588c37  assets/zejtron-demo-doctor.png
072bb9d1d8fa50780f4230bfe8a053991488b7112d814eaa93ec26bbab0d050c  assets/zejtron-demo-why.png
9c2ab381a656e4d2c520ee1d04b8cee2adde0a3ab6fb503f8128e131b74710c9  assets/zejtron-original-logo-2026.png
```

## Verify

From the repository root:

```sh
grep -E '^[0-9a-f]{64}  ' assets/signature-assets.md | b3sum -c
```

Every line must answer OK. A missing file, a modified byte, or an
unregistered image under `assets/` breaks the verdict.

## Registration law

- An image added under `assets/` must be registered here in the same
  change that adds it - an unregistered image is exactly the
  duplicate/fake surface this registry exists to catch.
- Replacing an asset rewrites its digest line deliberately in the same
  change; a silent byte drift fails the verify verdict.
- Digests are computed with the pinned `b3sum` (the Gate-keepers CI
  lane installs 1.8.7); any standard blake3 implementation agrees -
  the digest is the raw hash, no key, no length prefix.

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
