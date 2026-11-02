<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

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
| `assets/zejtron-original-logo-2026.png` | the official logo | 1470673 |
| `assets/zejtron-demo-doctor.png` | the doctor surface demo capture | 503738 |
| `assets/zejtron-demo-why.png` | the why surface demo capture | 471142 |
| `assets/qr/bitcoin.png` | bitcoin receive-address QR | 575 |
| `assets/qr/ethereum.png` | ethereum receive-address QR | 591 |
| `assets/qr/solana.png` | solana receive-address QR | 595 |

The canonical digests, in `b3sum -c` checksum format (paths relative to
the repository root):

```text
09ec09fcdc4815e23373cb266bb120aa4e1af140fb9d598e117d05478a791b47  assets/qr/bitcoin.png
4eb520de0fe258d2c82ba07ccba8d9e48bafc63904d022a83cc42b59d1ed2ac7  assets/qr/ethereum.png
bca56b0a454daf06ff2d57fe401719553e28733e73479de2652a0740a9e87d1a  assets/qr/solana.png
77f5a87a731499c090cfb565805a89aaccd1b638cf028c57f14b0973d1d75c20  assets/zejtron-demo-doctor.png
07f52d9efa4780e446b8f8850c0fadb84b59be00cc97968849d2afc516ad9edf  assets/zejtron-demo-why.png
405c65108085a036aeed726b7d9e08388f5eecca03d196fe2121d9ba07a30a7c  assets/zejtron-original-logo-2026.png
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
