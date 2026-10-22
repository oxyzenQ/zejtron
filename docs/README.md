<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Documentation Index

The map of the docs tree. The top-level `*.md` files ship in the
crates.io tarball (the lean-half rule); the subdirectories stay
repo-only. Source code is the single source of truth - every doc here
carries the disclaimer and yields to it.

## User docs

| Document | What it owns |
|---|---|
| [../README.md](../README.md) | The project front page: what zejtron is, install, the command surface, compatibility, safety contract, the intended environments (servers, desktops) and the user profiles - including who the tool is wrong for. |
| [EVIDENCE-LEDGER.md](EVIDENCE-LEDGER.md) | The Evidence Ledger Specification v1 (Frozen): the citable output format - the four provenance tiers, the block grammar, the UTC/deterministic/zero-escape laws, and the non-eBPF compliance path. |
| [EBPF_LIFECYCLE.md](EBPF_LIFECYCLE.md) | The Lazy Camera Doctrine: how the eBPF lane lives - the two modes (snapshot vs live), the kernel-side bounded rings, the attach/record/drain lifecycle, and why none of it is monitoring. |
| [BRANDING.md](BRANDING.md) | The brand: naming, the purple palette (#A855F7), the color system ladder, the civil-clock UTC markers, third-party usage rules. |
| [VERIFY_RELEASE.md](VERIFY_RELEASE.md) | How to verify a release: checksums (SHA-512 / BLAKE3 / SHAKE256), GPG signatures, the exact commands. |
| [RULES.md](RULES.md) | The project law: the gates, the caps, the conventions a change must land under. |
| [ROADMAP.md](ROADMAP.md) / [ROADMAP-current.md](ROADMAP-current.md) | Where the project is going; the owner's call. |
| [DEPENDENCY_AUDIT.md](DEPENDENCY_AUDIT.md) | The supply-chain ledger: every direct dependency's justification, the removed set, the rules going forward. |
| [LICENSING_FAQ.md](LICENSING_FAQ.md) | The licensing quick answers: who needs the commercial license, tiers, contact. |

## Governance (repository root)

| Document | What it owns |
|---|---|
| [../LICENSE](../LICENSE) | GPL-3.0-only, the full text. |
| [../NOTICE](../NOTICE) | The one-page license, trademark, and forking summary. |
| [../COMMERCIAL_LICENSE.md](../COMMERCIAL_LICENSE.md) | The commercial license offer: tiers, payment, verification. |
| [../CLA.md](../CLA.md) | The Contributor License Agreement (perpetual relicense grant; copyright stays with the contributor). |
| [../SECURITY.md](../SECURITY.md) | The security policy: reporting routes, scope, the hardening posture, the forensics (DFIR) scope. |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | How to contribute: the gates, the coding standards, the pre-commit contract. |
| [../QA.md](../QA.md) | The Q&A record: the claims a serious reader asks about, answered with sources. |
| [../TRADEMARK.md](../TRADEMARK.md) | Trademark usage terms for the zejtron name and branding. |

## Workflow and history

| Document | What it owns |
|---|---|
| [workflow/about-ci.md](workflow/about-ci.md) | How the CI estate is shaped and why. |
| [archive/](archive/) | Frozen changelog eras - never rewritten, the header gate exempts them for exactly that reason. |
