<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->

# Documentation Index

The map of the docs tree. The top-level `*.md` files ship in the
crates.io tarball (the lean-half rule); the subdirectories stay
repo-only. Source code is the single source of truth - every doc here
carries the disclaimer and yields to it.

## User docs

| Document | What it owns |
|---|---|
| [../README.md](../README.md) | The project front page: what zejtron is, install, the command surface, compatibility, safety contract, the intended environments (servers, desktops) and the user profiles - including who the tool is wrong for. |
| [EVIDENCE-LEDGER.md](EVIDENCE-LEDGER.md) | The Evidence Ledger Specification (current: v4): the citable output format - the four provenance tiers, the block grammar, the UTC/deterministic/zero-escape laws, the flat typed JSON rows with the typed actor (`--print-json`), and the non-eBPF compliance path. v1, v2, and the frozen v3 remain archived inside. |
| [USAGE.md](USAGE.md) | The usage playbook: the real-world investigation scenarios (find a RAM leak, catch a config-file writer, track a missing port, trace a deleted file still consuming disk), the exact commands, and how to read the Evidence Ledger. |
| [EBPF_LIFECYCLE.md](EBPF_LIFECYCLE.md) | The Lazy Camera Doctrine: how the eBPF lane lives - the two modes (snapshot vs live), the kernel-side bounded rings, the attach/record/drain lifecycle, and why none of it is monitoring. |
| [CAMERA-COST.md](CAMERA-COST.md) | The probe cost contract: the program census, the instruction budget, the ring bytes, the wake cost - the numbers the camera may not exceed. |
| [LTS_DEPTH_AUDIT.md](LTS_DEPTH_AUDIT.md) | The LTS depth audit record: the kernel-span evidence, the witness estate, the audit verdicts per lane. |
| [BRANDING.md](BRANDING.md) | The brand: naming, the purple palette (#A855F7), the color system ladder, the civil-clock UTC markers, third-party usage rules. |
| [VERIFY_RELEASE.md](VERIFY_RELEASE.md) | How to verify a release: checksums (SHA-512 / BLAKE3 / SHAKE256), GPG signatures, the exact commands. |
| [RULES.md](RULES.md) | The project law: the gates, the caps, the conventions a change must land under. |
| [ROADMAP.md](ROADMAP.md) / [ROADMAP-current.md](ROADMAP-current.md) | Where the project is going; the owner's call. |
| [DEPENDENCY_AUDIT.md](DEPENDENCY_AUDIT.md) | The supply-chain ledger: every direct dependency's justification, the removed set, the rules going forward. |
| [DOC_AUDIT.md](DOC_AUDIT.md) | The documentation depth audit: the master ruleset every doc is measured against - tell once (one home per fact, no duplicates), the depth bar, the registry, same-pass sync. |
| [INNOVATIONS.md](INNOVATIONS.md) | The innovation ledger: the named mechanisms that define the investigative core, each with the problem it kills, the file where the truth lives, and the proof that pins it. The map, not the ledger. |
| [LICENSING_FAQ.md](LICENSING_FAQ.md) | The licensing quick answers: who needs the commercial license, tiers, contact. |
| [FAQ.md](FAQ.md) | The user FAQ: root and privileges, kernel support, where the eBPF objects come from, the JSON lane, privacy, colors - and the deployment shapes (desktop, server, ultra scale). |
| [MAINTENANCE.md](MAINTENANCE.md) | The maintenance record: the incident classes the tree is armed against (the root-owned `__pycache__` class, the in-tree artifact staging class, the sweep-staled prebuilt lane class, the unknown commit id class) and the one-command recovery for each. |
| [PROOFS.md](PROOFS.md) | The proven datapath (night-datapath-1): what the proofs package verifies - the proptest tier, the eight Kani totality theorems with their measured budgets, the armed 30-minute split rule, why there is no night lane, and the signed loom census verdict. |
| [FREEZE.md](FREEZE.md) | The v80.0.0 LTS freeze declaration: what the CLI contract promises from the freeze onward, and what it refuses. |
| [REAL_USAGE_AUDIT.md](REAL_USAGE_AUDIT.md) | The pre-LTS real-usage audit: the release binary driven end to end (every verb, every JSON lane strict-parsed, the degradation lanes below the eBPF floor, the 400-run stability loop) with the verdict that cleared the LTS production floor. |
| [LTS_FORTRESS_AUDIT.md](LTS_FORTRESS_AUDIT.md) | The fortress audit record: the final pre-release audit before the v80.0.0 tag (night-last-total-lts), the sub-task verdicts and their peaks. |
| [Z11-GREEN-BASELINE-2026-11-25.md](Z11-GREEN-BASELINE-2026-11-25.md) | The green-baseline record (2026-11-25): the first all-green Z11 detonation on the host's own kernel - the refusal-to-fix timeline, the five legs, the run transcript. |

## Site-local (inside the trees they govern)

| Document | What it owns |
|---|---|
| [../PUBLISH-CHECKLIST.md](../PUBLISH-CHECKLIST.md) | The publish checklist: the tag-to-registry steps in order, under the freeze's `<VERSION>` convention. |
| [../AI_AGENTS_READ_THIS.md](../AI_AGENTS_READ_THIS.md) | The AI-agent notice: the license stop, and the `[measured]` capture-trap warning. |
| [../src/RULES.md](../src/RULES.md) | The src-tree law: structure and size rules, placed at the tree they govern. |
| [../assets/tools.md](../assets/tools.md) | The local tools notes behind the asset pipeline. |
| [../assets/signature-assets.md](../assets/signature-assets.md) | The asset signature registry: blake3 digests for every image under `assets/` and the GPG trust anchors under `assets/gpg/`. |
| [../corpus/README.md](../corpus/README.md) | The kernel dialect corpus: the parser regression lock - real kernel bytes, committed whole. |
| [../fuzz/seeds/README.md](../fuzz/seeds/README.md) | The fuzz lane's seed anchors: the committed corpus the runs seed from. |
| [../scripts/labs-exp/README.md](../scripts/labs-exp/README.md) | The lab experiment bench: owner-facing, self-contained verification tools. |
| [../scripts/labs-exp/VERIFY_NIGHT_CAFE_1.md](../scripts/labs-exp/VERIFY_NIGHT_CAFE_1.md) | The night-cafe-1 session handoff: the shell palette and the artifact walls, verified locally. |
| [../scripts/supermassive/README.md](../scripts/supermassive/README.md) | The supermassive contract's home: every surface, flag, and error path against the real binary. |

## Governance (repository root)

| Document | What it owns |
|---|---|
| [../LICENSE](../LICENSE) | AGPL-3.0-only, the full text. |
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
| [../CHANGELOG.md](../CHANGELOG.md) | The changelog: `[Unreleased]` is the live surface; the History section is the frozen record (the audit reads it for precedent, never corrections). |
| [archive/](archive/) | Frozen history - the retired changelog eras and the superseded v5.0.0 design specification - never rewritten, the header gate exempts them for exactly that reason. |

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
