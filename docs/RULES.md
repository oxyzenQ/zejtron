<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# zejtron Project Maintenance Rules

This document codifies the maintenance discipline for the zejtron project.
All contributors and maintainers must follow these rules.

## LOC Discipline

### Rust sources (hard cap 600, no mercy)

Rust source files must stay under **600 lines of code**. The scope is
every tracked `*.rs` file anywhere in the tree: `src/**`, `test/**`,
and `build.rs` (`scripts/gates/check-loc.sh`, wired as gate-keepers
section 9; the checker walks the git index by file type, so a new
over-cap file fails before the commit). When a file approaches the
cap, it must be split by responsibility before it becomes a
maintenance burden - a pure move with the gates green in between -
and each resulting file keeps one clear, single purpose such as
parsing, data models, output rendering, or owner mapping. There is no
exemption path.

### Scripts (hard cap 1000)

Every `.sh` and `.py` file under `scripts/` (recursive) must stay
under **1000 lines** (`scripts/gates/check-scripts-loc.sh`,
gate-keepers section 12). The budget is wider than Rust's on purpose:
a one-shot harness legitimately bundles its constants, its stage
table, and its verdict plumbing in one self-contained file - but no
script grows unbounded; the split into modules is the remedy.

### Exclusions

Documentation and plain-text files are not subject to the LOC limits:
`*.md`, `*.txt`, lockfiles, and assets.

## main.rs Scope

`main.rs` should stay small and only handle bootstrap and wiring. The
preferred range is **100 to 300 LOC**. It should parse CLI arguments and
dispatch commands to the appropriate modules, without containing substantive
business logic.

## src/ Structure

- **Root single-file policy**: `src/` root holds exactly ONE `.rs`
  file - `main.rs`. Every other module lives in its subsystem
  directory; a stray root-level module fails the build
  (`scripts/gates/check-loc.sh` checks the root layout before it
  counts a single line).
- **Subsystem directories** each own a `mod.rs` that carries the
  module declarations and re-exports: `cli/`, `commands/`, `info/`,
  `output/`, `system/`, `update/`.
- **Nested command modules** ride the `command.rs` + `command/`
  group idiom: the `.rs` file owns the command's entry surface, the
  same-named directory owns its submodules (see `commands/proc.rs`
  with `commands/proc/`).
- The colocated `src/RULES.md` reminds a contributor standing in the
  source tree of both disciplines; this document stays canonical.

## Feature Freeze

zejtron is currently **feature-frozen**. No new commands or runtime features
should be added. The project is in stabilization mode, and all work should
focus on:

- Bug fixes that do not change behavior for correct inputs.
- Stability and reliability improvements.
- Maintainability and code quality.
- Supply-chain hardening.
- CI/CD maturity.

Feature creep is explicitly prohibited. If a new feature idea arises, it
should be documented in the issue tracker but not implemented until the
project exits stabilization mode.

## Read-Only Behavior

zejtron is designed to be **read-only by default**. It must not kill
processes, close ports, start or stop services, modify files, or alter system
state in any way. Any change that would introduce write side-effects must be
rejected during review.

## CI/CD Maturity

CI must remain **green** at all times. All changes must pass the full
`./scripts/build.sh` suite before being merged to `main`. The normal CI pipeline must
run as read-only and must not require broad write tokens.

Release workflows must use the **minimum permissions necessary**. The release
workflow requires `contents: write` only for creating GitHub Releases. The weekly
maintenance workflow may use `contents: write`
only to commit a validated dependency refresh directly to the default branch.

## Supply-Chain Surface

The dependency footprint must stay **minimal**. No new runtime dependencies
should be added unless absolutely necessary. Dependency refreshes are handled by
the weekly maintenance workflow, which runs `cargo update`, executes the full
`./scripts/build.sh` suite, and commits `Cargo.lock` directly to the default branch only
when validation succeeds.

## Code Quality

All Rust source files must carry the SPDX license header:

```rust
// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
```

Headers must not be duplicated.

All code must pass:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features --locked -- -D warnings`
- `cargo test --all-targets --all-features --locked`

## Major Release Design Gates

Major releases (e.g. v5.0.0) carry additional requirements beyond normal
maintenance. These gates must be satisfied before a major version tag is
created:

- All tests pass, including new namespace tests.
- `actionlint .github/workflows/*` and `yamllint .github/workflows/*` pass.
- No source file exceeds 1000 LOC.
- No new high-risk dependencies without written justification in the commit
  message.
- The release CI workflow stays green on the tagged commit.
- Documentation and command help text remain consistent with actual behavior.
- `git diff --check` reports no whitespace errors.
- `bash -n check.sh version-to.sh` passes syntax validation.
- No regression against the previous stable release for any existing command.

The major release design plan is documented in [ROADMAP-current.md](ROADMAP-current.md) and
[v5.md](v5.md).

## Version Bumps

Version bumps must use the `./scripts/dev/version-to.sh` script (`vX.Y.Z`, or
`vX.Y.Z-pre` for a pre-release cut such as `v12.0.0-rc.1` - the same tag shape
the release lane validates), which updates `Cargo.toml`, `Cargo.lock`,
`README.md`, and `docs/workflow/about-ci.md` in a single, consistent pass.
Manual version edits are prohibited.

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
