<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->

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
  module declarations and re-exports: `cli/`, `commands/`, `ebpf/`, `evidence/`, `info/`,
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

Every job in every workflow declares `timeout-minutes`; no lane runs
unbounded, and **15 minutes is the hard ceiling** (the owner's
commit-driven CI law, night-fly-1) with **10 minutes the standard
budget** - a tighter cap is a measured wedge-detector (its comment
names the latest measured green); the generous-lane class that once
loosened a budget past the ceiling is retired whole, and every test
lane triggers from a commit on the default branch, never from a
calendar slot (the only scheduled lanes left are the maintenance,
advisory-watch, and CodeQL lanes).

## Supply-Chain Surface

The dependency footprint must stay **minimal**. No new runtime dependencies
should be added unless absolutely necessary. Dependency refreshes are handled by
the weekly maintenance workflow, which runs `cargo update` in every workspace
(auto-detected by `scripts/ci/refresh-cargo-deps.sh`, which walks each committed
`Cargo.toml` - root, `ebpf/`, `fuzz/`, and any future subfolder workspace - and
runs `cargo update` in each parent directory),
proves the prebuilt lane through the ONE WRITER (the parity rider: the
read-only verdict first, a rebuild only when the manifest pin lags the swept
tree), executes the full
`./scripts/build.sh` suite, and commits the validated dependency lane (the
refreshed `Cargo.lock` files plus `ebpf-prebuilt/`) directly
to the default branch only
when validation succeeds.

## Code Quality

All Rust source files must carry the SPDX license header:

```rust
// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial
```

Headers must not be duplicated.

All code must pass:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features --locked -- -D warnings`
- `cargo test --all-targets --all-features --locked`

### The warning-denial law (warning = failed)

A build lane that OUTPUTS a warning is a failed lane - there is no
advisory tier for build noise. The law is enforced at every seat the
estate builds through:

- the release-shaped build aliases carry `-D warnings` as the leading
  rustflag (NIGHT-strict-3, `.cargo/config.toml`);
- the check-all gate exports `RUSTFLAGS="-D warnings"` over its
  compile lanes and sweeps every lane's captured output for any
  remaining `warning:` line (night-cafe-3, `scripts/build.sh`'s
  `run_strict`); a lane that prints a warning fails with the offending
  lines and the remedy named;
- the CI workflows that compile outside the aliases (the Z11 pidhide
  detonation fixture's loader builds) carry the same env on the
  loader command.

Deliberate exceptions, documented where they live: the `pro-native-*`
dev aliases stay lint-free (a local scratch build is not the
warning-gated shape), and the miri lane runs without the denial env
(miri.yml's own comment; ci.yml owns the warning contract). The
runtime battery lanes are out of scope by design - zejtron's own UX
prints `warning:` lines as REPORTED DATA (the clamped `--since`
window, for one), and reported data is not build noise.

## Major Release Design Gates

Major releases (e.g. v81.0.0, the next major after the v80 LTS line)
carry additional requirements beyond normal maintenance. These gates must be
satisfied before a major version tag is created:

- All tests pass.
- `actionlint .github/workflows/*` and `yamllint .github/workflows/*` pass.
- The LOC caps hold: 600 for Rust sources, 1000 for scripts (see the
  LOC Discipline above).
- No new high-risk dependencies without written justification in the commit
  message.
- The release CI workflow stays green on the tagged commit.
- Documentation and command help text remain consistent with actual behavior.
- `git diff --check` reports no whitespace errors.
- `bash -n scripts/dev/version-to.sh` passes syntax validation.
- No regression against the previous stable release for any existing command.

The direction is documented in [ROADMAP-current.md](ROADMAP-current.md);
the superseded pre-freeze v5.0.0 design specification lives in
[archive/v5.md](archive/v5.md).

## Version Bumps

Version bumps must use the `./scripts/dev/version-to.sh` script (`vX.Y.Z`, or
`vX.Y.Z-pre` for a pre-release cut such as `v12.0.0-rc.1` - the same tag shape
the release lane validates), which runs the version walk (night-cafe-mclaren-1,
the zelynic lineage): the census is detected, never listed - every tracked
`Cargo.toml` plus every authored-but-uncommitted one, wherever it lives, read
structurally inside its `[package]` block, with the family prefix derived from
the root crate's own name. The zejtron law is the superset of the
family law:
EVERY versioned manifest rides the release version - the root crate, every
`zejtron-*` family crate, and every fixture/sibling crate beside them (the
test-fixtures/pidhide pair today; proofs/ and fuzz/ rode their own versions
before night-cafe-mclaren-1 and are healed to the release version by the
first bump or the drift heal) - and a manifest whose current version
differs is healed, never skipped. Every walked `Cargo.lock` moves the same
way: every `[[package]]` entry whose name rides the bump set, verified in
place. The same pass refreshes the prebuilt lane (the one writer runs when
an `ebpf/` surface changed; otherwise the read-only verdict must be green),
the release-example docs (`README.md`, `docs/workflow/about-ci.md`, and any
doc whose `TAG=` pin still names the old tag), and the CHANGELOG ledger.
The census re-reads the tree every run, so a new crate can never go stale
by being forgotten in a list - and
`scripts/gates/check-version-family-sync.sh` (gate-keepers section 13b)
holds the same law at every push, with
`./scripts/dev/version-to.sh v<ROOT_VERSION>` as the one-command heal.
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
