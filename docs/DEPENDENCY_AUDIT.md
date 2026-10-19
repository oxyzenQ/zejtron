<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Dependency Audit

The sibling supply-chain rule (NIGHT-hunt-6 lineage): every direct
dependency must have live call sites and a recorded justification
here. Anything with zero call sites gets removed, not kept "for
later"; feature lists are trimmed to the modules actually used; and
regressive dependencies are blocked in CI by the bans section of
`deny.toml` (`cargo deny check all`).

The audit baseline: 4 direct dependencies (chrono removed in
night-improve-13 - the Hinnant civil clock replaced it; see
`src/info/clock.rs` and the chrono ban in `deny.toml`).

<!-- ZEJTRON-DISCLAIMER -->
<!--
  Documentation Disclaimer - read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every doc - perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`) is the single source of truth. Always
  cross-check against the actual source files before relying on any
  specific number, file path, function name, or config key.

  If you find a discrepancy, please open a PR - the doc is wrong, not
  the source.
-->

## Direct dependencies

| Dependency | Version | Justification (live call sites) |
|---|---|---|
| `clap` | 4.5 | The entire CLI surface: derive parser (`src/cli/mod.rs`), help rendering, the brand styles (`src/cli/styles.rs`), error + suggestion lanes. Default features ride (derive + std + color + help + usage + error-context + suggestions are what the surface consumes). |
| `regex-lite` | 0.1 | The pattern filters where a full regex engine would be dead weight: substring/pattern matching in the read-only surfaces that accept user-supplied patterns. The "lite" build is deliberate - no unicode tables beyond what the surfaces need. |
| `tempfile` (dev) | 3.20 | Test-tree isolation: `touch`, `doctor`, and the path-surface unit tests create throwaway directories/files. Dev-only; never compiled into any binary. |

## Removed

| Dependency | Removed | Reason |
|---|---|---|
| `chrono` | night-improve-13 (2026-10-17) | The `clock` feature dragged `iana-time-zone` + `num-traits` into the lockfile for two timestamp-formatting call sites (`src/commands/touch/`, `src/commands/path.rs`). Wall-clock rendering is Howard Hinnant's `civil_from_days` algorithm directly (`src/info/clock.rs`, `build.rs`) - std only, UTC with an explicit marker, no timezone database in the binary. Re-adding chrono fails `cargo deny check all` in CI. |
| `ctrlc` | night-improve-4 (the refresh-loop removal) | The only consumer was the old `proc --live` refresh loop's Ctrl-C handler; night-improve-4 replaced the loop with the collect-over-a-window shape and the crate left the graph with the loop that needed it (its CHANGELOG entry says so). The stale justification row above claimed the contract for "any surface that must restore terminal state on Ctrl-C" - no such surface exists in the tree. The dead row itself is removed by night-improve-34's audit pass. |

## Rules going forward

1. A new direct dependency lands in the same commit as its first live
   call site AND its row in this file.
2. Feature lists: explicit, trimmed to consumed modules. A dependency
   whose feature surface cannot be named in one line is a dependency
   that was not audited.
3. No time crates, no async runtimes, no full regex engines without an
   owner conversation first - the boring-and-serious bar.
4. `cargo deny check all` (CI) is the enforcement arm; this file is
   the reasoning arm. A ban without a reason string here is a gate
   nobody can debug.
