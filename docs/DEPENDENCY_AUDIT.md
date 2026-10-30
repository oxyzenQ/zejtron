<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Dependency Audit

The sibling supply-chain rule (NIGHT-hunt-6 lineage): every direct
dependency must have live call sites and a recorded justification
here. Anything with zero call sites gets removed, not kept "for
later"; feature lists are trimmed to the modules actually used; and
regressive dependencies are blocked in CI by the bans section of
`deny.toml` (`cargo deny check all`).

The audit baseline: 3 direct runtime dependencies - `clap`,
`aya`, and `libc` (the last joined in night-dragon-6,
the SIGPIPE law) - plus one dev dependency (`tempfile`). chrono
removed in night-improve-13 - the Hinnant civil clock replaced it;
see `src/info/clock.rs` and the chrono ban in `deny.toml`.
regex-lite removed in night-dragon-maintenance-T1 - zero imports
across the tree (see the Removed table).

## Direct dependencies

| Dependency | Version | Justification (live call sites) |
|---|---|---|
| `clap` | 4.5 | The entire CLI surface: derive parser (`src/cli/mod.rs`), help rendering, the brand styles (`src/cli/styles.rs`), error + suggestion lanes. Default features ride (derive + std + color + help + usage + error-context + suggestions are what the surface consumes). |
| `aya` | 0.14 | The eBPF userspace loader: loads the embedded kernel object (source-built on a git checkout, registry-prebuilt from `ebpf-prebuilt/` on a tarball install), attaches the tracepoints, pins and reads the maps (`src/ebpf/`). Unconditional since night-weekly-maintenance-1 - no feature toggle, no dormant binary; the target install needs no nightly and no bpf-linker. |
| `libc` (unix) | 0.2 | The one raw call: the SIGPIPE disposition reset to `SIG_DFL` at main's top (`src/main.rs`) - std has no signal API, and a closed pipe must kill the process the UNIX way (silent, exit 141), never a Rust print panic. night-dragon-6; the escape hatch the policy note above `aya` reserved. `cfg(unix)`-gated. |
| `tempfile` (dev) | 3.20 | Test-tree isolation: `touch`, `doctor`, and the path-surface unit tests create throwaway directories/files. Dev-only; never compiled into any binary. |

## Removed

| Dependency | Removed | Reason |
|---|---|---|
| `chrono` | night-improve-13 (2026-10-17) | The `clock` feature dragged `iana-time-zone` + `num-traits` into the lockfile for two timestamp-formatting call sites (`src/commands/touch/`, `src/commands/path.rs`). Wall-clock rendering is Howard Hinnant's `civil_from_days` algorithm directly (`src/info/clock.rs`, `build.rs`) - std only, UTC with an explicit marker, no timezone database in the binary. Re-adding chrono fails `cargo deny check all` in CI. |
| `regex-lite` | night-dragon-maintenance-T1 (2026-10-30) | Zero imports across the tree - the stale justification row claimed "pattern filters", but the actual pattern filter (proc's `--find`) is std-only substring matching (`to_lowercase().contains()`, `src/commands/proc/forest.rs`), and the one regex-shaped call site (`touch`'s `journalctl --grep` argument) escapes its argument for an EXTERNAL command's engine through the hand-written `escape_journal_regex` (`src/commands/touch/audit.rs`) - no regex crate on this side of the process boundary. A dead runtime dependency is pure supply-chain surface; removed with no code change. |
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
