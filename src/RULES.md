<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# src/ Rules — Structure and Size

> The colocated reminder of the rules that govern everything under
> `src/`. The canonical, full policy text lives in
> [docs/RULES.md](../docs/RULES.md); this file exists so a contributor
> standing in the source tree sees the rules without going digging —
> the sibling project's `src/RULES.md` convention.

## Directory Discipline

- **Root single-file policy (night-improve-14)**: `src/` root holds
  exactly ONE `.rs` file — `main.rs`. No new `.rs` file may be placed
  directly at `src/` root; every module lives in its subsystem
  directory. The rule is enforced, not just written:
  `scripts/gates/check-loc.sh` checks the root layout before it
  counts a single line, and a stray root module fails the build.
- `src/` is organized by subsystem directory, each with a `mod.rs`
  that owns module declarations and re-exports: `cli/`, `commands/`,
  `info/`, `output/`, `system/`, `update/`.
- `src/main.rs` stays bootstrap/wiring only — parse, dispatch, exit
  (the 100–300 LOC soft target; see `docs/RULES.md` main.rs Scope).
- Nested command modules ride the `command.rs` + `command/` group
  idiom: the `.rs` file owns the command's entry surface, the
  same-named directory owns its submodules (see `commands/proc.rs`
  with `commands/proc/`).

## Size Discipline

- Every tracked `.rs` file: hard cap **600 lines**, no mercy
  (`scripts/gates/check-loc.sh`, gate-keepers section 9). A file over
  the cap is split into modules the same hour — a pure move with the
  gates green in between; there is no exemption path.
- Every `.sh`/`.py` under `scripts/`: hard cap **1000 lines**
  (`scripts/gates/check-scripts-loc.sh`, gate-keepers section 12).
- The canonical wording (the exact scopes and the remedies) lives in
  [docs/RULES.md](../docs/RULES.md).

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
