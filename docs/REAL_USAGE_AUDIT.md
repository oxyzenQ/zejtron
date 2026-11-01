<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Real-Usage Audit (pre-LTS floor)

An end-to-end audit of the shipped binary driven through real usage —
every surface, every flag class, every error path, the JSON lanes, the
degradation lanes, and a stability loop — run before the project lands
on the LTS production floor. Method: build the pinned release, then
exercise the binary as an operator would, byte-verifying anything that
looks wrong before calling it a bug. Date: 2026-11-01. Tree under
audit: `e7e2a44` (v80.0.1, build label `local-linux-amd64-gnu
(e7e2a44)`).

## Environment

Linux sandbox container, x86-64, kernel 5.10.134 — deliberately BELOW
the project's verified 5.15 eBPF floor, which makes the honest-refusal
lanes testable the happy path is not. Toolchains installed at the
pinned versions (stable 1.98.1, nightly-2026-09-18 + rust-src for the
eBPF source build, bpf-linker 0.11.1, b3sum 1.8.7).

## Results by leg

| Leg | Method | Result |
|---|---|---|
| Help / version | `--help`, `-V`, `--version` top-level plus all nine verbs | 12/12 exit 0, usage blocks present, build label carries the commit hash |
| Real invocation | all nine verbs with real arguments (paths, PIDs, ports, `path sh`, `proc --me`) | all exit 0, ledger-shaped output, provenance tags intact |
| JSON lanes | every `--print-json` invocation parsed with a strict JSON reader | 9/9 valid (path, recent, port, proc, holds, touch, why, net, doctor incl. `--symptom slow`/`ram`) |
| Error paths | unknown flags, missing args, nonexistent paths/PIDs/commands, unknown symptom | usage errors exit 2 with clap's one-screen contract; semantic errors exit 1 with one precise line; zero panics |
| Degradation | `doctor --attach`, `port --listen` without a TTY, `port --events-only` without a lane, `--check-update` under API rate limiting | each refuses or falls back with one honest line, no panic, correct exit codes |
| Stability loop | 400 repeated runs (touch/port/doctor), stderr capture, /tmp litter check | 0 failures, 0 stderr lines, 0 temp files, no residue |
| End-to-end suite | `./scripts/supermassive/supermassive.sh --leg low` (the project's own 486-check real-binary suite) | 486 pass, 0 fail, 1 skip with reason (eBPF attach refused: kernel below the verified floor); `UNTESTED FLAGS: none`; post-leg cleanup guarantee green; 37s of the 60s budget |
| Compile gates | `./scripts/build.sh check-all -q` (fmt, clippy, the full test battery, the musl shape) | PASS inside the two-minute cap |
| Dependency bans | root and fuzz `Cargo.lock` read for the banned families | zero banned crates; the serde enforcement and its ebpf carve-out live in commit `e7e2a44` and docs/DEPENDENCY_AUDIT.md |

## Findings

1. **No code defect found.** One suspected defect — the provenance tag
   rendering as `easured]` across the tree — was disproven at the byte
   level: every audited file contains the correct `[measured]` bytes
   and zero corrupted ones. The display artifact belongs to output
   capture pipelines that strip ANSI sequences without requiring the
   escape byte, eating the two characters `[m` wherever they pass. The
   guard note for future AI sessions now lives in
   [AI_AGENTS_READ_THIS.md](../AI_AGENTS_READ_THIS.md), because a
   global "fix" of the phantom would corrupt seventy-plus correct
   sites in one commit.
2. **The dependency gap the audit closed:** the serde family was
   reachable in `ebpf/Cargo.lock` (upstream aya-ebpf's build-dependency
   chain) while every gate watched only the root workspace. Closed in
   commit `e7e2a44` with the every-lock ban gate; documented in
   [DEPENDENCY_AUDIT.md](DEPENDENCY_AUDIT.md).

## Verdict

The estate behaves exactly as the license documents claim on a host
below the eBPF floor: read-only lanes render complete evidence
reports, the event lanes refuse with reasons instead of guessing, and
the tool leaves no residue behind. Cleared for the LTS production
floor from the real-usage side. The full eBPF-load evidence path is
owned by the kernel-floor and kernel-witnesses CI lanes, which run on
floors this sandbox cannot reach.

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
