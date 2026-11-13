<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# labs-exp

Owner-facing experiment bench: self-contained tools the owner runs
on a machine to verify a hardening era's work before closing it.
Nothing in this directory rides a release lane or a CI gate; the
files are maintainer tooling like the rest of scripts/, kept out of
the crate's include list by the manifest rule.

## zejtron-cli-ux-verify.sh

The CLI UX hardening verifier (night-total-hardening-1 follow-up):
the complete usage-error contract against a built binary in one
shot, 25 checks, the exit code is the verdict (0 = all green).

The fixes it verifies (all on main):

1. `358a693` - the pro-mode estate's `--limit` and `--depth` rows
   carry the ceiling wording the CLI structs name
   ("(0-1000000)", "(1-1024)"), not the pre-ceiling drift
   ("default 20", "minimum 1").
2. `aedddc7` - a non-UTF-8 argument (any glob expansion carrying
   invalid bytes) renders the clap InvalidUtf8 usage error with
   exit 2; the argv walk is lossy, the bridge never panics.
3. `69d5dc6` - case-variant subcommand spellings (`zejtron PORT`,
   `zejtron WHOHOLDS`) get the case-insensitive rescue through
   clap's own SuggestedSubcommand slot, the same one-tip contract
   the flag lane answers to.

### Run

```sh
cargo build --release
scripts/labs-exp/zejtron-cli-ux-verify.sh
```

The binary resolves through lib/zejtron-bin.sh (explicit argument,
then $ZEJTRON_BIN_PATH, then target/ discovery with the
profile-over-basic preference), so a named-profile build on this
machine is found without any flag. A missing binary is a named
refusal with the one-line build remedy, never a silent pass.

### Gate results at the commit this lab landed (69d5dc6 tree)

| Gate | Result |
| --- | --- |
| `cargo fmt --check` | clean |
| `cargo clippy --bins -- -D warnings` | clean |
| `cargo check --all-targets` | clean |
| `scripts/bench/scale-audit.sh` | PASS (proc 16 ms, holds 37 ms, doctor 109 ms; worst of 3, budget 500 ms; the host ran below the requested scale - the verdict is honest for the scale it reached) |
| `scripts/gate-keepers.sh` | 18/18 sections PASS |
| `scripts/build.sh check-all -q` | PASS (exit 0, under the 2-minute cap) |

The regression suite that pins the same contract inside the crate
lives in test/cli/ux_tests.rs (three pins joined in this pass: the
case-variant subcommand rescue, the case-variant retired-verb
rescue, and the non-UTF-8 argv collection) and rides CI's
cargo-test lane.

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
