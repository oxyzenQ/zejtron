<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# labs-exp

Owner-facing experiment bench: self-contained tools the owner runs
on a machine to verify a hardening era's work before closing it.
Nothing in this directory rides a release lane or a CI gate; the
files are maintainer tooling like the rest of scripts/, kept out of
the crate's include list by the manifest rule.

## zejtron-cli-ux-verify.sh

The CLI UX hardening verifier (night-total-hardening-1 follow-up,
extended by night-signature-1): the complete usage-error contract
plus the depth-matrix signature contract against a built binary in
one shot, 31 checks, the exit code is the verdict (0 = all green).

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

Root is never required: every check rides the usage layer (usage
errors, help, the version banner, one runtime probe that fails on a
missing path), so the lab runs the same with or without sudo.

### Section 10 - the depth-matrix signature (night-signature-1)

Six checks pin the anti-fake chain on the running binary: the `-V`
`Depth-sig:` line (the identity claim `rezky_nightky (oxyzenQ) 2026`
plus the anchor), `zejtron sig` and the `signature` alias both exit
0, the matrix closes with
`verdict: SIGNATURE: AUTHENTIC (4/4 depths verified)`, the JSON lane
speaks one line with `"verdict":"AUTHENTIC"`, and the binary image
itself carries the `ZJNS1` marker whose commit matches the `-V`
Build line (the D1 depth, grep-verified without executing the
artifact). The full mechanism story lives in
[docs/VERIFY_RELEASE.md](../../docs/VERIFY_RELEASE.md).

### The build-fingerprint guard

The verdict is only honest when the binary under test was built from
the tree the lab rides in. After resolution the lab fingerprints the
binary (the commit in the `-V` Build line) against `git rev-parse
HEAD`:

- target/ discovery that lands on a binary built from another commit
  is a named refusal (exit 2) with the rebuild remedy - a stale
  build reports the fixed contract as failing, which reads like a
  regression;
- an explicit target (the argument or `$ZEJTRON_BIN_PATH`) is
  deliberate and only warns;
- `ZEJTRON_ALLOW_STALE=1` verifies the old binary on purpose through
  either lane.

A tree without git, or a binary without a Build commit, skips the
guard silently (release artifacts fingerprint differently).

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

## zejtron-forensic-proof.sh

The live forensic pair proof (night-frontier-2, one command): the
who-deleted-this-file innovation proven on THIS host, end to end.

- attach (idempotent, privileged one-shot), create a file, unlink
  it two seconds into a live watch: the ledger must name the actor
  (an `unlinked` row carrying `rm` and its pid) and drain exactly
  one `op=unlink` record - the single-publish law;
- the same contract for `mv`: exactly one `renamed` row and one
  `op=rename` record;
- 14 checks, the last line is always `FORENSIC-PROOF: PASS|FAIL`
  so the verdict relays without parsing prose.

### Run

```sh
sudo scripts/labs-exp/zejtron-forensic-proof.sh
```

Root is the law (the event lane reads the root-pinned maps under
/sys/fs/bpf/zejtron): a non-root run is a named refusal, never a
snapshot pretending to be a proof. The kernel floor is 5.15; a host
below it gets the attach refusal named, and the lab fails honestly.

Leave-as-found: probes already recording before the lab started
stay attached; a probe the lab attached itself is detached after.

The build-fingerprint guard rides here too (the same law the CLI
UX lab carries): a discovered binary built from another commit is a
named refusal - rebuild first, or set ZEJTRON_ALLOW_STALE=1 to
prove the old binary on purpose.

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
