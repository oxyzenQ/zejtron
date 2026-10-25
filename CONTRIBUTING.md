<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Contributing to zejtron

First off, thank you for considering a contribution. zejtron is a
read-only Linux introspection toolkit maintained by **Rezky Cahya
Sahputra (rezky_nightky / oxyzenQ)** ("the Owner") — this document
explains the rules a contribution must land under.

## Contributor License Agreement

By submitting a pull request, patch, or code-bearing issue comment to
this repository, you accept the terms of the
[CLA](CLA.md): the Owner receives a perpetual, worldwide,
non-exclusive, royalty-free, irrevocable license to use and relicense
your contribution (necessary because zejtron is dual-licensed
GPL-3.0-only + Commercial), while you keep full copyright. The
[SECURITY.md](SECURITY.md) file owns vulnerability reports —
do not open public issues for security problems.

## Prerequisites

- Rust 1.98.1 (pinned to a concrete version in `rust-toolchain.toml`;
  the pinned channel is the dormant-mode contract — never a floating
  alias)
- A Linux host with `/proc` mounted — zejtron reads procfs, sysfs, and
  the filesystem; it has no kernel-module or eBPF prerequisites
- Optional linters the wholesale gate skips with a warning when
  missing: `shellcheck`, `shfmt`, `actionlint`, `markdownlint-cli2`,
  `yamllint`, `codespell`

## Build

The build commands (plain release, the pro-native host aliases, and
the arch-baseline release aliases) live once in the README —
[Install from source](README.md#install-from-source) — the same
commands apply for contributors. zejtron is feature-free by design:
one `cargo build --release --locked` builds everything, and the
default `cargo test --all-targets --all-features --locked` runs the
unit surface. The commit gate is one invocation:

```bash
./scripts/build.sh check-all
```

## Project Structure

```
src/
  main.rs        — entry point + dispatch (the ONLY file at src/ root,
                   enforced by check-loc.sh)
  cli/           — CLI definition (clap derive) + clap brand styling
                   + the UX bridge (typo rescue, migration redirects)
  commands/      — the read-only command surfaces (path, recent, port/,
                   proc/, holds/, touch/, why, net, doctor/)
  info/          — the -V version report + the std-only civil clock
                   (Hinnant civil_from_days)
  output/        — runtime color tier (capability ladder, error lane)
  system/        — the /proc readers (status grammar, cmdline, passwd
                   map, display neutralizer) + the retained state-dir
                   guard (pathguard)
  update/        — --check-update (curl-backed, refuses root)
test/            — the single test tree (night-improve-18: every *.rs
                   test file lives here, #[path]-wired from its src
                   module; mirrors the src/ layout, cosmostrix
                   Pattern C)
scripts/
  build.sh       — the commit gate (check-all) + CLI battery
  gate-keepers.sh — the wholesale non-code gate (self-installs the
                    pre-commit hook)
  gates/         — the individual gate scripts (headers, permissions,
                    LOC caps, name case, language discipline,
                    version sync, ...)
  dev/           — maintainer tooling (version-to.sh)
  package/       — install-on-my-machine.sh / install.sh / uninstall.sh
docs/            — the docs tree (BRANDING, RULES, VERIFY_RELEASE, ...)
```

## Coding Standards

1. **LOC limit**: <= 600 lines per `.rs` file (enforced by
   `scripts/gates/check-loc.sh`, wired into `gate-keepers.sh`;
   tree-wide by file type, no exemptions — over the cap means split,
   the same hour)
2. **Scripts LOC limit**: <= 1000 lines per `.sh`/`.py` under
   `scripts/` (`scripts/gates/check-scripts-loc.sh`; a file that
   cannot split the same hour self-declares `# LOC_EXEMPT: <reason>`
   as tracked debt)
3. **Copyright + SPDX**: every source, config, and doc file must have:

   ```
   Copyright (C) 2026 rezky_nightky
   SPDX-License-Identifier: GPL-3.0-only
   ```

   (comments prefixed per language; `.md` uses HTML comments.
   Enforced by `scripts/gates/check-headers.sh`; `.sh` files
   additionally carry the `# OS: Linux only` line.)
4. **License**: GPL-3.0-only
5. **Rust toolchain**: pinned to a concrete X.Y.Z in
   `rust-toolchain.toml` (never `stable` — dormant-mode policy). Sync
   across rust-toolchain.toml / Cargo.toml MSRV / CI pins is enforced
   by `scripts/gates/check-rust-version-sync.sh`.
6. **Read-only discipline**: zejtron never modifies system state — no
   kill, no close, no service control, no file writes at all (the
   claim is literal since the v80 surface reduction removed the env
   snapshot writes). A contribution that breaks this contract is
   rejected by definition.
7. **Dependency discipline** (the sibling supply-chain rule): every
   direct dependency needs live call sites and an entry in
   `docs/DEPENDENCY_AUDIT.md`; feature lists are trimmed to the
   modules actually used; zero-call-site deps get removed, not kept
   "for later". No time crates — wall-clock math is the Hinnant
   civil-from-days algorithm (`src/info/clock.rs` and `build.rs`; chrono
   is banned in `deny.toml`, re-adding it fails CI).
8. **English-only language**: comments, docs, script text, and string
   literals are pure English (chat may be mixed-language; committed
   artifacts never are). Non-Latin scripts appear only as
   marker-declared Unicode fixtures (`// NON_LATIN_FIXTURE:`).
   Enforced by `scripts/gates/check-language.sh`. Emoji-class
   codepoints are blocked repo-wide by the gate-keepers emoji sweep —
   no garbage emoji anywhere in tracked files.
9. **Permissions**: tracked files 644, tracked executables and every
   directory 755 (enforced by `scripts/gates/check-permissions.sh`,
   `--fix` repairs in place).
10. **Commit messages**: pure English, no emoji, the
    `Internal research:` prefix, `Signed-off-by: oxyzenQ
    <130107241+oxyzenQ@users.noreply.github.com>` — one task, one
    commit (the micro-commit-push contract).

## Pre-commit

```bash
./scripts/build.sh check-all
./scripts/gate-keepers.sh
```

`build.sh check-all` runs the Rust-side gates on the musl shape only
(every cargo verb pinned to `--target x86_64-unknown-linux-musl`, the
project's single libc shape - no gnu lane exists): toolchain check,
cargo fmt --check, cargo clippy --all-targets --all-features
-D warnings, cargo test, the release build, and the CLI runtime
battery. The musl rust-std target is required
(`rustup target add x86_64-unknown-linux-musl` or
`./scripts/setup.sh`). `gate-keepers.sh` runs the non-code sections
wholesale: the
shell quad (bash -n + shellcheck + shfmt + source resolution) on
shell scripts, yamllint + actionlint on workflows, TOML validation,
codespell, markdownlint, SPDX license headers (check-headers.sh), the
file permission guard (644 files / 755 executables and directories),
the repo-wide emoji sweep, the 600-line Rust LOC cap and the 1000-line
scripts LOC cap, the toolchain-pin sync check, and the English-only
language discipline. Missing tools are skipped with a warning so the
gate stays usable on a fresh clone; CI runs the same script with every
tool pinned and installed.

The first wholesale run self-installs the local pre-commit hook
(`git config core.hooksPath=.githooks`, repo-local), so every future
commit on the clone executes `scripts/gates/check-commit-gate.sh`
(the commit-time arm of the actions-pin health contract) even when
the wholesale gates are forgotten.

## Branch Strategy

- `main` is the integration branch: always gated, always releasable.
- Work lands as focused, single-task commits (micro-commit-push);
  there are no long-lived feature branches in the normal flow.
- Version numbers are the Owner's call: the version-to.sh tooling
  records the release in the changelog ledger, and no contributor
  bumps versions or cuts tags unilaterally.
