<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Release Workflow

This project uses GitHub Actions for CI and GitHub Releases.

## CI

CI runs on pushes and pull requests targeting `main`.

It installs stable Rust with `rustfmt` and `clippy`, installs `codespell`, restores the Rust cache, and runs:

```sh
./scripts/build.sh
```

## Dependency Maintenance

The `zejtron - Dependency Maintenance` workflow runs every Monday at 07:00 WIB (00:00 UTC) and can also be run manually. It checks out the default branch, runs `cargo update`, executes `./scripts/build.sh`, and commits the refreshed `Cargo.lock` directly back to the default branch only after validation passes.

Maintenance workflow commits use:

- `github-actions[bot]`
- `41898282+github-actions[bot]@users.noreply.github.com`

## Release

Release builds run for tags matching `v*`. The workflow builds:

- `x86_64-unknown-linux-gnu`
- `x86_64-unknown-linux-musl`

Release archives use a flat layout:

- `zejtron`
- `README.md`
- `LICENSE`

Example release asset flow:

```sh
TAG=v11.0.0
cargo build --release --locked --target x86_64-unknown-linux-gnu
```

The release workflow uploads `zejtron-${TAG}-linux-amd64-{v3,v4}-{gnu,musl}.tar.gz` (the four-leg matrix) and matching checksum files.

## Version Bump Flow

```sh
./scripts/dev/version-to.sh v11.0.0
./scripts/build.sh
```

The script rewrites every version surface in one pass: `Cargo.toml` and
`Cargo.lock` (the complete cargo surface - zejtron is a single-crate
repo, there is no second manifest to ride along), the release
examples in `README.md` and this document, and the `CHANGELOG.md`
ledger - the bumped version is recorded as a bare line under
`## [Released]`, newest first, above `## [Unreleased]`. The ledger
writer probes honestly: a missing file, an already-recorded version, or
a non-standard section shape warns and writes nothing rather than
claiming a rewrite that did not happen, and the script's final
verification fails if the ledger line for the new version is absent.

## Release Command Flow

```sh
./scripts/dev/version-to.sh v11.0.0
./scripts/build.sh
git add .
git commit -m "chore: prepare v11.0.0 release"
git push origin main
git tag -a v11.0.0 -m "v11.0.0"
git push origin v11.0.0
```

## Actions-Pin Health

The workflows' `uses:` pins are kept fresh by a contributor-carried
gate (the sibling project's actions-pin contract, one engine for both
seats):

```sh
./scripts/gates/check-actions-pins.sh            # report only
./scripts/gates/check-actions-pins.sh --apply    # heal stale tag pins
```

The gate reads every `uses:` reference against GitHub's latest stable
release (with a tags fallback), classifies it, and - under `--apply` -
heals tag pins sitting behind the upstream major in place. Branch pins
(the `dtolnay/rust-toolchain@stable` shape) and SHA pins are reported
as skips for a human decision, never healed by a guess. The heal is
advisory-lane tooling, never wired into the offline commit gate: pin
freshness is a remote fact, and a check that needs the network has no
seat in a check that must stay fast. `--apply` fails closed if
anything outside `.github/workflows/` changes, and `GITHUB_TOKEN`
(optional, standard convention) lifts the unauthenticated API quota.

## Supermassive (the heavy lane)

`zejtron - Supermassive` is the wide cross the fast lane deliberately
does not run: `{MSRV 1.98.1, stable} x {gnu, musl}` - four legs, each
verifying its shape end to end. The gnu legs run the full gate
(`./scripts/build.sh check-all -q`) on their own toolchain, so the
pinned MSRV floor is proven on itself instead of assumed from a
stable-lane pass. The musl legs build the static release shape
(musl-tools, exactly as the release matrix provisions it) and then run
the CLI battery against the leg's own binary via `ZEJTRON_BIN_PATH` -
closing the honest gap where the shipped musl binary had never
executed the runtime battery. Triggers: a weekly schedule,
`workflow_dispatch`, and a core-paths push filter (a workflow that can
change its own contract owes itself a run); no pull_request trigger,
because `zejtron - CI` owns PRs. `scripts/build.sh battery` is the
lane's reusable entry point: the runtime battery alone, no compile,
against whatever binary `ZEJTRON_BIN_PATH` names.
