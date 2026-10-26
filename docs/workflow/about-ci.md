<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Release Workflow

This project uses GitHub Actions for CI and GitHub Releases.

## CI

CI runs on every push and every pull request - no path filter, no
branch filter (the owner's unfiltered-CI simplification: the filter
spelling's sync tax across every workflow cost more than the runner
minutes it saved). The publish lanes (`release.yml`, `crates-io.yml`)
are the estate's one deliberate exception: they wake only on the
owner-pushed `v*` tag, never blind.

It installs stable Rust with `rustfmt` and `clippy`, installs `codespell`, restores the Rust cache, and runs:

```sh
./scripts/build.sh
```

## Gate-keepers (the wholesale gate)

The `zejtron - Gate-keepers` workflow runs `scripts/gate-keepers.sh`
wholesale on every push and every pull request - the same blind posture
as the fast lane - with every tool it probes installed and pinned
(version plus sha256, the bytes-are-the-pin contract), because a check
that silently skips behind a missing tool is a check that does not
exist. The 19 sections cover the shell quad, the workflow linters, TOML
syntax, the repo-discipline gates (headers, permissions, emoji,
language, the LOC caps), the pin-sync guards, the fuzz include law
(section 18), and the documentation disclaimer's placement (section
19: every living .md carries the stale-data warning as its bottom
block - a block pasted mid-file or under a header is relocated to the
last lines, the sibling's legacy marker migrates to the house marker,
and CHANGELOG.md with docs/archive/ stay frozen). Section 16 is the
push-time seat of the prebuilt verdict: the one writer's read-only
`--check` verdict (`scripts/dev/regenerate-ebpf-prebuilt.sh`) runs
fail-closed in CI, so the
ebpf/ tree pin, the staged object's blake3 and size, the toolchain pin,
and the version mirror must all agree on the pushed tree. The
commit-time hook enforces the same verdict on every commit of a wired
clone (the first wholesale run self-installs `core.hooksPath=.githooks`),
and the build-time arm (`build/ebpf.rs`) auto-heals a stale lane for
every local cargo build - but a heal inside a CI runner would leave the
pushed manifest stale and the run green, which is exactly the gap
section 16 closes: what the developer heals locally, CI verifies.
Section 17 gives the actions-pin sweep its strict seat - the one place
where the network is always there and the `GITHUB_TOKEN` is native, so
the freshness verdict upstream actually returns turns the push red (see
Actions-Pin Health below).

## Fuzz (the reliability lane)

The `zejtron - Fuzz` workflow runs on every push and every pull request - the same blind posture as the fast lane. It is the continuous proof behind the parser claim: three `cargo-fuzz` targets, one per critical input surface, each driven with libFuzzer for a bounded 60 seconds per run. The harnesses path-include the parser sources (see `fuzz/Cargo.toml`) instead of adding a library target to the bin-only crate - the fuzzer compiles the same bytes the binary ships, so a guarantee the lane proves is a guarantee the binary carries.

The three targets:

- `btf_parser` - the BTF parser (`src/ebpf/btf.rs`) driven through `parse_btf_offsets` and `verify_writev_symbol_in`: hostile bytes in, a named error out, never a panic.
- `proc_parser` - the /proc and /etc raw parsers (`src/system/mod.rs`): the cmdline byte grammar plus the passwd, status, and cgroup string grammars behind the same UTF-8 gate the real readers sit in.
- `sanitize_display` - the terminal-safety neutralizer, asserted on every input: no control character survives into a rendered row (the CWE-150 gate), and honest data comes back byte-identical.

The lane's corpus starts from committed seed anchors
(night-improve-50, `fuzz/seeds/`): hand-built BTF blobs - the
kernel 6.18 unnamed-union shape, a two-level anonymous nest, and
the direct-member layout carrying a verifiable `vfs_writev` - that
the workflow copies into the working corpus after every cache
restore. A coverage-guided fuzzer starting from an empty corpus
must first rediscover a valid BTF header byte by byte before it
can touch the anonymous-descent paths night-improve-49 added; the
seeds put the first input inside those paths from run one, so the
60-second budget buys depth where the parser actually walks
today. The seeds are the lane's definition and travel with the
repo (the same law as the targets and the manifests); the corpus
the fuzzer grows between runs stays out of git (the `fuzz/`
gitignore), reproduced from the CI artifact when a crash needs
one.

The weekly deep session rides the same lane: every Monday 07:30
WIB (00:30 UTC) the three targets run for 15 minutes each instead
of 60 seconds - the owner-lazy insurance the continuous net
cannot buy. Both sessions share the corpus cache, so the deep
session and the per-push sessions grow one asset; the budget is
the only difference, exactly the low/best leg law the supermassive
suite already carries.

The lane rides nightly Rust - the fuzzer's standard toolchain - with the main crate's stable pin untouched: the override is env-scoped to the fuzz lane's cargo invocations, the other lanes never see it. The corpus is cached between runs, so the fuzzer keeps growing where the last one stopped; a crash fails CI with the crashing input in the log, and the fix is a parser that returns the named error. The eBPF kernel-side code is deliberately not fuzzed: it runs behind the kernel verifier, not in userspace.

## Dependency Maintenance

The `zejtron - Dependency Maintenance` workflow runs every Monday at 07:00 WIB (00:00 UTC) and can also be run manually. It checks out the default branch, runs `cargo update`, executes `./scripts/build.sh`, and commits the refreshed `Cargo.lock` directly back to the default branch only after validation passes.

Maintenance workflow commits use:

- `github-actions[bot]`
- `41898282+github-actions[bot]@users.noreply.github.com`

## Release

Release builds run for tags matching `v*`. The workflow builds:

- `x86_64-unknown-linux-musl` (the only shape; fully static)

Release archives use a flat layout:

- `zejtron`
- `README.md`
- `LICENSE`

Example release asset flow:

```sh
TAG=v80.0.1-zejtron.3
cargo build --release --locked --target x86_64-unknown-linux-musl
```

The release workflow uploads `zejtron-${TAG}-linux-amd64-{v3,v4}-musl.tar.gz` (the two-leg matrix, both fully static) and matching checksum files.

## crates.io (the registry lane)

`zejtron - crates.io publish` is the registry arm (the sibling's
tag-means-publish contract, night-improve-58): the owner-pushed `v*`
tag - the same filter `release.yml` carries - IS the publish command.
The ship-set verification runs first (`cargo package --list --locked`
inventory plus a full `cargo package` dry run against the exact tree
the tag names), and the publish job uploads straight after: the tag
must match Cargo.toml's version (`scripts/dev/version-to.sh` is the
bump tool), the `CRATES_IO_TOKEN` repository secret must be set (the
cargo-side variable the lane derives from it is `CARGO_REGISTRY_TOKEN`
- the mapping lives in the workflow), and an already-published version
skips the upload instead of failing - the idempotency probe, because
crates.io rejects duplicate versions and a re-pushed tag or re-run
must stay safe. The manual dispatch lane is retired (the manual
first-publish instruction with it): pushing a tag is the owner's
deliberate act. Code-surface pushes and pull requests never wake this
lane - the fast lane (`zejtron - CI`) owns those. The publish lanes
are the estate's one deliberate exception to the unfiltered-CI
posture: every other lane burns on any change, while a publish waits
for the owner's tag.

## Version Bump Flow

```sh
./scripts/dev/version-to.sh v80.0.1-zejtron.3
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
The pass carries the release lane's full tag shape: the input accepts a
stable or pre-release version (`vX.Y.Z` or `vX.Y.Z-rc.1`, the optional
suffix shape `release.yml` validates before flipping the GitHub
release's prerelease flag), and every rewrite consumes an optional
old-version suffix, so a tree sitting on an rc cut bumps to the next rc
or to stable with no stale `-rc.N` tail on any rewritten surface.

## Release Command Flow

```sh
./scripts/dev/version-to.sh v80.0.1-zejtron.3
./scripts/build.sh
git add .
git commit -m "chore: prepare v80.0.1-zejtron.3 release"
git push origin main
git tag -a v80.0.1-zejtron.3 -m "v80.0.1-zejtron.3"
git push origin v80.0.1-zejtron.3
```

## Actions-Pin Health

The workflows' `uses:` pins are kept fresh by a contributor-carried
gate (the sibling project's actions-pin contract, one engine for all
four seats):

```sh
./scripts/gates/check-actions-pins.sh            # report only
./scripts/gates/check-actions-pins.sh --apply    # heal stale tag pins
```

The gate reads every `uses:` reference against GitHub's latest stable
release (with a tags fallback), classifies it, and - under `--apply` -
heals tag pins sitting behind the upstream major in place. Branch pins
(the `dtolnay/rust-toolchain@stable` shape) and SHA pins are reported
as skips for a human decision, never healed by a guess.

Four seats, one engine. The automatic seat is the pre-commit hook:
`check-commit-gate.sh` delegates to the engine on every commit of a
wired clone (gate-keepers self-installs `core.hooksPath=.githooks`),
advisory - it reports and never blocks, because pin freshness is a
remote fact and a commit must not hinge on one. The binding seat is the
Gate-keepers CI lane: section 17 runs the sweep with `--strict` and the
runner's `GITHUB_TOKEN`, so the verdict upstream actually returns turns
the push red - the one seat where the remote fact is always reachable,
and the only red it can produce (every skip reason stays a skip there
too). The offline full gate
(`scripts/build.sh check-all`) carries no seat at all: a check that
needs the network has no place in a check that must stay fast. The
on-demand seats are the report and the maintainer heal: `--apply`
rewrites stale tag pins in place and fails closed if anything outside
`.github/workflows/` changes, and `GITHUB_TOKEN` (optional, standard
convention) lifts the unauthenticated API quota.

## Supermassive (the heavy lane)

`zejtron - Supermassive` is the wide cross the fast lane deliberately
does not run: `{MSRV 1.98.1, stable} x {host, musl}` - four legs, each
verifying its shape end to end. The host legs run the full gate
(`./scripts/build.sh check-all -q`) on their own toolchain, so the
pinned MSRV floor is proven on itself instead of assumed from a
stable-lane pass. The musl legs build the static pro-v3 shape
through the `cargo pro-linux-amd64-v3-musl` alias - the release
page's amd64-v3 static binary, never a bare `cargo build --release
--target` (the owner's from-source law, night-improve-52; the
parity gate `scripts/gates/check-release-parity.sh` binds the
alias's -C tokens to the release matrix's rustflags verbatim) -
and then run the CLI battery against the leg's own binary via
`ZEJTRON_BIN_PATH`, closing the honest gap where the shipped musl
binary had never executed the runtime battery. The alias links
through rust-lld (the pinned toolchain's own linker, the
`.cargo/config.toml` contract), so the musl legs install no
musl-tools package any more. Triggers: every
push - no path filter, no branch filter (the owner's unfiltered-CI
simplification retired the estate-wide spelling; the filter's sync
tax across every workflow cost more than the runner minutes it saved)
- plus `workflow_dispatch`; the weekly schedule stays retired
(night-improve-28). No pull_request trigger, because `zejtron - CI`
owns PRs.
`scripts/build.sh battery` is the lane's reusable entry point: the
runtime battery alone, no compile, against whatever binary
`ZEJTRON_BIN_PATH` names.

## Supermassive E2E (the surface lane)

`zejtron - Supermassive E2E` owns the per-surface end-to-end depth:
every surface, every flag, every error path, exercised against the
REAL compiled binary through `scripts/supermassive/` (that suite's
README is the contract's home). Two legs run the IDENTICAL check
depth - the low-spec leg on the MSRV floor (60s wall budget) and
the best-spec leg on the stable frontier (300s wall budget); the
budget buys headroom, never depth. Both legs build the binary
through the `cargo pro-linux-amd64-v3-musl` alias - the release
page's amd64-v3 shape, never a bare `cargo build --release` (the
owner's from-source law, night-improve-52): the depth suite
exercises the exact shape the release ships. Triggers: every push
(no path filter, no branch filter - the owner's unfiltered-CI
simplification), plus `workflow_dispatch`; no `pull_request`
trigger (the fast lane owns PRs).

## Supermassive Container E2E (the container lane)

`zejtron - Supermassive Container E2E` proves the container claim
the doctor makes: the static musl binary runs inside a REAL docker
container (alpine 3.20, pinned by manifest digest - the actions-pin
discipline applied to the test substrate) and must report container
evidence, render the [eBPF] section with the container's own facts,
and exit clean on every read-only surface. The lane's docker is
unprivileged by design: the eBPF lane's privileged attach belongs
to the host kernel, not a container namespace, so the container
lane pins the honest refusal rendering (the attach itself found its
CI seat in the kernel-floor lane below). Triggers: every push and
every pull request (no filters - this lane is cheap enough for the
PR path), plus `workflow_dispatch`.

## Supermassive Alpine (the musl smoke lane)

`zejtron - Supermassive Alpine` proves the two claims only a
musl-native, systemd-free rootfs can prove: the shipped shape is a
fully static musl binary (a file(1) tripwire runs before any
container does), and the tool degrades honestly where systemd is
absent - alpine runs OpenRC, so `systemctl` and `journalctl` do not
exist there, and the doctor must warn, never fail and never fake.
The proof is `scripts/supermassive/surfaces/alpine-smoke.sh`, a
standalone ten-probe surface (deliberately NOT in the harness's
ALL_SURFACES - the glibc host legs would fail T0 by definition)
executed inside the digest-pinned alpine:3.20 rootfs: the -V musl
identity, help, the doctor's warn-not-fail readiness, apk package
ownership through `path`, the JSON lanes (port, proc, doctor
--symptom ram, why), the honest-error path, and a standing panic
sweep. The lane is a smoke, not a 502-probe re-run: the binary is
static, so the kernel-facing behavior is already covered by the host
legs. The rootfs is stepped INTO with docker (the container lane's
proven shape - JavaScript actions cannot run inside a musl
container). Triggers: every push and every pull request, plus
`workflow_dispatch`.

## Supermassive Kernel Floor (the micro-VM lane)

`zejtron - Supermassive Kernel Floor` boots the REAL documented
floor kernel - the jammy GA release-day image,
linux-image-unsigned-5.15.0-25-generic from the LIVE archive's
jammy main pocket (frozen by archive policy; the weekly
jammy-updates ABI bumps are deliberately not configured) - in a KVM
micro-VM on the runner, and runs the FULL supermassive low leg
inside it, as root, on exactly the oldest kernel zejtron promises
to run on. No stock GitHub runner ships a 5.15 kernel (the ubuntu
images ride 6.x HWE kernels), so every other lane proves the floor
only as an at/above agreement check against a newer kernel; this
lane boots it. What it proves that nothing else can: the at-floor
direction of the kernel-floor agreement, LIVE; the privileged
attach lifecycle for real (root + BTF + the floor kernel is the
one CI place attach can succeed - the doctor surface's
success-direction specs); and the whole suite on the floor
userland shape (ubuntu, the suite jammy itself shipped with). The
VM: direct kernel boot, KVM host-passthrough, no disk, no modules
(every filesystem the suite touches is built into the Ubuntu
generic kernel), a RAM-resident initramfs (ubuntu:24.04 container +
the checkout + the binary, the same assembly the sibling projects'
lanes use), the dynamic low envelope (quarter cores / eighth RAM,
floored at 1 vCPU / 1024 MB), panic=-1 + -no-reboot + an outer
timeout so a wedged guest cannot burn the job budget, and qemu's
isa-debug-exit port device as the deterministic guest exit (the
verdict relays through SANDBOX-* sentinel lines on the serial
console - the VM cannot relay exit codes through qemu). The local
twin is `scripts/sandbox/zejtron-sandbox.sh` (the same boot shape,
rootless-packed by `scripts/sandbox/rootfs-pack.py`, KVM when
`/dev/kvm` is writable, TCG software emulation otherwise). The
same twin grew the arbitrary-kernel lane: `--kernel PATH` boots
any local vmlinuz under the same discipline, and the init
switches to report mode (a marker packed at `.sandbox/lane`,
only present when `--kernel` takes a PATH): the floor guard
becomes the floor DIRECTION row (at/above or below the 5.15
floor - the same number the suite's capability computation
reads), the substrate probes report instead of gate, and the
payload's exit code is the verdict. The CI lane stays
floor-strict by construction (it packs no lane marker); the
arbitrary lane is the local operator's instrument for any kernel
zejtron is asked to prove itself on, from either side of the
floor line. Triggers:
every push (no path filter, no branch filter - the owner's
unfiltered-CI simplification), plus `workflow_dispatch`; no
`pull_request` trigger (the fast lane owns PRs).

## Supermassive Kernel Witnesses (the report lane)

`zejtron - Supermassive Kernel Witnesses` boots the GA kernels on
either side of the floor line - focal 5.4.0-26 (below), jammy
5.15.0-25 (at, report mode), noble 6.8.0-31 (above) - plus the
moving-latest witness, the cachyos leg (night-improve-53): the
owner's own distro line, unpinned - the packer resolves the repo's
CURRENT flagship kernel (linux-cachyos, the newest line the repo
ships) and re-checks the repo index on every call through the .ver
sidecar, so the witness can never boot a stale "latest". The GA
legs ride the low envelope (the low-spec leg's math); the
moving-latest leg rides the BEST envelope - every core / three
quarters of the runner's RAM - the newest-software half of the
low/best span the suite's own leg vocabulary carries. All four
witnesses run the FULL supermassive low leg inside each, in
report mode: the init reports the floor direction instead of
gating the identity, and the payload's exit code is the verdict.
The lane runs the OPERATOR'S OWN INSTRUMENT
(`scripts/sandbox/zejtron-sandbox.sh --kernel SUITE --battery`)
- the same entrypoint, packer, and init as the local twin, so CI
cannot drift from the operator's tool: they are one code path.
The witness cache (the suite's GA kernel deb, the base tarball,
the iproute2 closure) rides `actions/cache` keyed by the
packer's hash; the initramfs itself is rebuilt every run. The
payload is the STATIC pro-v3 musl shape, built through the
`cargo pro-linux-amd64-v3-musl` alias (night-improve-52: the
release page's amd64-v3 static binary, rust-lld carrying the link
so no musl-tools rides the lane) - the twin's userland is the
ubuntu:22.04 base (glibc 2.35) and a glibc-2.39 runner build
refuses to execute there (the lane's first run found exactly
that); the floor lane rides the same static shape (night-badass-1,
the GNU purge: every lane is musl). The
one CI-only proof this lane owns: the privileged attach
lifecycle in the success direction on 6.8 GA under KVM (BTF
readable above the floor), and the below-floor refusal direction
- a kernel no stock runner can host. Triggers: every push (the
unfiltered-CI posture), plus `workflow_dispatch`; no
`pull_request` trigger (the fast lane owns PRs).

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
