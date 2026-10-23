<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# zejtron 80.0.0 - publish checklist

The v80.0.0 LTS freeze is in effect (see
[docs/FREEZE.md](docs/FREEZE.md)): the tree says `80.0.0` everywhere
the mirror law demands, the prebuilt lane is in sync, and every gate
is green. This checklist is the owner's manual publish lane - the
agent does NOT publish; crates.io is the owner's hand, always.

## What this state proves

- The version mirrors across all active files: root `Cargo.toml`,
  `Cargo.lock`, `ebpf/Cargo.toml`, `ebpf/Cargo.lock`, and the
  prebuilt manifest's `[contract]` version all read `80.0.0`
  (verified by `scripts/dev/regenerate-ebpf-prebuilt.sh --check`).
- The registry install builds with eBPF enabled and no toolchain on
  the target: the crate embeds the manifest-verified prebuilt kernel
  object.
- `cargo publish --dry-run --locked` passes on the tagged tree.
- Every gate on the tree's battery is green
  (`./scripts/build.sh check-all` + `./scripts/gate-keepers.sh`).

## The owner runs these commands (in order, on the personal laptop)

1. `cargo login` (paste the crates.io API token; the token is
   personal, never committed, never shared).
2. `cd /path/to/zejtron && git pull`
3. Tag the freeze if it is not tagged yet (the release lane triggers
   on `v*` tags):
   `git tag -a v80.0.0 -m "v80.0.0"` then
   `git push origin v80.0.0` - CI builds the two musl shapes and
   publishes the GitHub release.
4. `cargo publish --locked`
   (do NOT pass --allow-dirty here; the tree must be clean.)
5. Verify: `curl -s https://crates.io/api/v1/crates/zejtron`
   returns 200.
6. In a fresh directory: `cargo install zejtron --locked` and run
   `zejtron doctor`. The [eBPF] row must show `Feature: enabled`,
   and `zejtron -V` must report the `linux-amd64` musl build shape.

## What the owner does next

- LTS maintenance only: bug fixes, procfs/sysfs compatibility,
  internal performance. The surface is frozen.
- The pricing ladder and the licensing docs ride independently of
  the release cadence.

## What this checklist does NOT do

- It does NOT publish from any agent or CI lane - the registry
  upload is the owner's manual step, by design.
- It does NOT reopen the pre-release ladder; the next version bump
  is a deliberate owner decision (breaking changes need a major
  version, per the mirror law and `scripts/dev/version-to.sh`).
