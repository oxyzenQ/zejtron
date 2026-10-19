<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# zejtron 80.0.0-alpha.1 — publish checklist

## What this commit proves

- Prebuilt lane lands; the crates.io install builds with eBPF
  enabled, no toolchain on the target.
- The version mirrors across all active files.
- `cargo publish --dry-run --locked` passes.
- Every gate on the tree's battery is green.

## The owner runs these commands (in order, on the personal laptop)

1. `cargo login` (paste the crates.io API token; the token is
   personal, never committed, never shared).
2. `cd /path/to/zejtron && git pull`
3. `cargo publish --locked`
   (do NOT pass --allow-dirty here; the tree must be clean.)
4. Verify: `curl -s
   https://crates.io/api/v1/crates/zejtron` returns 200.
5. In a fresh directory: `cargo install zejtron --version
   80.0.0-alpha.1 --locked` and run `zejtron --doctor`.
   The [eBPF] row must show `Feature: enabled`.

## What the owner does next

- Real usage QC passes (dead-feature removal, bug hunting).
- After QC, a future pass bumps to 80.0.0 stable and freezes.

## What this pass does NOT do

- It does NOT publish.
- It does NOT freeze.
- It does NOT bump the version.
