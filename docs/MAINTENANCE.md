<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Maintenance Record (owner)

The incident classes this tree has already armed itself against, and
the one ritual each class demands when it resurfaces. Everything here
is either already automated (this page names where the automation
lives and what it does when it fires) or carries a one-command
recovery. A maintenance task that needs a decision made from scratch
is a signal to write the decision down here first and only then act.

## The root-owned `__pycache__` class (fixed, night-dragon-maintenance-T1)

The family field report (2026-10-30, the zelynic tree): a normal
non-root `rm -rfv zelynic` died with `Permission denied` on
`scripts/__pycache__/zelynic_harness_lib.cpython-314.pyc` and two
siblings. Root cause: CPython caches the bytecode of every IMPORTED
module beside its source, so a harness run under `sudo` (the eBPF
work needs the privilege) wrote `.pyc` files owned by root; the later
non-root teardown could not remove them. The files were never
tracked — `.gitignore` carried `__pycache__/` — the damage was
purely local, which is exactly why it sat unnoticed until a teardown
hit it.

The shipped fix removes the phenomenon instead of documenting around
it: every python entry point under `scripts/` sets
`sys.dont_write_bytecode = True` immediately after its import guard
and before any repo-local import (see `scripts/gates/check-name-case.py`
and `scripts/sandbox/rootfs-pack.py`), so no repo-local bytecode is
written at any privilege level. The cost is a per-run recompile of
imported modules — milliseconds, invisible next to the work the
harnesses drive. `.gitignore` additionally ignores both shapes of the
artifact (`__pycache__/` and `*.pyc`), so even a host that writes
them anyway never tracks them.

The rule going forward: a new python file under `scripts/` copies the
guard block before its first repo-local import; a python file that
imports repo-local code without the guard is a regression of this
class. A checkout already poisoned by pre-fix root-owned caches
recovers with one sudo cleanup:

```
sudo find . -name __pycache__ -type d -prune -exec rm -rf {} +
```

after that the tree is normal-user-owned again and the guard keeps it
that way.

## The unknown commit id class (armed since night-improve-5)

A binary that cannot name its commit prints `unknown` in the version
report's `Build:` line — the incident class a sibling project hit on
its registry-installed binary (`Build: linux-amd64-gnu (unknown)`):
`~/.cargo/bin/<tool>` came from `cargo install` off crates.io, the
tarball extract has no `.git` directory, and the build script's git
probe correctly refused to lie — but no fallback existed to recover
the commit cargo itself had recorded at packaging time.

zejtron is armed against it: `build.rs`'s commit-sha resolution chain
answers in three steps, first hit wins:

1. `git rev-parse --short=7 HEAD` — local and CI checkouts.
2. the `GITHUB_SHA` env var — CI environments that carry no `.git`.
3. `.cargo_vcs_info.json` — the registry lane: cargo materializes the
   file beside the manifest when it packs the crate, carrying the sha1
   of the commit the crate was packaged from, so a
   `cargo install zejtron` build recovers the real commit with no
   toolchain beyond stable.

The shared normalizer (`normalize_short_sha`) rejects anything that
is not 7..=40 ASCII hex — a detached submodule answering the literal
`HEAD`, a truncated sha, non-hex noise — so every source renders one
canonical lowercase 7-char shape, and a genuinely unanswerable build
prints the honest `unknown` rather than a guess. The chain is
watched for staleness via `cargo:rerun-if-changed` on both `.git/HEAD`
and `.cargo_vcs_info.json`, so a dev checkout and a registry extract
never share one stale verdict.

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
