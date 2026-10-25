<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# the fuzz lane's seed anchors

Three hand-built BTF blobs, one directory per fuzz target, seeded
into the working corpus by the lane itself (`.github/workflows/
fuzz.yml` copies them under `fuzz/corpus/<target>/` before every
run, after the cache restore, so the fuzzer starts the session
from the shapes that matter instead of rediscovering a valid BTF
header byte by byte).

These files are data, not code: the lane's definition travels
with the repo (the same law as the targets and the manifests in
`fuzz/Cargo.toml`), while the corpus the fuzzer GROWS between
runs stays out of git (`fuzz/.gitignore`) - a seed names a shape
the parser must hold, a grown corpus entry is a discovery, and
only the first kind belongs in a commit. The anchors mirror the
synthetic blobs the unit suite pins in `test/ebpf/btf_tests.rs`
and `test/ebpf/btf_flatten_tests.rs` (night-improve-49's
anonymous-descent shapes), so every parse expectation below is
already asserted byte-for-shape by the rust tests; the seeds
carry those same shapes into the fuzz lane's own budget.

## btf_parser

- `file-f-path-in-unnamed-union.bin` - the kernel 6.18 shape:
  struct file's f_path rides an unnamed union (a const-wrapped
  struct path beside its writable `__f_path` twin), the exact
  layout Al Viro's constification landed on the 6.18 line. The
  twelve-offset parse must answer
  `[48, 64, 0, 16, 8, 16, 0, 8, 16, 0, 0, 8]` - the union descent
  finding f_path, f_inode still direct, the fd-walk trio
  (night-improve-57) parsed after the frozen eight.
- `file-f-path-two-level-anon-nest.bin` - a two-level anonymous
  nest (unnamed union into a const-wrapped unnamed struct, both
  at nonzero bases), the accumulation math pinned: f_path lands
  at byte 96 (64 + 32 + 0), so the depth-8 descent, the qualifier
  resolution, and the offset summing all ride the fuzzed path;
  the fd-walk trio rides behind (16, 0, 0, 8).
- `direct-members-plus-vfs-writev.bin` - the pre-6.18 direct-member
  layout carrying a verifiable `vfs_writev(file*, ...)` FUNC
  record (the file struct's id is load-bearing for the arg0 walk,
  so the fd-walk trio rides after the writev records): the parse
  answers `[48, 64, 16, 32, 8, 16, 0, 8, 16, 0, 0, 8]` and
  the writev walk resolves arg0 through the pointer to struct
  file - the one anchor that exercises BOTH pure entry points
  the harness drives.

The other two targets carry no seeds yet: `proc_parser` and
`sanitize_display` read byte grammars whose entry shapes are
cheap for coverage-guided mutation to reach from an empty
corpus, and a seed file with nothing structural to teach would
be ceremony, not depth.

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
