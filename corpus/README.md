<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# The Kernel Dialect Corpus

This directory is the parser regression lock (night-frontier-Z2,
E2): REAL kernel bytes, committed whole, so a parser change that
would misread any committed dialect fails the suite on every host,
forever. The moving kernels are locked live on the CI witness legs
(jammy 5.15, noble 6.8, cachyos - the parsers read those hosts' own
/proc and BTF on every push); this corpus freezes the dialects
themselves, so the lock also holds where no live kernel can run.

Every file here is REAL bytes captured or extracted from a real
kernel - nothing is synthesized, and the provenance of every file
is stated below. The digests are pinned in the tests
(`test/ebpf/btf_corpus_tests.rs`, `test/corpus/proc_corpus_tests.rs`)
through the tree's own blake3 implementation; a file that drifts by
one byte refuses by digest before any parse runs. The directory is
repo-only (outside the crate's `include` list) - it ships with the
repository, never inside a published tarball.

## btf/ — real kernel BTF blobs

Both blobs are the `.BTF` sections extracted from the shipped
`vmlinuz` of Ubuntu GA kernel packages (the archive.ubuntu.com pool
packages, downloaded unmodified; the extraction unwraps the
compressed payload and copies the section with `objcopy`). Both are
the exact kernels the CI lanes boot:

| file | kernel | source package | size |
| --- | --- | --- | --- |
| `5.15.0-25-generic.btf` | jammy GA 5.15.0-25 (the attach floor's own kernel) | `linux-image-unsigned-5.15.0-25-generic_5.15.0-25.25_amd64.deb` | 5,169,768 B |
| `6.8.0-31-generic.btf` | noble GA 6.8.0-31 (the second-generation witness kernel) | `linux-image-unsigned-6.8.0-31-generic_6.8.0-31.31_amd64.deb` | 6,052,713 B |

The two blobs are the offsets law's range made concrete: their
derived walk tables DIFFER where the kernel generations moved
(`file.f_path` 16 → 152, `file.f_inode` 32 → 168,
`task_struct.files` 2928 → 3080) and agree where the layouts held.
The tests pin both tables, both digests, and the disagreement
itself - a corpus that carried one blob twice would flatten the
range pin and fail.

## kernel-dialect/ — real /proc captures

| file | what it is |
| --- | --- |
| `5.10.134-kangaroo-al8/meminfo` | `/proc/meminfo` from the live sandbox host, kernel 5.10.134 (kangaroo al8) - one dialect BELOW the attach floor: parsing is wider than attaching, and the corpus proves the parsers read formats older than the estate promises |
| `5.10.134-kangaroo-al8/status` | `/proc/<pid>/status` of pid 13333, the `cp` process that performed the capture - the bundle's own worker, its provenance stated by being its own fixture |
| `5.10.134-kangaroo-al8/status-pid1.txt` | `/proc/1/status` of the same host - the sandbox's `tini` init |
| `5.10.134-kangaroo-al8/net/{tcp,tcp6,udp,udp6,dev}`, `stat`, `diskstats`, `mounts`, `uptime`, `loadavg` | the same host's live `/proc` files at capture time (2026-11-14), the parsers' full input surface |

Captured 2026-11-14 from the project's own sandbox host. The
process facts inside (`cp`, `tini`) belong to the capture itself -
they are the bytes the parsers must read, stated plainly.

## Adding a dialect

1. Capture (or extract) the real bytes on a real host.
2. Commit them under `corpus/btf/<release>.btf` or
   `corpus/kernel-dialect/<release>/`.
3. Run `cargo test the_btf_corpus -- --nocapture` (the derivation
   harness prints the digest and the walk table).
4. Pin the digest and the table in the corpus tests. Values are
   derived from the committed bytes, never guessed.

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
