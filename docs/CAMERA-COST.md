<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->

# The Camera Cost Contract

The price of zejtron's camera, published as arithmetic. Every number
below is either derived from an artifact in this repository (the
committed eBPF object, the BPF sources, the shipped binary) or
enforced as a budget by the suite per push - and every derived
number is pinned by a test (`src/ebpf/cost.rs`,
`test/ebpf/cost_tests.rs`): a probe that grows, a ring that resizes,
or a binary that balloons fails the suite until the contract is
consciously re-pinned in a commit that says why. This is the table a
competitor would have to publish to claim the same thing - none
does, because publishing it requires the floor kernel, the dialect
corpus, and the witness estate that re-prove it per push.

## The eBPF instruction cost (compile-time, pinned)

Derived from `ebpf-prebuilt/zejtron-ebpf.o` (16 KB): every PROGBITS
section named `kprobe/*` or `tracepoint/*` is one program; one BPF
instruction is 8 bytes. The derivation harness prints this table
(`cargo test cost -- --nocapture`); the pins
(`test/ebpf/cost_tests.rs`) freeze it.

| program (its attach hook) | instructions |
| --- | --- |
| `kprobe/__set_page_dirty_nobuffers` (D4, the page-shape dirty anchor) | 225 |
| `kprobe/fault_dirty_shared_page` (D6, the memory-backed fault anchor) | 287 |
| `kprobe/filemap_dirty_folio` (D4, the folio-shape dirty anchor) | 211 |
| `kprobe/vfs_open` | 225 |
| `kprobe/vfs_rename` | 21 |
| `kprobe/vfs_unlink` | 36 |
| `kprobe/vfs_writev` | 219 |
| `tracepoint/io_uring/io_uring_submit_sqe` (D4) | 261 |
| `tracepoint/raw_syscalls/sys_enter` (the write probe + the D4 splice probe) | 1323 |
| `tracepoint/sched/sched_process_exec` | 12 |
| `tracepoint/sched/sched_process_exit` | 75 |
| `tracepoint/sock/inet_sock_set_state` | 261 |
| programs total | **3156** |
| `.text` (shared helper text) | 583 |
| **the whole camera** | **3739** |

night-frontier-Z7 (D4) re-pinned the table consciously: the off-path
trio rides the same cost contract - the mmap-dirty truth, the splice
truth, and the io_uring truth, all still gated by tracked_inodes so
the cost stays bounded by questions, not host activity. THE INLINE
LAW (found live by the C77 root leg): a bpf2bpf call into .text
leaves an unresolved pseudo-call at BPF_PROG_LOAD (the 5.15 runner's
verifier refused the splice probe with EPERM), so every walk is
inlined and each program carries its own hops - the estate's
inline-only discipline, now proven by the table itself.

night-frontier-Z8 (D5) re-pinned the table consciously again: every
record now carries the actor's identity block (cgroup id, comm,
netns inode), and the fill rides each program (the inline-always
helper ebpf/src/identity.rs serves all nine constructors). The
inline-only programs each grew by their own identity walk - the
dirty anchors doubled (109/95 -> 225/211), vfs_open 109 -> 225, the
sys_enter section 935 -> 1323 across the write and splice probes,
the sock probe 144 -> 261, io_uring 143 -> 261 - and the unlink/
rename pair stayed at their own stub sizes because their shared
publish tail lives in .text, which grew 382 -> 547 for the same
fill. The price of "who did this, and from where" riding every
record without a cross-lookup.

night-frontier-Z9 (D6) re-pinned the table consciously a third time:
the memory-backed rung joins the camera - ONE new program, 287
instructions, zero new maps, zero new rings. The probe carries the
whole memory-backed walk inline (the vm_fault.page hop, the mapping
descent, the tracked_inodes gate, and the class gate: the
superblock's registered filesystem name, read through the kernel's
own string helper at event time - "tmpfs"/"ramfs" is the memory-
backed class, data never a compiled guess). The shared text grew
547 -> 583 for the string-read framing beside the identity fill.
The price of closing the tmpfs/ramfs/memfd residual: 287
instructions, bounded by questions like every walk before it.

For scale: a 3739-instruction camera is still a few microseconds of
work per event. The tool that watches your files - INCLUDING the
silent paths no other tool sees, now NAMING who acted and from
which container - costs less bytecode than two screens of C.

## The kernel-side memory cost (source-derived, pinned)

| what | where | size |
| --- | --- | --- |
| `file_events` ring | `ebpf/src/main.rs` | 512 KiB (D5's conscious re-pin: the record grew 40 -> 72 bytes, and the ring doubled so the held-record window GREW - 6553 records at the 80-byte aya stride versus the 5461 the old contract measured) |
| `sock_events` ring | `ebpf/src/sock.rs` | 256 KiB (kept: the filter bounds it to LISTEN/UDP-close transitions too rare to need the memory; 3640 records at the 72-byte stride) |
| `proc_events` ring | `ebpf/src/exits.rs` | 256 KiB (its record did not grow) |
| **total kernel-side rings** | 3 rings | **1 MiB** |

The pins read the SOURCE (not a copy): the scan walks `ebpf/src`
for the `RingBuf::with_byte_size` sites, so a resize moves the sum
and the contract fails until re-pinned. Nothing else is allocated
kernel-side: no per-process state, no global buffer, no watchdog
process - the rings are the whole footprint, and they are bounded.

## The runtime budgets (enforced live per push)

The suite's camera-cost surface enforces these on the booted kernel
on every root CI leg (the kernel floor, the witness span); the
witness logs carry the measured milliseconds per dialect.

| budget | ceiling | how it is enforced |
| --- | --- | --- |
| attach wall time (plant the whole estate: BTF verify, programs, links, pins, generation stamp) | 2000 ms | measured with the suite's own clock, asserted per push |
| userland address space | 64 MiB | `ulimit -v 65536` around the representative surfaces (version, proc, path, why live, doctor with the camera planted) - the kernel itself refuses a run that outgrows the contract |
| shipped binary size | 16 MiB | `stat` on the static musl payload, asserted per push (measured at this writing: ~3.0 MB) |

Measured reference points (the sandbox host, this writing): attach
completes in tens of milliseconds on the floor kernel; peak resident
memory of the representative surfaces measured ~12 MB against the
64 MiB ceiling - five times the headroom, enforced by the kernel,
not promised by the README.

## Why this table is hard to copy

The numbers are the cheap half. The contract is the other half: the
floor kernel that runs them live per push, the five-dialect corpus
that freezes the parsers they depend on, the witness estate that
boots 5.4 through 7.x and re-measures every push, and the pins that
make a silent cost regression a red build. A vendor can print these
rows; matching them requires the whole proof estate this repository
ships.

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
