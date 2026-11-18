<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

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
| `kprobe/vfs_open` | 109 |
| `kprobe/vfs_rename` | 21 |
| `kprobe/vfs_unlink` | 36 |
| `kprobe/vfs_writev` | 104 |
| `tracepoint/raw_syscalls/sys_enter` | 591 |
| `tracepoint/sched/sched_process_exec` | 12 |
| `tracepoint/sched/sched_process_exit` | 75 |
| `tracepoint/sock/inet_sock_set_state` | 144 |
| programs total | **1092** |
| `.text` (shared helper text, BPF-to-BPF calls) | 346 |
| **the whole camera** | **1438** |

For scale: a 1438-instruction camera is a few microseconds of work
per event. The tool that watches your files costs less bytecode than
one screen of C.

## The kernel-side memory cost (source-derived, pinned)

| what | where | size |
| --- | --- | --- |
| `file_events` ring | `ebpf/src/main.rs` | 256 KiB |
| `sock_events` ring | `ebpf/src/sock.rs` | 256 KiB |
| `proc_events` ring | `ebpf/src/exits.rs` | 256 KiB |
| **total kernel-side rings** | 3 rings | **768 KiB** |

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
