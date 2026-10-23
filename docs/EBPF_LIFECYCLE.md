<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# The eBPF Lifecycle

**The Lazy Camera Doctrine**

This document is the citable definition of how zejtron's eBPF lane
lives on a host: when it starts, where it records, who drains it,
and why none of that makes zejtron a monitoring daemon. The
reference implementation is `src/ebpf/` (the loader, the rings, the
readers) and `ebpf/src/main.rs` (the kernel-side programs); this
document is the prose rendering of that code, and the code wins any
disagreement.

## 1. The two modes

zejtron answers questions in exactly two modes, and every surface
names which one it rode:

- **Snapshot** - a direct read of `/proc` and `/sys` at the instant
  of the command: what HOLDS right now. `path`, `recent`, `proc`,
  `net`, the doctor's checks, and the state half of every evidence
  report ride this mode. A snapshot needs no privileges beyond the
  invoking user's own, sees exactly what the kernel shows that
  user, and is gone the moment the command exits. Its truth is a
  photograph: the scene at one instant, not the act.

- **Live** - a kernel-recorded event, captured by an eBPF program
  attached inside the kernel at the moment the action crossed an
  entry point: what HAPPENED, with the acting process's PID, in the
  order it happened. The `--since` windows of `port`, `holds`,
  `touch`, and `why` ride this mode. Its truth is a recording: the
  transition itself, not the state before or after it.

The two modes meet in the Evidence Ledger's provenance tiers: a
snapshot row is `[measured]` (direct perception of state), a
kernel-recorded row is `[observed]` (direct perception of the
event), and a report that could reach neither says so in its
Unaccounted block instead of guessing. A snapshot can miss a change
that happened a second ago; a recording can miss a state that
already reversed. Two truths, kept distinct, on purpose.

## 2. The Lazy Camera

The live mode is a camera, not a feed. After `doctor --attach`
plants it, the kernel-side programs record events into **bounded
ring buffers that live in kernel memory** - and that is the whole
recording story. Nothing streams to userspace. Nothing is written
to disk. No zejtron process exists between commands to receive
anything, because there is nothing to receive: the events sit in
the rings, inside the kernel, until a command drains them.

The rings are rolling windows with hard bounds - 256 KiB each,
where the oldest records are overwritten when a ring fills, and a
failed reservation drops an event without failing the probed
kernel path. Each ring is also filtered at the source, in the
kernel, before a single byte of ring traffic is spent: the socket
probe keeps only port-surface transitions (a busy host's ESTABLISHED
churn never crosses), and the file probes check the tracked-inodes
map so only the one file a command asked about is recorded. The
camera has a fixed-size film roll; it cannot grow, and it cannot
be made to persist.

This shape is the answer to the question every eBPF tool gets
asked: "so it runs in the background?" No. The BACKGROUND is the
kernel itself, doing what the kernel already does - executing
processes, opening files, changing socket states - with six small
programs riding those paths and writing compact records into three
bounded rings (the socket ring, the file ring, and the post-mortem
exit ring night-improve-47 added). The userspace half of zejtron is
lazy: it
exists only for the lifetime of a command, and between commands it
is not asleep, it is absent.

## 3. The lifecycle

The lane's whole life, boot to boot:

1. **Attach, once per boot.** `sudo zejtron doctor --attach` loads
   the embedded pure-Rust object (six programs: the
   `sched_process_exec` counter, the `inet_sock_set_state`
   socket-event probe, the `vfs_open`/`vfs_write`/`vfs_writev` file
   probes, and the `sched_process_exit` post-mortem exit probe),
   verifies every struct offset and the vectorized-
   write symbol against the host's own BTF - the member lookups
   descend the anonymous unions 6.18-line kernels wrap their
   members in, and still refuse by name when a member cannot be
   found - attaches each program,
   and pins programs, links, and maps under `/sys/fs/bpf/zejtron`.
   The attach prints its summary and exits. Because bpffs is a
   virtual filesystem, the pins do not survive a reboot - the lane
   is per-boot by physics, not by policy.

2. **The kernel records.** From attach until drain, the programs
   write records into the rings as events cross their probes. The
   pinned links keep the programs attached and the pinned maps
   keep the rings alive with no zejtron process anywhere on the
   host. A record carries the fact and the actor - a port, a
   transition, an inode, an action, a process exit with its pid and
   its name, a monotonic timestamp -
   and nothing else: no file contents, no addresses beyond the
   socket's own identity, no payload of any kind.

3. **A command drains.** `zejtron port --since 30s`, `zejtron why
   <path> --since 30s`, and their siblings open the pinned rings by
   path - the read side needs no capabilities, only the bpffs walk
   - and drain the records the kernel holds. The doctor's ram
   symptom drains the exit ring the same way for its last-five-
   seconds post-mortem section, and the night-improve-48 symptom
   lanes (`cpu`, `disk`, `network`, `gpu`) drain a 2-second slice
   of the same ring as their sampling overlay - wide enough to
   cover their own 1.0-second sampling window plus the drain's own
   skew, narrow enough that every [observed] row is one of the
   freshest facts on the host. A ring read CONSUMES:
   advancing the reader advances the consumer position stored in
   the kernel map, so each drain sees what accumulated since the
   previous drain (or since attach, for the first). The window
   waits for its own duration - the wait IS the collection, so a
   section labeled "last 30s" really watched the last 30s - and
   the command prints its Evidence Ledger section and exits.

4. **Optional detach.** `sudo zejtron doctor --detach` unpins
   everything (links first, so an interrupted cleanup leaves a
   detached probe, never a half-attached one) and removes the pin
   directory. The kernel footprint is exactly zero again - the
   same state a host that never attached has.

The doctor's `[eBPF]` section reports the lane's state in every
run, attached or not: the kernel, BTF, lockdown, and capability
verdicts, the lane, and the camera's own posture - `Mode: Lazy
Camera (Kernel: recording | CLI: asleep)` when the probe is
attached, `Mode: Lazy Camera (Kernel: not recording | CLI:
asleep)` when it is not. One probe, one verdict, no drift between
the doctor and the attach preflight.

## 4. Why this is not monitoring

The difference between a lazy camera and a monitor is the
difference between a photograph you ask for and a feed that never
stops:

- **No daemon, no agent, no telemetry.** Nothing of zejtron runs
  between commands. There is no socket, no port, no listener, no
  heartbeat, no writer - the userspace half literally does not
  exist between invocations. The project's "never" list is
  explicit: zejtron will never be a daemon, an agent, or a
  telemetry endpoint.

- **Zero footprint when not invoked.** Between commands the lane's
  entire presence is six small kernel programs writing fixed-size
  records into three bounded rings - kernel memory the attach
  already paid for, zero CPU on quiet paths (the filters
  run before the records), zero userspace memory, zero wakeups.

- **Nothing is written to disk.** The rings live in kernel memory
  and die with the pins. No logs, no spools, no state files, no
  caches. A drained event exists in exactly one place after the
  drain: the terminal that asked.

- **The user asks; the camera answers; the CLI exits.** Every
  drain is one command's lifetime. No drain runs unattended, no
  window opens without a command that asked for it, and the
  consumption semantics keep even the record-keeping honest: what
  nobody asked about is overwritten by what the rings can still
  hold, exactly as a rolling camera's film roll overwrites its
  oldest frames.

A monitor watches so it can alert. zejtron records so it can
answer - and only when asked. The distinction is not rhetorical;
it is the difference between a tool an operator runs and a tool
that runs on the operator.

## 5. What the camera cannot see

Honest limits, named here so no surface has to discover them the
hard way:

- **The rolling window.** A full ring overwrites its oldest
  records. On a quiet host the rings hold minutes-to-hours of
  history; on a busy one the window is what it is. A drain reports
  what the ring held, never what it might have held.

- **The consumption semantics.** A drained event is consumed. Two
  `--since` windows back to back show different sets not because
  the kernel changed its story but because the first command read
  the chapters it asked for. The alternative - a persistent reader
  - is a daemon, and the lane refuses it.

- **The filter discipline.** The file probes record only the file a
  command is asking about, for the duration that command asked -
  the tracked-inodes map is planted at the start of a wait and
  removed at its end. A file nobody queried has no file history
  waiting anywhere. The exit ring is the one deliberate
  exception: it records every process exit (leader-only - one
  record per process), because the post-mortem doctor cannot know
  in advance which exit will be the one it is asked about; its
  bound is the ring's own rolling window.

- **The pre-attach past.** The camera starts at attach. What
  crossed the kernel before the attach is unreachable by this lane,
  and the surfaces that care say so through their fallback ladder
  (audit, journal, snapshot) instead of pretending.

- **The probe floor.** The lane needs kernel >= 5.15, lockdown
  inactive, and `CAP_BPF` + `CAP_PERFMON` for attach - and the
  doctor names every missing piece, per host, in every run.

The posture under all of it is zero-leakage: metadata only, never
content. A path is metadata; a write's bytes are not. A port and a
PID are metadata; a packet's payload is not. The camera records
what happened and who did it - the "who", the "what", and the
"when" - and leaves the "what exactly" to the operator, on
purpose.
