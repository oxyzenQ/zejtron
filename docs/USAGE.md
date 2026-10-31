<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# The zejtron usage playbook

The investigation manual: real scenarios, the exact commands, and how
to read what the Evidence Ledger answers. zejtron is a read-only
evidence tool - every command inspects, none modifies - built on the
Lazy Camera doctrine: no daemon, no background collector, nothing runs
between your commands. The camera shoots only while you are looking
through it.

This document tells you what to run when something feels wrong. It
does not replace the references: the output format is specified
(frozen) in [EVIDENCE-LEDGER.md](EVIDENCE-LEDGER.md), and the kernel
lane's lifecycle is documented in [EBPF_LIFECYCLE.md](EBPF_LIFECYCLE.md).

## How to read the Evidence Ledger

Every zejtron report is an Evidence Ledger - the same grammar on every
surface, so you learn it once. The pieces, top to bottom:

- **The header and mode line.** The first lines name what was asked
  and which lane answered: `Mode: live` means the kernel's own eBPF
  records answered (you are root, the probe is attached);
  `Mode: snapshot (window 10s, journal fallback)` means the report was
  assembled from filesystem metadata and log replay instead. The mode
  line is the honesty seat - it tells you how strong the evidence
  under it can possibly be.
- **The evidence rows.** Each row carries a provenance tier tag:
  - `[observed]` - the kernel recorded the event in flight (the
    strongest tier; only the live lane produces it);
  - `[measured]` - read directly from the filesystem or /proc right
    now (state, not history);
  - `[inferred]` - reconstructed from an indirect source (an audit or
    journal record replayed after the fact);
  - `[unaccounted]` - the named absence: what the report could not
    see, and why.
- **The Changes subsection.** The event window's rows: what happened
  to the queried target in the last N seconds. A window is watched,
  not reconstructed - `--since 30s` waits 30 seconds, because the
  camera only records while the shutter is open. The wait is
  narrated on stderr - a grey countdown, erased before the report
  lands - so an open shutter never looks like a hang.
- **The Unaccounted block.** Always present, even when empty. Read it
  before trusting anything: it names every boundary the evidence
  crossed (a pid that exited before attribution, a record older than
  the window, an event window this user could not have).
- **The two-line verdict.** What the evidence supports, and - just as
  important - what it cannot support. A sparse window gets a sparse
  verdict, never a confident line the rows do not back.

Two habits worth keeping: pipe the output (`zejtron why /etc/hosts |
less`) - stdout is byte-clean on a pipe, zero escape codes - and add
the global `-v` flag to see on stderr which lane was selected and why
(`[lane] live eBPF window selected (attached)`,
`[lane] snapshot only (eBPF not attached)`).

## Privileges: what root unlocks, what non-root gets

zejtron is honest about both worlds, and neither one lies to you.

- **Root (or CAP_BPF/CAP_PERFMON):** `zejtron doctor --attach` is the
  one privileged step - a one-shot that plants the kernel probes and
  pins them under `/sys/fs/bpf/zejtron`, then exits. No daemon. While
  the pins exist, `why`, `holds`, and `touch` get `[observed]` rows:
  the kernel's own record of who opened or wrote what, with the pid
  attributed. `zejtron doctor --detach` unpins everything.
- **Non-root:** every command still runs, on the snapshot lane -
  filesystem metadata plus whatever the audit log or journal recorded.
  When the pins exist but belong to root, the report does not fail: it
  steps down, and the Unaccounted block carries the note
  `1 event window (unavailable without root - falling back to snapshot
  mode)`. That note is the tool telling you a stronger lens existed
  and was out of reach.
- `zejtron doctor` is the readiness oracle: its `[eBPF]` section names
  the kernel's verdict (BTF, lockdown, capabilities, pins) in plain
  rows, so you never guess why the live lane is dark.

## Scenario 1: How to find a RAM leak

**The situation.** The host feels tight. `top` shows the usual
suspects but nothing explains the missing memory - the classic ghost:
memory allocated by a process that exited, or sitting in a file no
directory entry names anymore.

**Run:**

```console
$ sudo zejtron doctor --symptom ram
```

**Read the evidence.** The symptom lane walks four classes of
residual, and each lands in its own section:

- **Exits in the last five seconds** - process exits the kernel
  recorded (the event window, `[observed]` when the probe is live).
  The tool's own invocations are excluded from the rows and named
  in a grey boundary line (`2 exits of this tool excluded`) - a
  watch-loop's self-exits are facts about the observer, not the
  host, and the count rides the JSON as `observer_excluded`.
- **The memory deltas** - the charge/discharge between samples, so a
  slow leak shows as a direction, not a number.
- **Deleted-but-open files** - `/proc/*/fd` targets ending in
  ` (deleted)`: the inode is unlinked, the pages are still resident
  because a process still holds the descriptor.
- **memfd files** - in-memory files (`memfd:` targets) whose pages
  ride the holder: the QC classic is a `memfd:pulseaudio (deleted)`
  blob of tens of megabytes held by a desktop shell process - no file
  on disk, no `du` hit, real resident pages with a named owner.

**Next move.** Each row names the holder pid. Decide with the
attributed name in hand: a stale holder is a restart candidate; a
growing memfd family is a leak in the holder. `--raw` appends the
plain /proc reads the analysis came from, for the drill-down.

## Scenario 2: How to catch a process modifying a config file

**The situation.** A config file - `/etc/hosts`, a unit file, a cron
spool - keeps changing, and nothing in the usual logs says who did
it.

**Run.** One privileged step to arm the camera, then the question:

```console
$ sudo zejtron doctor --attach
$ zejtron why /etc/hosts --since 60s
```

**Read the evidence.** With the probe live, the Changes section
carries `[observed]` rows - the kernel saw the open or the write in
flight, and the row names the actor: process name, pid, user. A row
like `opened - brave (pid 2985, z)` is the kernel's own testimony,
not a reconstruction. The verdict lines then separate what the
evidence proves from what it merely suggests.

**If you run non-root** (or the attach has not happened), the same
command still answers - from the audit log or the journal, tagged
`[inferred]` - and the Unaccounted block carries the
`unavailable without root` note. The report degrades; it does not
die.

**Next move.** Nothing in the window? Widen it: `--since` accepts
`s`/`m`/`h` up to one hour on every verb that has it. Add `--trace`
to see how zejtron knows each row, or `--raw` for the kernel events
as drained.

## Scenario 3: How to track down a missing port

**The situation.** A service is supposed to listen on 443 and nothing
is there - or something is there and nobody admits to it.

**Run:**

```console
$ zejtron port 443
$ zejtron port --listen
$ zejtron port --all --numeric
```

**Read the evidence.** `port 443` answers the direct question: who
owns the port, if anyone. `--listen` narrows to listening and bound
sockets (it excludes `--all` - the two ask opposite questions).
`--all --numeric` shows every parsed socket without name resolution
- the fast, truthful view. Leftover states tell their own story: a
`FIN_WAIT2` row is a connection remnant, not a listener - the peer
left first and the local side is waiting out the clock.

**Next move.** Found an owner pid and want the full picture?
`zejtron holds 443` treats the port like a held resource and reports
the holder with the file-surface's evidence grammar. Want the
connection churn and not the snapshot? `--events-only` renders just
the event window; `--snapshot-only` pins the report to the phase-1
behavior. The window defaults to 60s here and is widened with
`--since` the same way.

## Scenario 4: How to trace a deleted file still consuming disk

**The situation.** `df` says the filesystem is full; `du` over the
tree finds nothing to delete. The missing gigabytes are inodes with
no directory entry - unlinked, but still held open by a running
process.

**Run.** First, find the holders (the doctor's memory symptom lists
deleted-but-open files with their holder pids; the disk symptom gives
the pressure picture):

```console
$ sudo zejtron doctor --symptom ram
$ zejtron touch /path/to/the/deleted/file
$ zejtron holds /path/to/the/deleted/file
```

**Read the evidence.** `touch` is the inspector's touch: it modifies
nothing, and answers when the path last changed - metadata rows
(`[measured]`) plus the write events the window caught
(`[observed]` with the probe live). `holds` answers the question the
release decision needs: which process, by name and pid, still holds
the file open right now. An unlinked inode's space returns when the
last holder closes it or exits - not one byte before.

**Next move.** The holder row is the deliverable: hand it to the
process owner, or restart the holder if it is yours. Re-run `holds`
after the fix - an empty holder list with the df number recovered is
the closure the ledger exists to provide.

## The one-page cheat sheet

```console
zejtron doctor                      # readiness: what can this host answer right now
zejtron doctor --attach             # root, one-shot: arm the kernel probes
zejtron doctor --detach             # unpin everything, idempotent
zejtron doctor --symptom slow       # why is everything slow: one window, ranked findings
zejtron doctor --symptom ram        # the memory ghosts, holders named
zejtron why /etc/hosts --since 60s  # who changed this, with the evidence tier stated
zejtron holds /path/or/443          # who holds this file or port open
zejtron touch /path                 # when did this path last change (modifies nothing)
zejtron recent /etc --limit 20      # what changed here lately
zejtron port --all --numeric        # every socket, no name resolution
zejtron proc --me --depth 2         # the process tree, mine, shallow
zejtron net                         # interfaces and routes
zejtron -v <any command>            # stderr lane trace, stdout stays ledger-clean
```

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
