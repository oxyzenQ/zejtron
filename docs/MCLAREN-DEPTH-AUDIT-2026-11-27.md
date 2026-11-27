<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->

# night-cafe-mclaren-2 - the depth master audit record

Task date: 2026-11-27. This document is the audit record for the
night-cafe-mclaren-2 session: the design, the engine, and the
architecture were audited end to end the way a race car's drawings,
engine block, and chassis are audited before the build - not by
re-running the previous record's stopwatch, but by going where
night-arc-gems-1 (docs/ARC-GEMS-AUDIT-2026-11-26.md) did not reach:
the kernel-side engine bytes, the subsystem layering graph, the
adversarial-parse depth, the proof instruments run live on this
host, and a fresh determinism certificate. Every claim below cites
what was actually run, so each line reproduces on another host.

## Scope, method, and host honesty

The audit ran on a container host the eBPF lane cannot attach to
(kernel 5.10.134, below the documented 5.15 floor; no CAP_BPF or
CAP_PERFMON; no tracefs) - the same honest-degradation frame the
previous audit used, and the frame the tool itself advertises: the
doctor named its own snapshot mode and its blindness in
`[unaccounted]` rows while this audit worked, exactly as the Evidence
Ledger Specification requires. The attach lane's runtime behavior
stands on the dated owner records
(docs/Z11-GREEN-BASELINE-2026-11-25.md) and the CI legs that run on
real hardware; nothing in this record takes it on faith from this
host, and nothing in it needed to.

Toolchain honesty: this host started bare. The toolchain was
installed from the repository's own pins, not from ad-hoc versions -
stable 1.98.1 (rust-toolchain.toml's channel, plus the musl std the
gate builds through) and the dated nightly-2026-09-18 with rust-src
plus the checksum-verified bpf-linker 0.11.1, both via the
repository's own `scripts/dev/bootstrap-ebpf.sh` (finished green,
138 s). The gate that follows ran through exactly the versions the
repository pins.

What ran live on this host:

- the full commit gate, `./scripts/build.sh check-all -q`: exit 0,
  ok=9 warn=3 fail=0 - the toolchain checks, fmt, `cargo check`
  and `cargo clippy -D warnings` (both feature shapes), the full
  test estate and the no-default-features test lane, the musl
  release build (`gate_build`), codespell. The three warns are the
  host's own honesty notes (no systemd, no CAP_BPF/PERFMON, no
  tracefs), not gate failures.
- the proofs lane, `cd proofs && cargo test --locked`: 30 passed,
  0 failed (the property tier, 4096 shrinkable cases per law).
- the `sig` self-check: D0 through D4 pass; **D5 refused** - the
  HEAD commit carries no GPG signature, and the chain reports the
  refusal by name instead of pretending to a provenance it does not
  have. The refusal is the feature: an unsigned commit must never
  render as signed.
- the determinism certificate, re-issued by hand: `why
  /etc/resolv.conf` rendered twice independently, byte diff empty
  (904 bytes); `path /etc/hosts` and `port --help` byte-identical
  across invocations; `proc --me` differs only in the invocation's
  own pid (8072 vs 8073) - the host changed, the grammar did not,
  which is the contract: same input state, same bytes.
- the ten-verb smoke: every help surface exits 0 (path, recent,
  port, proc, holds, touch, why, net, doctor, sig); the file
  surfaces probe exit 0 on real targets; `port 22`, `proc 1`, and
  `net` render full ledgers at exit 0; a wrong-shaped argument
  (`port /etc/hosts`) is refused with the name of the refusal
  (`error: invalid port: /etc/hosts`) - shape mismatches are
  messages, not crashes.

Marker honesty: this session's captured output showed the documented
`easured]` artifact (AI_AGENTS_READ_THIS.md's capture-trap warning).
The bytes were verified correct before anything was judged, and
nothing was "fixed" - the trap the repository warns about was stepped
into and stepped back out of, by the document's own procedure.

## The kernel-side engine, read end to end (ebpf/src, 2,394 LOC)

This is the audit's center of mass: the previous record verified the
host side by stopwatch; this one reads the engine that runs in
kernel space, statically, against its own contract.

- **Twelve programs, one object, one record contract.** The exec
  counter tracepoint, the socket-state tracepoint, the open kprobe,
  the write stub tracepoint, the writev kprobe, the exit tracepoint,
  the unlink and rename probes, the off-path estate (the mmap-dirty
  anchors, the splice probe, the io_uring probe), and the
  memory-backed fault anchor - all in one ELF, all publishing either
  the 72-byte file record or the 64-byte sock record through
  `src/ebpf/events.rs`, included into the kernel crate via
  `#[path = "../../src/ebpf/events.rs"]` - the very bytes the
  userspace tests and the proofs crate compile. There are no twin
  record definitions to drift.
- **Offsets are data, never code.** Every struct walk reads its
  field offsets from the `offsets` map, written once at attach from
  the host's own BTF, and the loader refuses to attach without a
  BTF-verified set. The source documents why with a measured
  example: `i_ino` sat at offset 64 on the reference probe host
  where the textbook layout says 16 - a compiled-in wrong offset
  would read garbage silently, and the design refuses that failure
  class at the door.
- **Loop discipline holds.** The engine's only iteration is the
  bounded 25-slot offset read (`for slot in 0..OFF_SLOTS`, the
  OFF_SLOTS contract) and the panic handler's arch-required halt.
  Every fd walk is a bounded stage chain with a per-stage census
  slot, not a loop; the 5.15 verifier's combined-stack caps are
  respected by on-demand slot reads instead of by-value offset-set
  copies (the D8 record, itself evidence of real-hardware iteration).
- **Atomic discipline.** No plain shared-field update path exists:
  the exec counter and both censuses ride BPF_ATOMIC fetch_add (the
  lost-update lesson inherited from the lineage), which pins cpu v3
  bytecode - documented against the verified 5.15 floor.
- **The honesty maps are real machinery.** `drop_census` counts one
  fetch_add per FAILED ring reservation; `STATS_QUESTIONS_REFUSED`
  counts the kernel's refused tracked_inodes inserts; the
  write-probe census names the furthest walk stage as one of
  fourteen named slots. The kernel cannot remember what it did not
  record, but it can count the failures - and the userspace drains
  read those counts back into `[unaccounted]` blocks.
- **Every memory read is a probe read.** A bad kernel address
  returns Err (mapped to None), never a fault; a failed walk drops
  the event and never fails the kernel path the probe rides. The
  unsafe blocks are concentrated (13 in the off-path verifier, 4 in
  the ring reader, the rest in the interop readers) and each carries
  its SAFETY contract inline.
- **The license section law.** The ELF `license` section carries
  the kernel-facing `GPL\0` marker because gpl-only helper access
  requires a kernel-recognized string - and the source says, at the
  site, that this is a kernel-interface constant and not the
  project's license claim. AGPL-3.0-only stays the source license.

## The layering graph, counted

A census of `use crate::<subsystem>` statements across `src/**`
(counted per edge, main.rs included):

| Edge | Count |
| --- | --- |
| commands -> evidence | 25 |
| commands -> output | 11 |
| commands -> ebpf | 8 |
| ebpf -> output | 3 |
| cli -> output | 2 |
| commands -> system | 2 |
| commands -> info | 1 |
| ebpf -> info | 1 |
| info -> evidence | 1 |
| update -> output | 1 |
| ebpf -> commands | 2 |

Exactly one pair reads in both directions: commands -> ebpf and
ebpf -> commands. The reverse edges are one function -
`device_token_from_stat` (src/commands/lane.rs) - the pure
st_dev-to-device-token converter that the record contract
(src/ebpf/events.rs documents it), the attach-time self-verification
probes, and the command lane must agree on. It is single-sourced,
pure, I/O-free, and gate-protected; no written law forbids the edge,
and moving a shared contract during the freeze is churn, not value.
The honest verdict: noted, not moved - a future crate split owns it
first. Everything else is a clean one-way fan from commands to the
leaf subsystems, and `main.rs` holds its bootstrap scope (190 lines,
parse-dispatch-exit).

## Parser depth (the adversarial bytes)

- `src/ebpf/btf.rs`: the section layout combines the untrusted
  header offsets with `checked_add` at the trust boundary and
  refuses a short header or an overrunning section by name; every
  per-record loop guards its advance with an explicit `> end` check
  before trusting the record length; all slicing is `.get()`
  (Option-based). Zero `unwrap`, zero `expect`, zero `panic!` sites
  in the parser.
- The dialect lock is real bytes, not synthetic shapes: `corpus/`
  carries committed real kernel BTF (the below-floor dialect bundle
  through the 7.3.3 BTF witness), and the parser regression tests
  run against those bytes every gate lane.
- `src/info/signature.rs` holds the same zero-unwrap posture; its
  inputs are build-embedded rather than adversary-shaped, and this
  record states that distinction rather than inflating the claim.

## The math, run live (not just cited)

- Property tier, run on this host: 30 laws green - the clock
  round-trip over the FULL signed i64 domain, the chronological
  order of the fixed-width timestamp rendering, the watch-gap and
  sleep decision tables sampled over their full stamp domains, the
  filter-key packing laws, the record-size contract pins.
- For-all tier: eight Kani totality theorems wired into proofs.yml
  with measured budgets (the lane's own docs own the numbers); the
  loom instrument carries a signed census NO - the proof-carrying
  cores are pure functions, there is nothing to interleave.
- The proofs crate compiles the binary's own source bytes via
  `#[path]` inclusion - no proof twin to drift from the product.

## Bottleneck question, this host's re-answer

The structural facts re-verified on today's tree: zero `Mutex`/`RwLock`
in `src/` (the grep returns nothing), the read path single-threaded
and lock-free, the one concurrency surface the spinner's two
`Arc<AtomicBool>` flags, the event rings drain on read so no query
queues behind another, and every surface is one pass from kernel
bytes to rendered rows. The live smoke on this host answered every
surface in single-digit to low-double-digit milliseconds at
container scale; the scale-audit margins (4x-33x inside the 500 ms
wall budget) from the previous record remain the measured benchmark,
and nothing in this audit's structural read contradicts them - the
read path is linear in the size of the host, and nothing superlinear
was found. No new bottleneck, no new structural debt.

## Verdict: complete works, not gimmick

Every mechanism the documentation names resolved to a real
implementation site, a gate, or a proof pin. The INNOVATIONS map's
thirty-one source references all resolve to live files. The
repository-wide doc path census found zero stale references - the
one hit, `scripts/package/install.sh` inside CHANGELOG.md, is a
"Removed" entry naming a script that was genuinely deleted, which is
history recording its subject correctly, not staleness. The honesty
machinery itself works on this host: the D5 refusal, the
`[unaccounted]` tiers, the snapshot degradation, the question and
drop censuses, the named refusals on wrong-shaped arguments.

The named residuals the engine declares at its own sites (not
findings of this audit - the source declares them): the plain write
lane cannot see mmap stores (the memory-backed fault anchor's whole
reason to exist), the off-path io_uring probe rides only where the
host's BTF vouches for it, and O_PATH peeks are not opens in the
data sense. Each is documented at the site that owns it, which is
what honest residual reporting looks like.

The over-engineering verdict matches the previous record and this
audit's independent reach: the architecture is at its stated peak.
The high-value investment is keeping the gates red-on-regression and
letting CI carry the weight; nothing found justifies re-engineering,
and this audit changed no source. The one deliverable is this record
and its docs/README.md index row.

## CI at audit time

The HEAD commit this audit read (d646d3b, the night-cafe-mclaren-1
record) carried 18 workflow runs at audit time: 17 success, one
intentional conditional skip, zero failures - green on main, the
baseline this session inherited and stands on.

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
