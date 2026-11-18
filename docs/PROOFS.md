<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# zejtron Proofs (night-datapath-1, the proven datapath)

The unit test answers "I ran this input and it behaved". The proof
answers "NO input can make it misbehave". This document is the home
of the second claim: what the proofs package verifies, with which
instruments, under which budgets, and what was examined and signed
away. The vehicle is the `zejtron - Proofs` workflow (per push, per
pull request); the instruments live in the detached `proofs/` nested
package - the ebpf/ crate's own detachment shape, so the proof
instruments never enter the root manifest's dependency graph and
nothing here ships in any binary.

## The include law: a theorem about the bytes the binary runs

The proofs crate compiles the userspace tree's leaf law files through
`#[path]` wirings - the fuzz harnesses' include law, one directory
over. There is no re-implementation to drift: the theorem the lane
verifies is about the same bytes `src/main.rs` builds into the
binary. Two files are wired today:

- `src/ebpf/events.rs` - the layout contract between the BPF program
  and the userspace reader: the event records, the filter-key
  packing, the port decision table. Plain core Rust, no aya, no
  libc.
- `src/info/clock.rs` - the civil clock: Hinnant's civil arithmetic,
  the signed unix-seconds conversion and its panic-free inverse.
  std plus the libc pair (the monotonic helper the binary carries),
  which is why the proofs manifest carries libc - dev-instrument
  only, detached from the root graph.

Night-datapath-1 moved the events contract's test declaration
(`test/ebpf/file_events_tests.rs`) out of the law file into
`src/ebpf/mod.rs`: a leaf law file carries no `#[cfg(test)]` module,
or the proofs package would compile the root crate's test scope.
The same test file runs in the same gate lanes; nothing moved but
the declaration.

## The instruments and their division of work

- **Proptest** (stable, `cargo test`): 4096 shrinkable cases per law
  per run - the sampled-but-shrinking instrument. Laws whose domain
  a bounded model checker cannot reach live here: the SystemTime
  round trip across the full signed i64 (std's SystemTime arithmetic
  is syscall-backed, outside a model checker's reach), the
  timestamp's chronological ordering, and sampled bridges for the
  packing residual and the port decision table.
- **Kani** (bounded model checking, `cargo kani --lib --harness`):
  FOR ALL INPUTS within each harness's domain. Six totality
  theorems, one invocation per harness - a verdict is never lost to
  a sibling's budget:

| Harness | Theorem | Domain | Measured (kani 0.68.0, CaDiCaL, the port host) |
| --- | --- | --- | --- |
| `device_token_zero_extends_for_all_inputs` | the u32 widening is the zero extension | full u32 | 0.02s |
| `record_sizes_are_the_shared_contract_for_all_inputs` | the ring byte counts are the struct sizes | static | 0.02s |
| `is_port_surface_event_matches_the_spec_for_all_inputs` | the decision table equals the doc's spec | 32 symbolic bits | 0.02s |
| `pack_filter_key_is_injective_on_the_documented_domain` | no collision inside the documented 32-bit domain | 128 symbolic bits | 0.03s |
| `pack_filter_key_aliases_exactly_as_documented_for_all_inputs` | the residual aliases exactly as the doc pins | 160 symbolic bits | 0.03s |
| `civil_arithmetic_round_trips_and_stays_in_domain_for_all_inputs` | Hinnant round trip + domain invariants (the yoe [0,399] law the leap-day fix restored) | +-4095 years, 41 symbolic bits | 39.7s |

  The whole Kani tier is 40 seconds of solver time inside the job's
  15-minute ceiling. The numbers are this host's measurement (the
  port session, 2026-11-18); CI's first runs are the standing
  record's hosted numbers.

## The 30-minute split rule (armed, not triggered)

The owner's law: if a Kani or loom lane ever runs over 30 minutes,
it must split into micro tests. The per-push lane already sits at
the finest split a for-all theorem allows - one harness, one
invocation, one verdict - and its measurement is 40 seconds against
a 15-minute budget. The honest further lever is lemma decomposition,
a proof-shape change that needs its own signed round; a harness that
cannot decide inside 30 minutes moves to that round. The budget is
never the lever - a bigger budget turns an undecided theorem into a
longer wait, not a verdict.

## Why there is no night lane

The zelynic reference split a solver-bound tier (four theorems
measured unfinished at ten minutes) into a night lane with
per-harness budgets. zejtron's theorems carry no such circuit: the
slowest harness measured 39.7 seconds. A night lane with nothing
solver-bound in it would be a schedule-only lane - a Skipped row on
every push, the shape the estate's law forbids. The lane reopens the
day a theorem measures undecided, with real numbers.

## The loom census: censused, NOT adopted (signed verdict)

Loom 0.7.3 proves interleavings of shared-memory protocols.
zejtron's proof-carrying cores are pure functions with no shared
mutable state, and the userspace tree's two atomics
(`src/output/capability.rs`, `src/output/verbose.rs`) are plain
startup statics - set once, read after, no location-backed
raw-memory CAS discipline anywhere. Inventing shared state a checker
could explore would prove a model, not the bytes the binary runs.
The verdict is standing-enforced, not archival: the proofs lane's
`loom-census` job re-reads the tree on every push and fails the day
a location-backed atomic lands outside the designated files or a
loom dependency enters without a standing lane. The instrument
reopens the day the tree carries a real shared-memory protocol.

## Reproduce locally

```bash
cd proofs
cargo test                       # the proptest tier (stable)
cargo install --locked kani-verifier@0.68.0
cargo kani setup                 # once: the bundled toolchain
cargo kani --lib --harness device_token_zero_extends_for_all_inputs
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
