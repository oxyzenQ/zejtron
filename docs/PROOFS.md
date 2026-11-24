<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->

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
  packing residual, the port decision table, the watch-truth
  materiality, and the sleep blackout's sign law.
- **Kani** (bounded model checking, `cargo kani --lib --harness`):
  FOR ALL INPUTS within each harness's domain. Eight totality
  theorems, one harness per matrix job - a wedged harness consumes
  its own ceiling and can never starve a sibling's verdict:

| Harness | Theorem | Domain | Measured (kani 0.68.0, CaDiCaL, the port host) |
| --- | --- | --- | --- |
| `device_token_zero_extends_for_all_inputs` | the u32 widening is the zero extension | full u32 | 0.02s |
| `record_sizes_are_the_shared_contract_for_all_inputs` | the ring byte counts, the field-by-field offset table, and the append-only head/tail law (night-netrunner-Z2) | static | 0.02s |
| `is_port_surface_event_matches_the_spec_for_all_inputs` | the decision table equals the doc's spec | 32 symbolic bits | 0.02s |
| `pack_filter_key_is_injective_on_the_documented_domain` | no collision inside the documented 32-bit domain | 128 symbolic bits | 0.03s |
| `pack_filter_key_aliases_exactly_as_documented_for_all_inputs` | the residual aliases exactly as the doc pins | 160 symbolic bits | 0.03s |
| `civil_arithmetic_round_trips_and_stays_in_domain_for_all_inputs` | Hinnant round trip + domain invariants (the yoe [0,399] law the leap-day fix restored) | +-4095 years, 41 symbolic bits | 39.7s |
| `watch_gap_materiality_is_the_documented_decision_table_for_all_inputs` | the watch-truth materiality IS the documented decision table (the absence arm, the one-second bound, the unstamped and unreadable arms, the exact-arithmetic identity) | full u64 stamps + Option<u64> pre, clamped window [1s, 1h] | seconds class (the first CI run's hosted number is the standing record) |
| `sleep_blackout_sign_law_holds_for_all_stamp_pairs` | the sleep materiality IS the documented sign law (None on unreadable stamps, the SLEEP_BOUND, the exact delta, never zero) | full u64 stamp pairs | seconds class (the first CI run's hosted number is the standing record) |

  Every job sits two orders of magnitude inside its own 15-minute
  ceiling. The numbers are this host's measurement (the port
  session, 2026-11-18); CI's first runs are the standing record's
  hosted numbers - the two night-netrunner-Z2 harnesses carry their
  budget class until then.

## The matrix split (night-netrunner-Z2, the zelynic shape)

The night-datapath-1 record named the finest split a for-all theorem
allows - one harness, one invocation, one verdict - and
night-netrunner-Z2 enforced the same law one level up: the Kani tier
is the matrix of one-harness jobs, the zelynic proofs lane's own
shape. A wedged harness consumes its own job's 15-minute ceiling and
can never starve a sibling's VERDICT; fail-fast false keeps every
theorem's verdict its own.

## The 30-minute split rule (armed, not triggered)

The owner's law: if a Kani or loom lane ever runs over 30 minutes,
it must split into micro tests. The matrix split (above) is the
invocation law at the job level; the honest FURTHER lever is lemma
decomposition - the zelynic Z12 lever, whose own census taught the
discipline: decompose the wall classes the census MEASURES
(division-inversion derivations, multiply-monotonicity relations,
function-boundary mod/div chains), never a shape that already
decides inside the ceiling. zejtron's tier is 40 seconds of solver
time against a 15-minute budget; nothing here qualifies, and a
proof-shape change that needs its own signed round waits for a
harness that cannot decide inside 30 minutes. The budget is never
the lever - a bigger budget turns an undecided theorem into a longer
wait, not a verdict.

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
mutable state. The FULL concurrency inventory (the
night-netrunner-Z2 re-census, the LTS release's audit copy): the
userspace tree's set-once statics (`src/output/capability.rs`,
`src/output/verbose.rs`) and its OnceLocks
(`src/output/capability.rs`, `src/cli/mod.rs`) ride std's own
synchronization; the spinner's two `Arc<AtomicBool>` flags
(`src/output/spinner.rs`) are a cross-thread UI handshake with no
compound invariant - the worst an interleaving reaches is a
cosmetic frame, never corrupt state; the kernel side carries
per-slot monotonic `fetch_add` counters (`ebpf/src/main.rs`'s drop
census, `ebpf/src/write.rs`'s per-stage stats) whose slot ownership
is compile-time static and whose exactness rides the fetch_add
primitive itself - no CAS, no spin lock, no compound protocol, and
NO location-backed raw-memory atomic anywhere in the tree.
Inventing shared state a checker could explore would prove a model,
not the bytes the binary runs.

The zelynic night-frontier-Z17 shape (the interleaving theorem over
a budget core's CAS composition) was examined against this tree and
returned the same SKIP, for the same reason: zejtron is a camera,
not a limiter - the budget-core subject does not exist here, and a
theorem needs a subject, not a target of opportunity. Proving the
counters' exactness for all interleavings would prove the fetch_add
primitive (the toolchain's own contract), not zejtron's bytes - the
same model-not-proof refusal the census already signed. The verdict
is standing-enforced, not archival: the proofs lane's `loom-census`
job re-reads the tree on every push and fails the day a
location-backed atomic lands outside the designated shape or a loom
dependency enters without a standing lane. The instrument reopens
the day the tree carries a real shared-memory protocol - the honest
further lever then is the Z17 lemma decomposition, never a bigger
budget.

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
