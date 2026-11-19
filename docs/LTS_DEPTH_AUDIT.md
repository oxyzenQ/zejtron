<!-- SPDX-FileCopyrightText: 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# The LTS depth audit (night-depth-hardening-4 / night-zen-lts-2 / night-zen-lts-1)

Date: 2026-11-18. Scope: the whole root repo, five pillars, one rule -
fix what bites, skip what is at peak, and say so. The audit ran three
independent sweeps (infra, source, deterministic-output precision)
plus a local stress pass, and every finding below carries its
disposition: FIXED (with the commit), SKIPPED (why, honestly), or
PEAK (already at its ceiling, nothing to do).

## 1. Stability & crash

FIXED - none needed at the crash level. The stress pass found no
crashes, no coredumps, no engine failures: 709/709 tests, the whole
read-lane surface double-run byte-compared, and the three kernel-fed
parsers (BTF, netlink, ring buffer) degrade instead of panicking on
malformed input. Two latent stability risks WERE fixed before they
could bite:

- `src/ebpf/btf.rs` - a malformed BTF blob could turn the
  anonymous-member descent into a minutes-long grind (member visits x
  record_pos walks, no total-work ceiling). The walk now shares a
  1024-unit budget across its recursion; real structs cost a few
  dozen units, the hostile worst case dies in under a second, fuzz
  target included.
- The doctor JSON exits lane sampled the wall offset PER ROW inside
  its render closure - an NTP step mid-render split one document's
  rows across two civil times, violating the one-offset-per-render
  law the module's own comment claimed it honored. The sample is
  hoisted above the row loop (the text lane's shape).

PEAK (skip, verified): the ring contract (repr(C) + checked casts +
capacity-equal drain), the netlink walk (every stride bounds-checked),
the evidence JSON serializer (fixed key order, integer-only numbers),
the guest_exit belt in the sandbox, the release draft-then-publish
tripwires. The LTS ledger from the source sweep: ring wraparound,
monotonic-clock headroom, 2038 safety, pid recycling, inode reuse -
all checked and clean, none need work.

## 2. Code hygiene (the dragon hunt)

FIXED:

- `src/ebpf/btf.rs` breached the 600 no-mercy cap at 612 lines. Split
  per the law, not exempted: the byte-level decode (`decode_info`,
  `kind_extra_bytes`, `u32_at`) moved to its own 49-line module
  (`src/ebpf/btf_decode.rs`), the walker stays under the cap at 577.
- `scripts/gate-keepers.sh` - a dead no-op block (`SHELL_FILES=""`
  assigned to an empty var behind a stale comment) and a dead
  SKIP_FILES era entry removed; the qc runner at the tree root now
  rides the wholesale lint quad and the scripts LOC cap (it was
  outside every gate).
- Comment rot from the GNU purge, counted honestly: "all four builds"
  (the matrix is two legs) in release.yml and the parity gate,
  "18 sections" (21 gates run) in gate-keepers.yml, "45-minute job
  timeout" (the cap is 10) in codeql.yml, "six attach targets" (eight)
  in regenerate-ebpf-prebuilt.sh. A wrong count is a wrong contract
  for the next maintainer.
- The witnesses lane's cert-binary comment claimed the test build
  inherits the alias's v3 rustflags "verbatim" - false (the alias's
  -C tokens ride the alias invocation only). Rewritten to state the
  real scope: every leg builds the same shape, so the digests compare;
  nobody may assert the v3 label on the cert binary.

SKIPPED (over-engineering, per the mandate): the dev-token decode
exists three times across lane.rs/holds - documented deliberate, and
unifying it changes the BTF record contract for zero behavior change.
The three hand-rolled DNS-hardening steps pre-date the composite
action but carry a duplicate guard the action lacks; folding them is
churn on three proven lanes for one cosmetic drift. `push_rolling`,
`cost.rs`'s derivation harness and the pathguard module stay as
documented test seams and retained foundations - they are named in
their own headers, not orphaned.

## 3. Optimization

PEAK (skip, verified, with the one exception noted): the hot paths
were profiled by construction - the net lane, port renderer and
evidence ledgers all sort at the collection boundary with total-order
tails (the night-depth-hardening-1 campaign), the parser reads each
BTF file once, the ring drain consumes by contract. The one real
waste found was not CPU but INFRA: the fuzz corpus cache minted three
brand-new entries per push (one per target), orphaning the previous
generation and eroding the shared 10 GB cache budget under which the
release lanes already red once. The cache is split restore/save, the
save gated to the weekly sweep - corpus growth bounded, per-push churn
zero. The container E2E lane got the ebpf-build cache every other
compile lane shares (it alone cold-rebuilt the nested object) and a
cap recalibrated to what its cold path can actually cost.

## 4. Security hardening (white hat / kernel hacker mode)

FIXED:

- `src/ebpf/verify_write.rs` - the one root-writable predictable
  surface: the attach self-verification wrote through
  `/tmp/zejtron-verify-write-<pid>/`, a symlink-following, pre-plantable
  path (a local attacker could clobber an arbitrary file as root via
  a planted probe symlink). The scratch now rides an OS-random name
  (std `RandomState` entropy, zero new dependencies), is created by
  an atomic `mkdir(2)` with collision retry, and refuses any directory
  whose owner is not the process's effective uid (read from
  /proc/self/status, fail-closed) BEFORE the first byte is written.
  The pre-planted variant is dead by construction.
- `src/system/pathguard.rs` - a trailing slash on HOME made the
  credential blocklist miss (`/home/z//.ssh/` never matched the
  canonical candidate). The deny prefixes build through
  `PathBuf::join` and compare by components now.
- `src/update/mod.rs` - the one network surface resolved curl through
  PATH, so a hostile PATH could feed the user a forged update verdict.
  Fixed-path probes first (/usr/bin, /bin, /usr/local/bin), PATH
  fallback documented as message-only residual exposure.
- `src/commands/doctor/checks.rs` - the kernel readiness row read
  `uname` through PATH; it reads /proc/sys/kernel/osrelease directly.
  The command probes (systemctl, journalctl) stay PATH-resolved by
  contract: their availability IS the fact the row reports.
- `src/ebpf/btf.rs` (+ `btf_decode.rs`) - the kind_flag field is now
  decoded per the kernel's btf.h (`vlen:10 | klen:6` when bit 31 is
  set), where the old code read all sixteen bits as vlen. Zero live
  desync on the 5.15-7.3 corpus (every flagged record carries klen
  zero), so this is the future-kernel guard pinned by the corpus
  tests.
- `.github/workflows/fuzz.yml` - cargo-fuzz was the estate's one
  unpinned scanner on a per-push lane (an unauthenticated
  crates.io-to-execute surface on a repo that sha256-pins every other
  byte). Pinned to 0.13.2, the version the lane has been running.

PEAK (skip, verified): the provenance/signature math, the JSON
escaper, the netlink SAFETY arguments, the root_refusal contract on
the network surface. The loader's garbled refusal literals (hard-wrapped
without continuations) were fixed as a courtesy while here - every
attach refusal now prints what it means.

## 5. LTS stability & the deterministic-output contract

The mission's headline: precision and deterministic output for every
distro at 5.15+. Verdict after the sweep: the contract HOLDS for the
evidence ledgers, the JSON lanes, the -V/sig digests and every sorted
surface (UTC-only clock, no locale reads, no COLUMNS dependence,
1024-based units, total-order sorts with pid/name/path tails), and
the two leaks that kept it partial are FIXED:

- The net lane's ARP neighbors and routes rode the kernel's
  hash-bucket/file order - byte-stable across runs and kernel versions
  now (sorted at the collection boundary; proven locally: three runs
  under live neighbor churn, byte-identical).
- The doctor JSON per-row offset (the one-offset law, above).

The remaining doctor variance is inherent evidence content, named and
accepted: the doctor's own PID row (a live process changes PID by
definition) and the kernel's live memory between samples. The
certificate lane remains the pin for what can be pinned. SKIPPED:
making the doctor JSON's boot-relative `timestamp_ns` wall-anchored -
it is the record's own fact and any pin over it would be a lie about
the host; the scan-stamps in the ledgers are the same class.

Infra endurance (night-zen-lts-2): the release lane's apt step gained
the Acquire::Retries posture the kernel lanes already carry (a slow
mirror must not red the tag run), the apt b3sum duplicate is gone (the
pinned 1.8.7 from the bootstrap signs the release - the signing tool's
version is a pin, not a PATH-order accident), the maintenance lane
rebases before its weekly push, the local kernel-matrix seat rides the
CI ladder's six suites, the version-sync gate polices RUSTUP_TOOLCHAIN
pins, and the release-parity gate counts platforms without a number
that can rot.

## The gates, after

709/709 tests, clippy `-D warnings` clean, check-all exit 0,
gate-keepers 22/22 (was 20/2 - the two failures were the LOC cap the
btf split answers and the qc-runner coverage it adds), release-parity
and version-sync green with their new arms, yamllint + actionlint
clean on all twenty workflows, shellcheck clean via the wholesale
quad, and the full CI board watched to green on the fix head.

## Honest scope

Three audit agents swept infra, source and output precision; their
findings were re-verified before fixing (one finding - the floor
lane's "redundant" rust-std target - was verified FALSE and skipped:
that lane's dtolnay step carries no targets input). The skipped items
above are skipped on purpose, not missed; each is named so the next
audit can re-judge with fresh eyes.

## The night-zen-lts-Z session (2026-11-19)

A fresh-eyes sweep over the delta the fortress audit never saw: the
Z1-Z10 frontier eras (256 commits, 109 Rust files since v80.0.0) -
the code newest enough to have escaped every prior depth pass - plus
the standing lenses (determinism, panic census, kernel-probe safety,
infra) re-run against it. Session note: the recycled audit container
had lost bpf-linker, and `./scripts/dev/bootstrap-ebpf.sh` restored
the toolchain pair in one command - the panic message's own remedy,
working as designed. Baseline after restore: 758/758 tests (the Z9/Z10
eras grew the suite from 709), clippy `-D warnings` clean.

### 1. Stability & crash

PEAK (skip, verified): the Z10 watch-truth arithmetic read end to end
(`material_watch_gap_ns`, the boottime pairing, the `PreBreath`
four-reading shape) - i128 throughout, saturating clock reads, the
one-second materiality bound, the backwards-pairing anomaly arm named.
No overflow, no underflow, no division, no panic path. The Z9 kernel
side (`membacked.rs`, `offpath.rs`) keeps the verifier-safe discipline:
every hop an `Option` probe-read through the three helpers, the
anon/ksm low-bit guard, the tracked gate before ring traffic, the fd
bounds check, zero loops. No crashes, no coredumps, nothing to fix.

### 2. Code hygiene (the dragon hunt)

FIXED (three micro-commits):

- The generation map's FIVE-slot contract (efc295e): night-frontier-
  Z10 grew the pinned map to `with_max_entries(5)`, but
  `GENERATION_SLOTS` stayed 4 - pinned by a test asserting the stale
  value - and the map's doc in `ebpf/src/main.rs` still said "four
  slots". The count constant, the slot-lockstep pins, and the doc now
  say five, and the lockstep test gained the fifth slot's assert
  (`GEN_SLOT_ATTACHED_MONOTONIC`, the watch-truth datum). A wrong
  count is a wrong contract.
- The Z8/Z9/Z10 line-join damage in four message literals (7fa8b07):
  the identity-walk attach refusal, the two pre-Z2 estate errors, and
  the off-path offsets summary carried 14-18-space runs mid-sentence -
  the same garbled-refusal class the last audit healed elsewhere in
  the loader. Every literal prints what it means again.
- The Z10-era doc misattachments (607e3b5): `monotonic_now_ns`'s doc
  was doubled verbatim (eighteen lines twice); `format_sleep_span`'s
  doc sat stranded above `current_clocksource`; and
  `capture_file_window`'s doc had been orphaned onto the `PreBreath`
  struct by a doc inserted without a separating blank line - rustdoc
  concatenates adjacent blocks, so the function rode undocumented and
  "the third member" named a tuple shape Z10 retired. Each doc rides
  its own item now; the splice probe's inline comment names the arm
  the code actually rides.

SKIPPED (deliberate): the five `from_pin` + `Array::try_from` copies
in `estate.rs` would fold into one helper for ~25 lines - churn on
five proven lanes for zero behavior change (the documented-duplication
precedent). Five files sit exactly at the 600-LOC ceiling (plant.rs,
mod.rs, events.rs, btf.rs, port/events.rs): legal per the gate, split
on next touch, not before.

### 3. Optimization

PEAK (skip, verified): the session's diffs are comment, string
literal, and dead-constant level - codegen-neutral by construction.
The timing sanity confirms it (release build 34.6s; proc 1-2ms,
recent 3ms, doctor 8-9ms across double runs). No hot-path work
invented to justify a diff.

### 4. Security hardening (white hat / kernel hacker mode)

PEAK (skip, verified): the Z9 memfd record-verification door rides
`verify_write.rs`'s hardened scratch creator - the atomic-mkdir +
ownership-check fix from the last audit is SHARED, not duplicated,
so the whole off-path verify family inherits it. The class gate reads
the kernel's own filesystem registry at event time (data, never a
compiled guess). The new infra stays inside the posture:
`codeql-triage.yml` is minimal-permission (actions: read,
security-events: write), fixed-filter, fixed-dismissal-comment, zero
third-party actions (nothing to SHA-pin); the workflow injection
sweep finds only fixed-vocabulary interpolations (`event_name`,
`default_branch`). The secret-shape sweep stays zero.

### 5. LTS stability & the deterministic-output contract

PEAK (skip, verified): the HashMap census across `src/` resolves to
lookups and O(1) indexes whose render order a Vec owns
(`touch/audit.rs` keys by msg_id with a single `get`;
`port/render.rs` documents the index-plus-Vec shape) - no iteration
order reaches a rendered byte. The panic census stays zero (no
unwrap/expect/panic/todo/unimplemented in the production trees). The
Z10 entries render only on material movement (gap past one second, a
regime switch, a skew past the bound) - content-dependent evidence,
not run noise; the determinism certificate still pins what can be
pinned, and the hermetic fixtures do not consult the new surfaces.

### The gates, after

758/758 tests, clippy `-D warnings` clean, `check-all -q` exit 0,
gate-keepers 21/21, and the three fix commits ride one push whose CI
board is watched to green.

### Honest scope

The sweeps targeted the Z-era delta (source, kernel side, infra);
every finding was re-verified against the source before the edit, and
the skip list above is skipped on purpose, not missed. The estate's
own regen lane was honored twice: the two eBPF-tree comment edits
regenerated the prebuilt manifest, and each fix commit carries it
(the one-writer law, in parity per commit).

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
