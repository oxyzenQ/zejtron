<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# zejtron LTS Fortress Audit (night-last-total-lts)

The final pre-release fortress audit before the v80.0.0 tag, run at
commit `1261e58` on the `main` line. The mission's own law governs
this document: a sub-task already at its peak is NOT changed - the
finding is recorded here with the reason it is at peak, and nothing
is invented to justify a diff. The audit landed exactly one artifact:
this document. Zero source changes, zero CI changes, zero version
changes - the version stays the owner's call.

## Method and its honest limits

Every finding below names HOW it was verified, because a claim
without its verifier is noise:

- **read**: the code path was read line by line in this audit.
- **local gate**: executed on the audit container
  (`scripts/gate-keepers.sh`: 20 passed, 0 failed, including the
  shell quad, the permissions parity at 644/755, codespell, the
  emoji sweep, the language gate, and the name-case law).
- **CI**: executed by the workflows on this push family - the
  Dragon Guard Miri workflow, the 480-test cargo run inside
  `build.sh check-all -q`, and the supermassive legs. The audit
  container carries no Rust toolchain by the project's own
  machine-time law (heavy builds belong to CI), so miri and the
  full suite verify through CI, which is green at `1261e58`
  (13 of 13 workflows).

## Phase 1 - the sharpest skill (core Rust and eBPF)

### 1.1 Stability and crash

**Miri** - verified by CI. The Dragon Guard Miri workflow (five
pure-Rust families) is green at the audited commit. A local miri run
was skipped for the documented reason above; CI is the project's
standing verifier for UB and it passes.

**The custom JSON serializer** (`src/evidence/json.rs`) - **already
at PEAK**. Verified by read plus its unit tests:

- `write_string` names every JSON escape the grammar knows: quote
  and backslash take their two-character forms, `\b` `\f` `\n` `\r`
  `\t` take the named forms, and the catch-all arm sends every
  remaining scalar below 0x20 - including NUL (`\u0000`) - through
  `\u00xx`. All other scalars (the whole UTF-8 range) pass through,
  which is what RFC 8259 requires. A malformed or hostile filename
  cannot break the envelope.
- The unit test `escapes_quotes_backslashes_and_control_bytes` pins
  the quote, backslash, newline, tab, `\u{01}`, and `\u{0c}` forms;
  a second test pins the UTF-8 pass-through. The mission's injection
  trio (`"`, `\n`, `\u0000`) is covered by the first two arms and
  the catch-all the `\u{01}` case already rides.
- The plumbing is honest: the user-supplied subject path rides
  `write_string` at the report head, and every row's dynamic string
  fields ride the same helper. The only literal quote pushes outside
  the helper are fixed enum tokens (`"not-attached"`, `"drain-failed"`)
  that carry no user bytes. Every JSON emitter in the tree (evidence,
  doctor, net, port, recent, path, proc) uses the shared writer -
  no serializer hand-rolls its own escaping.

**`unwrap()` and `expect()` in production paths** - **already at
PEAK: the census is zero**. A direct sweep of the whole `src/` tree
returns no `.unwrap()` and no `.expect(` anywhere - production and
test files alike. The error ladder carries every fallible step; the
one `expect` in build tooling (`CARGO_MANIFEST_DIR` in
`build/ebpf.rs`) is cargo's own guarantee, not runtime input. The
two `unreachable!` sites (`src/commands/doctor/symptom.rs`) sit
behind the `KNOWN` vocabulary gate that validates the symptom string
before both match arms - an internal invariant, unreachable from
malformed `/proc` data.

### 1.2 Code hygiene

- `TODO` / `FIXME` / `todo!` / `unimplemented!`: zero hits in `src/`.
- `panic!`: zero hits in production files.
- `#[allow(dead_code)]`: fifteen sites in `src/ebpf/events.rs`, four
  elsewhere - every one is a documented, deliberate retention, not
  stale code:
  - The `events.rs` sites are the eBPF record-contract constants
    (op vocabulary, BTF offset slots). The same file compiles on
    both sides of the kernel boundary; the eBPF side reads what the
    host side does not name. The scoped allows name exactly that
    split, and the vocabulary "renumbers never" - removing them
    would break the record contract, not clean it.
  - `src/system/pathguard.rs` carries a module-level allow over a
    lexical path normalizer retained without a production caller -
    a retention already audited twice (night-improve-0, restated by
    the night-total-lts-3 audit) with tests keeping the primitive
    honest while it waits.
  - The `Mode::Mixed` and `Provenance::Unaccounted` variants hold
    reserved seats of the evidence grammar so a later pass cannot
    invent a fifth - the scoped allow is the honest count.

### 1.3 Optimization (hot path)

**`src/ebpf/ringbuf.rs`** - **already at PEAK**. The night-dragon-1
shape is already the optimized one: a drain collects its batch
first (bounded by the ring's own 256 KiB capacity), and
`extend_rolling` applies the 4096-record rolling cap with at most
two memmoves per drain - the per-record `Vec::remove(0)` front
shift is gone from production (the per-event `push_rolling` form
survives test-only, with a correctly scoped allow). No `.clone()`
and no per-record `String` allocation exists on any drain path;
the only `format!` calls sit on the one-shot map-open error path.

**`src/commands/port/window.rs`** - **already at PEAK**. The
collect loop is drain, deadline check, bounded sleep - no
allocation per event. Owner names resolve once at render time with
a graceful `.ok()?` for vanished processes. The duration parser
saturates (`night-total-lts-1`), so an absurd `--since` cannot
wrap into the window; the clamp law holds the [1s, 1h] shape. The
clock is monotonic end to end (`bpf_ktime_get_ns` records against
`/proc/uptime`), so no wall-clock drift enters the window.

### 1.4 Security (kernel hacker mode)

**Path traversal through `zejtron why`** - **no boundary exists to
attack, by design, and that is the honest answer**. The command
resolves the user path with `fs::metadata` at the caller's own
privilege: the binary never elevates, never reads file contents,
and touches only metadata, `/proc` holders, and the eBPF event
rings. `zejtron why ../../../../etc/shadow` does exactly what
`stat /etc/shadow` does for the same user - no privilege crosses.
The `sudo` in the docs is the operator choosing their own
privilege, which no traversal can widen. Canonicalization is used
only as a lookup refinement with a graceful fallback
(`unwrap_or_else(|_| path.to_path_buf())`), so symlink loops and
vanished paths degrade instead of crashing. The lexical normalizer
that WOULD jail a path already exists in
`src/system/pathguard.rs`, retained and tested for the future
sandboxed lane that will need it.

**eBPF verifier safety** - **already at PEAK**. All kernel reads
funnel through three helpers (`read_u64_at`, `read_u32_at`,
`read_ptr_at`), each a `bpf_probe_read_kernel` wrapped in an
`Option` - a bad address returns `None` instead of faulting. The
offsets come from the pinned `offsets` map, written only by the
privileged attach from live BTF, never from event data - an
attacker controls none of the address arithmetic. No unbounded
loops exist on the BPF side.

**Ring-buffer flood to OOM** - **bounded, verified**. A flood
cannot exceed the ring's own 256 KiB per drain (the kernel holds
no more than the map's capacity); the consumers validate
`record.len()` against the pinned record size before the one
unsafe `read_unaligned` (a short record is skipped, never failed),
and `extend_rolling` caps the window at 4096 records regardless of
flood duration or wait length. The CLI cannot grow past a window-
shaped bound.

## Phase 2 - the fortress infra (CI, scripts, build)

### 2.1 Stability and crash

**`set -Eeuo pipefail` coverage** - the census lands at 25 of 50
tracked shell files with the full flag set, and the split is
architectural, not accidental:

- The supermassive harness enforces the flags at exactly one point
  (`supermassive.sh` line 43) and the sourced library (`lib.sh`)
  plus every surface inherit them. A sourced file setting its own
  flags would mutate the caller's shell - the one-enforcement-point
  shape is the correct one for a sourced library.
- The standalone runners (`zejtron-qc.sh`, `scale-audit.sh`,
  `uninstall.sh`, `sandbox-init.sh`) run `-u` without `-e` on
  purpose: they count failures and print summaries; `-e` would
  abort on the first red check and destroy the very report they
  exist to produce. `scale-audit.sh` documents its fork-pressure
  clock design beside the flag.

**`simulation.sh` teardown races** - **already at PEAK**. The
teardown hand is TERM, a grace beat, KILL, then a bare wait that
reaps every child; the killed-mid-write case is named in the
code (a killed loop never writes a count that gets trusted), the
stderr silence precedes the log open, and the runner-level
post-leg cleanup guarantee (night-dragon-4) counts zombies and
strays and FAILS the surface if any survive - the race
consequence is detected, not assumed away. Empirically: green on
the owner-host runs and on the CI legs.

**gate-keepers on `zejtron-qc.sh`** - resolved in this session
before this audit: commit `1261e58` brought the file under the
repo's gates, and the wholesale run now passes 20/20 locally and
green in CI. No residual.

### 2.2 Code hygiene

**Workflow audit** - the action SHAs are pinned and enforced by
the repo's own freshness gate (section 17, human-decision SKIPs
excepted by design); the cache keys carry the toolchain and the
job shape (`supermassive-1.98.1--supermassive-Linux-x64`); no
duplicated logic rises to the level of a refactor this close to a
tag - the repeated toolchain-setup steps are standard Actions
composition, and a reusable-workflow refactor before an LTS
release is risk with zero binary gain. Deliberately not changed.

**Stale comments** - `build.rs`, `build/ebpf.rs`, `Cargo.toml`,
and `.cargo/config.toml` were read end to end. Every comment cites
a mechanism that exists in the tree (the prebuilt lane, the
saturating window parser, the ring reader's batch shape, the
SIGPIPE law, the musl-only libc rule). Nothing stale found -
nothing removed for removal's sake. The version string stays
`80.0.0-rc.3` untouched; the tag is the owner's call.

### 2.3 Optimization

**`build.rs` eBPF recompilation** - **already at PEAK**. The eBPF
lane emits `cargo:rerun-if-changed` per tracked file under `ebpf/`
plus the `ebpf-prebuilt/` directory, and deliberately does not
watch the nested `ebpf/target` (the nested cargo owns it). The
object recompiles only when its inputs change; unrelated Rust
edits do not pay the nightly cross-compile.

**`check-all` runtime** - measured on CI: the quiet check-all
step inside the CI job completes in about 49 seconds (toolchain
restore to verdict), comfortably under the two-minute law.

### 2.4 Security (white hat)

**CI secrets** - **clean**. Every secret rides an `env:` block
(`secrets.GPG_PRIVATE_KEY`, `secrets.GPG_PASSPHRASE`,
`secrets.GITHUB_TOKEN`, `secrets.CRATES_IO_TOKEN`); none is ever
echoed, interpolated into a `run:` string, or written to a log.
The publish workflow fails closed with a named error when the
registry token is absent. A repo-wide sweep for literal token
shapes (`ghp_`, `github_pat_`, `gho_`, AWS access keys) returns
zero hits in tracked files.

**Shell injection in the harness** - **clean**. `supermassive.sh`,
`lib.sh`, and the surfaces contain no `eval` and no string-built
shell: invocations pass through array positionals (`"$@"`), and
the runner sanitizes the child environment entirely (`env -i`
with an explicit allowlist - the binary sees only PATH, HOME,
TMPDIR, LC_ALL, LANG). The two `bash -c` sites in the tree are
both safe by construction: the sandbox payload quotes every
argument with `printf %q` ("no eval, no shell parsing"), and the
scale audit's `setsid bash -c` body is a static single-quoted
literal fed by positional parameters.

### 2.5 LTS stability

**Time-bombs** - none. The date literals in the test tree are
inert parse fixtures (a fixed input parsed to a fixed expected
output, no `now` comparison). The one wall-clock test
(`fileprobe_tests.rs`, "within 2s of the wall clock") is a
deliberate monotonic-to-UTC conversion contract between two reads
microseconds apart, with no calendar arithmetic to trip on a date
boundary. The window grammar's overflow time-bomb was already
defused by `night-total-lts-1` (saturating multiply).

**eBPF prebuilt manifest parity** - verified live in this audit:
`scripts/dev/regenerate-ebpf-prebuilt.sh --check` reports "in
sync: manifest pins match the ebpf/ tree, the staged copy, the
toolchain pin, and the version mirror". The commit gate re-checks
the same verdict on every commit.

## The verdict

Every sub-task the mission named is already at its peak, guarded
by a verifier that proves it: the escaper by unit tests, the ring
consumer by its own bound proofs, the overflow by the saturating
parser, the teardown by its named zombie law, the manifest by the
b3sum parity check, the gates by the 20/20 wholesale run, and the
whole binary by the 480-test CI run inside a 49-second check-all,
miri, and the supermassive legs - all green at the audited commit.
The fortress asked for one artifact: this document. The dragon
flies with zero diffs.
