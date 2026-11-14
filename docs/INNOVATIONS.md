<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# The zejtron Innovation Ledger

This page records the mechanisms that define zejtron's investigative
core. It is written simple on purpose, so a new maintainer (or a
curious competitor) can learn the whole engine in one sitting. Each
entry names the problem it kills, the mechanism in one breath, the
file where the truth lives, and the proof that pins it. The canonical
version-by-version history is `CHANGELOG.md`; this page is the map,
not the ledger - facts told here link to their canonical home and
are never restated into drift.

One law runs through everything below: **read-only, kernel-truth,
refusal-with-a-name.** zejtron never writes, never guesses, and
never fakes: every row carries exactly one provenance tier
(`[observed]`, `[measured]`, `[inferred]`, `[unaccounted]`), every
degraded lane names itself, and a mechanism that cannot verify
against the host refuses by name instead of planting a hope. The
one-surface expression of the law is the Evidence Ledger; the
one-kernel expression is the Lazy Camera.

## The estate, in dependency order

**1. The Evidence Ledger** (`src/evidence/` - `row.rs`, `render.rs`,
`json.rs`). The hole: an investigation fragments across five tools
speaking five dialects, none deterministic. The ledger is the one
grammar: a subject, a mode line, an Evidence block, an Unaccounted
block, a two-line verdict - every row carrying exactly one
provenance tag, the tag being the truth about the source. The render
shape is locked and byte-deterministic; piped output carries zero
escape bytes; timestamps render UTC by the civil clock only. The
typed JSON lane (`--print-json`, `ledger_version: 4`) hand-writes
its serializer to keep the runtime graph at three crates. The
canonical spec (the block grammar, the tier definitions, the frozen
v3) lives in [EVIDENCE-LEDGER.md](EVIDENCE-LEDGER.md); the four-tier
law is pinned by `test/evidence/`. And the report's civil times are
honest down to the sample they came from (night-frontier-Z2): every
row renders under the ONE wall offset the renderer sampled at its
start (two rows can never disagree because an NTP step fell between
their reads), and the offset the capture started with is re-read at
render time - a wall clock that moved more than half a rendered
second across the capture is NAMED in the Unaccounted block, the
signed movement beside the rows' exposure, instead of riding the
rendered times silently. The bound and the compare are pure and
pinned by `test/info/clock_tests.rs`.

**2. The Lazy Camera** (`src/ebpf/plant.rs`, `loader.rs`,
`ringbuf.rs`, `events.rs`). The hole: forensics tools either run an
always-on userland agent (Sysdig, Datadog) or miss the event. The
camera is planted on the operator's command (`doctor --attach`):
programs and links pin under `/sys/fs/bpf/zejtron`, the kernel
records into bounded rings, nothing streams to userspace, and the
CLI wakes only to drain the window it was asked for, then exits.
Attach is a one-shot that may exit; the pins keep the camera alive.
`--detach` sweeps the whole pin estate, legacy and foreign entries
included - no manual `rm` is ever needed. And the camera's own
footprint is honest: the watcher's self-exits are facts about the
observer, counted beside the evidence (`observer_excluded`), never
laundered into the host's record. The doctrine (why none of
it is monitoring) lives in [EBPF_LIFECYCLE.md](EBPF_LIFECYCLE.md);
the lifecycle is pinned by `test/ebpf/loader_tests.rs` and
`test/ebpf/ringbuf_tests.rs`. And the camera proves it is
who it says it is (night-frontier-Z2, the generation stamp): the
estate stamps its boot identity, its probe object identity, and the
attach instant into a pinned `generation` map at attach, and every
recording boundary re-derives the live facts and compares - a
foreign boot or a foreign build refuses by name with the remedy.
And the camera's own failures are honest (night-frontier-Z1, the
drop truth): a full ring's failed
reservation is counted - one `drop_census` slot per ring, bumped
in-kernel at the exact failure, read back through its pin - and the
draining surface's Unaccounted block names how many events the
kernel saw but could not hold. The kernel cannot remember what it
did not record; counting the failures is the honesty the kernel
itself allows, and it is the last silent boundary the ledger does
not own. Pinned by `test/ebpf/readback_tests.rs` and the surfaces'
builder pins (`test/commands/lane_tests.rs`, the doctor and port
JSON pins).

**3. BTF-verified attach** (`src/ebpf/btf.rs`, `btf_writev.rs`,
`verify_write.rs`, `readback.rs`). The hole: a kprobe's struct
offsets are compiled at build time, but the host's kernel moved
them - and 6.18 wraps members in anonymous unions besides. The
answer is data, not code: every struct offset, the fd-walk positions,
and the vectorized-write symbol are verified against the host's own
vmlinux BTF at attach, descending the anonymous aggregates modern
kernels use, and the verified offsets are written whole into the
offsets map. The write probe verifies itself before planting; a
shape that cannot be verified refuses at attach, by name, before
anything is planted - the refusal echoes what it checked. night-frontier-Z1 closes the
verification loop around the recording boundary: the file ring's
drain re-derives the planted walk table - all fifteen offsets-map
slots, the two BTF-derived anchors included - from the host's
CURRENT vmlinux BTF before one record is trusted, refusing by slot,
planted value beside the current word (`src/ebpf/reverify.rs`).
Only the file ring is gated, and that is the honesty: the sock
probe's records ride verified tracepoint-context constants and the
exit probe's ride helpers alone, so a drift cannot corrupt them -
a refusal on records it cannot corrupt would be a refusal that
lies. night-frontier-Z2 freezes the
range itself: the .BTF sections of two REAL GA kernels (the floor's
jammy 5.15.0-25 and noble 6.8.0-31) are committed whole under
`corpus/btf/` and their derived walk tables are pinned slot by slot
- including the disagreement (f_path 16 -> 152, f_inode 32 -> 168,
task_struct.files 2928 -> 3080), so a parser change that would
misread either dialect fails the suite on every host, forever.
Pinned by `test/ebpf/btf_tests.rs`,
`test/ebpf/btf_flatten_tests.rs`, `test/ebpf/reverify_tests.rs`,
`test/ebpf/btf_corpus_tests.rs`, `test/ebpf/readback_tests.rs`.

**4. The unlink/rename forensic pair** (night-frontier-2;
`src/ebpf/btf_unlink.rs`, `ebpf/src/unlink.rs`). The ledger's oldest
named hole: "who deleted this file?" - the README's Limitations
carried "does not see unlink events" for eras because the
`vfs_unlink` signature churned across the kernel floor (the dentry
moved from arg1 to arg2 in 5.12) and a kprobe argument position is
compiled, so no single compiled position served the range. The
answer is per-host data: a BTF parameter scan derives the dentry
argument index at attach (2 on the idmap+ kernels, 1 before them),
and `vfs_rename`'s `old_dentry` member offset resolves through the
same anonymous-aggregate descent. One unlink(2) renders exactly one
`unlinked` row and drains exactly one `op=unlink` record; one
rename(2) the renamed twin (the record carries who acted, not the
new name - stated, not hidden). The rings are gated by the
`tracked_inodes` filter - only inodes an operator asked about enter
the record, so the camera's cost stays bounded by the questions,
not by the host's file activity. Pinned by `test/ebpf/btf_unlink_tests.rs`;
hostile input is a fuzz surface (`fuzz/fuzz_targets/btf_parser.rs`,
night-frontier-3, with the committed seeds driven through the real
verifiers by unit test). Live proof, one command:
`sudo scripts/labs-exp/zejtron-forensic-proof.sh`; CI proof:
`scripts/netrunner/critical-sim.sh` on the floor VM
(night-verify-1).

**5. The anchor identity law** (`src/commands/why/ledger.rs`). The
hole: the watched path can vanish mid-scan - the very event the
operator is investigating deletes the subject. The walk rides the
anchor's identity, the inode the scan started on: a path that
vanished or was replaced still answers for that inode, its
deleted-but-open holders stay visible, and the split is named in the
Unaccounted block (`the path vanished during the scan`) instead of
corrupting the report.

**6. The lane ladder** (`src/commands/lane.rs`). The hole: an event
window on a host where the kernel lane cannot run would either lie
or crash. The ladder degrades honestly: live (the kernel lane
watched) to journal fallback (the log lane answers) to snapshot
(metadata only), every degradation named in the report's `Mode:`
banner with the reason - `Mode: live`, `Mode: snapshot (journal
fallback)` - so a degraded window always introduces itself. The
ladder is pinned by `test/ebpf/lane_tests.rs`.

**7. The UX bridge** (`src/cli/ux.rs`). The hole: a forensic CLI
must answer muscle memory, not punish it - typos, case-variant
spelling (`zejtron PORT`), retired verb names (`whoholds`,
`whyopen`), and hostile argv bytes all reach the parser. The bridge
runs four enrichers in a fixed order over clap's error (unknown-arg
suggestion, removed-subcommand redirect, subcommand-flag redirect,
the case-insensitive fallback that fires only where clap was
silent), shares one `jaro_ci` matcher between the flag and
subcommand lanes so the two cannot drift, collects argv lossy so
non-UTF-8 bytes render the usage error instead of a panic, and
enforces the one-tip contract (a rescued error carries exactly one
tip - clap's own survives, the fallback never doubles) and the
exit-code law (help 0, usage error 2, runtime 1). Pinned by
`test/cli/ux_tests.rs`; live proof, one command:
`sudo scripts/labs-exp/zejtron-cli-ux-verify.sh`.

**8. Pro mode** (`src/cli/pro_mode.rs`, `src/cli/examples.rs`). The
hole: flags scattered across per-verb help pages, aliases hidden.
One `--help` carries the complete options estate grouped by the verb
that owns it, every alias disclosed, every verb closing with its
example rows - and coverage tests fail the build if a flag, an
alias, or a verb escapes the surface (the pro-mode estate is
exhaustive by construction, not by discipline). Pinned by
`test/cli/cli_tests.rs` and `test/cli/examples_tests.rs`.

**9. The dependency & wrapper doctrine** (`deny.toml`, `src/info/clock.rs`,
`src/evidence/json.rs`, `src/system/`). The hole: forensic tools
that carry LLVM, Lua, or a framework, and wrappers that shell out to
the tools they claim to replace. The runtime graph is exactly three
crates - `clap`, `aya`, `libc` - with `serde` banned outright,
`chrono` replaced by Howard Hinnant's `civil_from_days` on
`std::time` only (no timezone database, no local guesses in
containers), and no regex crate at any size (the pattern filter is
std-only substring matching). And the nine surfaces read `/proc`
and `/sys` directly - delete `ss`, `lsof`, and `ps` from the system
and zejtron still answers byte for byte; the external-binary census
is short (`curl`, `journalctl`, `dpkg`/`rpm`/`apk`, `uname`), every
entry an optional lane that degrades honestly when absent - the Arch
pacman database is read straight from `/var/lib/pacman`. The full
justification ledger and the rules going forward
live in [DEPENDENCY_AUDIT.md](DEPENDENCY_AUDIT.md); the ban lane
runs in CI (`cargo-deny`, `cargo-audit`).

**10. The doctor's symptom estate** (`src/commands/doctor/`). The
hole: "the machine is slow" needs four tools sampling four windows
at four moments. The doctor reads readiness and symptoms in one
grammar: the `ram`, `cpu`, `disk`, `network`, and `gpu` lanes, and
the `slow` umbrella composing the cpu, disk, memory, and network
lanes over ONE shared 1.0-second window (one sleep, simultaneous
evidence) plus the swap rate, ranked into one severity-ordered
answer. The ram lane drains a 5-second exit ring when the camera is
attached. Lanes are snapshots, never monitors - stated in the
README's Limitations, not fixed in code.

**11. Root-honest surfaces** (`src/update/`). The hole: tools that
reach the network as root silently. `--check-update` - the one
network surface in the binary - refuses sudo by name before any
network I/O, and tag verification is fail-closed. The refusal is a
feature: a read-only investigator must never let a version check
become the incident.

**12. The kernel matrix, two seats** (night-frontier-4;
`scripts/sandbox/kernel-matrix.sh`, `.github/workflows/supermassive-kernel-witnesses.yml`).
The hole: kernel-shape drift is discovered by a user's bug report.
Four witnesses burn per push - focal 5.4.0 below the floor, jammy
5.15.0 at it, noble 6.8.0 above it, cachyos as the moving-latest
witness (the line that caught the 6.18 anonymous union live) - and
the same ladder runs on the operator's own box through the same
sandbox code path, one command, one verdict table. One
implementation, two seats: the local instrument cannot drift from
what CI proves, and the witnesses lane's 5-minute budgets stay the
only CI burn.

**13. The supermassive estate** (`.github/workflows/supermassive*.yml`,
`.github/workflows/netrunner-night-c77.yml`,
`scripts/netrunner/critical-sim.sh`). The hole: a claim that only
the release notes verify. Every lane proves the whole estate end to
end - the e2e legs (MSRV floor and stable frontier), the container
leg, the alpine musl smoke proof, the kernel floor micro-VM on the
exact jammy GA 5.15.0-25 kernel the floor documents, and
netrunner-night-C77, which runs the whole tool as a forensic
instrument under both identities: the root leg attaches the live
chain and proves the forensic pair for real; the non-root leg
asserts the refusal direction - the attach MUST refuse, naming its
reason, never faking a success. How the estate is shaped and why
lives in [workflow/about-ci.md](workflow/about-ci.md).

**14. The verifier-first release doctrine**
(`scripts/package/install-on-my-machine.sh`, `ebpf-prebuilt/manifest.toml`,
`docs/VERIFY_RELEASE.md`). The hole: shipping shapes nobody tested.
x86-64 only ships exactly what the Supermassive E2E suite proves on
real hardware (the verifier-first doctrine; other architectures
build from source by the same rule), the release matrix ships two
fully static musl shapes (x86-64-v3, v4) with SHA-512, BLAKE3,
SHAKE256, and a GPG signature each, and the registry lane carries
the maintainer-built eBPF object so a `cargo install` target needs
no nightly and no bpf-linker. The pre-LTS real-usage audit
([REAL_USAGE_AUDIT.md](REAL_USAGE_AUDIT.md)) drove the release
binary end to end - every verb, every JSON lane strict-parsed, the
degradation lanes below the eBPF floor, a 400-run stability loop -
before the freeze was declared.

**15. The depth-matrix signature** (night-signature-1, the masked
night-signature-advanced-1 scheme; `src/info/provenance.rs`,
`src/info/signature.rs`, `src/commands/sig.rs`,
`scripts/release/generate-provenance-words.py`,
`docs/VERIFY_RELEASE.md`). The hole: identity claims that only the
license files carry can be copied verbatim by a thief, and a rebuilt
or hacked binary claims whatever its `-V` report says - worse, a
plaintext claim inside the artifact hands the thief the exact grep
target to strip. The answer is the masked provenance scheme: the
ownership claim exists in the binary ONLY as opaque XOR-masked
64-bit words (a splitmix64 stream over two independent layers - the
identity manifest and the Copyright authors), no printable run of
four bytes survives anywhere in `.rodata`, and `strings | grep
rezky` finds nothing. The claim materializes to plaintext only at
runtime: one unmask pass per render feeds both the display and the
integrity fold (the single-pass invariant), the words pass through
`std::hint::black_box` so LLVM cannot fold the recompute back into
the constants, and three verifications must all hold - the FNV-1a 64
fingerprints (const-evaluated at compile time, `fp=` on the status
line), the identity binding between the two layers, and the BLAKE3
anchor over the framed payload (the estate's own std-only BLAKE3,
zero new dependencies). `-V` carries the status line
(`Depth-matrix: fp=... status=verified anchor=b3:... layers=...`, the
report's green provenance seat on a terminal, plain bytes in a pipe)
and `zejtron sig` renders the whole four-depth matrix with the dual
fingerprint row and the honest self-hash note. The constants come
from the generator script - the committed truth source, carrying the
identity once the way NOTICE does. The verify recipes and the honest
limits (what AUTHENTIC proves and what only the pinned D3 hash
proves) live in [VERIFY_RELEASE.md](VERIFY_RELEASE.md).

**16. The proof rig** (night-frontier-Z2;
`test/evidence/certificate_tests.rs`,
`scripts/ci/determinism-certificate.sh`, `corpus/`). The hole: the
deep laws - "two conformant runs diff to empty", "the parsers read
every kernel dialect we promise" - are claims a competitor can copy
into their own README as words. The proof rig turns the claims into
verified artifacts a buyer can audit. The determinism certificate
renders three canonical fixtures (the full Evidence Ledger grammar,
the doctor's ram report, the port event section) in TWO INDEPENDENT
cargo test invocations on every push, diffs the two directories,
and issues the certificate only when the diff is empty - the digest
and the commit ride the artifact; hermeticity is the fixtures' own
law (every camera consultation enters as an explicit None, every
civil time renders only where the shape names it absent - a flaky
certificate is not a certificate). The kernel dialect corpus is the
parser lock made concrete: real kernel bytes (two GA BTF blobs, a
real /proc bundle captured one dialect BELOW the attach floor),
committed whole, digests pinned through the tree's own blake3, the
derived walk tables pinned slot by slot - and the DIFFERENCE
between dialects pinned too, because a corpus that carried one blob
twice would prove nothing. The moving kernels stay locked live on
the witness legs; the corpus freezes the dialects themselves. The
provenance of every file lives in [corpus/README.md](corpus/README.md);
the certificate pins are `test/evidence/certificate_tests.rs` and
`test/ebpf/btf_corpus_tests.rs`, `test/corpus/proc_corpus_tests.rs`.

## How a newcomer reads this tree

This page for the shape, [EVIDENCE-LEDGER.md](EVIDENCE-LEDGER.md)
for the output contract, [EBPF_LIFECYCLE.md](EBPF_LIFECYCLE.md) for
the kernel lane, [docs/RULES.md](RULES.md) for the laws a change
lands under, [workflow/about-ci.md](workflow/about-ci.md) for the
proof estate, and `CHANGELOG.md` for what changed when. The labs the
owner runs before closing an era live in `scripts/labs-exp/`.

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
