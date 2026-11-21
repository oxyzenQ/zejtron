<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->

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
pinned by `test/info/clock_tests.rs`. And night-frontier-Z6 (D3,
the sleep blackout) names the dimension Z2 could only imply - WHY a
window is empty: the record stamps ride CLOCK_MONOTONIC, which does
not run while the host sleeps, while the kernel's CLOCK_BOOTTIME
does; their divergence IS the kernel's own suspend accounting, so
the delta of two gap samples across a capture names exactly the
span the host spent asleep inside it - a wall step cannot fake it
(the gap is the difference of two kernel clocks read in one breath,
wall-independent) and an awake host cannot trip it (the materiality
bound is one rendered second). The Unaccounted block renders the
blackout as proof of ABSENCE - "the host spent 14m 12s asleep
inside this capture; no event can exist in that span" - turning the
anti-forensic shape (suspend, manipulate, resume) from an
unexplained hole into named evidence; a pairing that moves
BACKWARDS (a paravirt resync) is named as the anomaly arm instead
of being trusted. The sampling is cross-pinned LIVE on every kernel
the suite runs on (clock_gettime BOOTTIME against /proc/uptime, the
boottime domain's two independent sources); the suspend-class arm's
real-VM seat (ACPI S3 + RTC wakealarm) is named as the unavailability
it is until such a seat exists, and the awake-host negative runs
per push on every root CI leg
(`scripts/netrunner/critical-sim.sh`, the sleep-gap leg). Pinned by
`test/info/clock_tests.rs`, `test/commands/lane_unaccounted_tests.rs`,
`test/commands/port/events_tests.rs`.

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
not own. And night-frontier-Z3 proves the census itself: the
suite's loss-certificate surface floods one tracked window past
the file ring's capacity with a storm the generator counts
OUTSIDE the camera, then asserts the conservation identity -
delivered records + drop_census == ground truth - in all four
directions (delivered beyond truth = fabrication; truth beyond
delivered + drops = silent loss; an overload with a zero census =
a lying census; exact equality over a real overload = the
certificate issues). A census that undercounted would fail the
suite, not the host. The exactness rests on the drain window: the
rolling cap is 8192 - above either ring's whole take - so the render
carries every record the ring held and no cap can hide a census
error (the live runs proved the need: a 4096 cap left a 1365-record
residue a census lie could hide inside). And night-frontier-Z5
counts the camera's own refusals at the question source: a
tracked_inodes insert the kernel refuses for capacity (the map
full, E2BIG) bumps a pinned census slot in the stats map, and the
refusing command's error names the camera, the cumulative count,
and the remedy - the question map obeys the census law like every
bounded resource the camera owns, and the conservation identity
(accepted + refused == attempts) is proven live by the
question-census leg in `scripts/netrunner/critical-sim.sh`: 1024
stale-key fills, two named refusals, the counts read back
consecutive. Pinned by
`test/ebpf/readback_tests.rs`, `test/ebpf/tracked_tests.rs`, the surfaces' builder pins
(`test/commands/lane_tests.rs`, the doctor and port JSON pins), and
the suite self-test's stub-camera matrix
(`scripts/supermassive/selftest.sh` - all seven seats, no kernel
needed).

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
And night-frontier-Z3 freezes the SPAN: five REAL dialects committed
whole under `corpus/btf/` - jammy 5.15.0-25, Debian bookworm's
current 6.1 point release (6.1.0-50), the frozen mainline 6.6.95
build, noble 6.8.0-31, cachyos 7.3.3 (the 7.x line) - extracted by
the committed instrument (`scripts/ci/corpus-extract-dialect.sh`,
one implementation, two seats: the maintainer's capture and the
witness lane's per-push re-digestion), their walk tables pinned slot
by slot WITH the migration history (f_path 16 -> 152 -> 64, three
packings; task_struct.files 2928 -> 3552) and the mainline build's
struct inode outlier pinned too; the pre-BTF 5.4 dialect is pinned
as a named absence the witness lane asserts per push.

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

**14. The verifier-first release doctrine** - and night-depth-
hardening-Z1 deepens it into a REPRODUCIBLE release chain: the
release lane pins the build stamp to the commit timestamp
(SOURCE_DATE_EPOCH, honored by build.rs in ZEJTRON_BUILD_TIME) and
redacts the builder's HOME and checkout path from the embedded path
strings (--remap-path-prefix folds them to `redacted`), so the hash
the release page publishes is the hash ANYONE can rebuild from
source. The standing proof runs per push
(.github/workflows/reproducible-release.yml): two INDEPENDENT
runners, no shared cache, one flag composition, byte identity via
cmp; scripts/release/repro-build.sh re-verifies locally with two
cold builds. The verify recipes and the honest scope live in
[VERIFY_RELEASE.md](VERIFY_RELEASE.md) (section 4a).
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
and `zejtron sig` renders the whole five-depth matrix with the dual
fingerprint row and the honest self-hash note - and since
night-frontier-Z5 the matrix carries D4, the camera object: the
runtime re-hashes the embedded eBPF probe object (the one artifact
that executes at ring 0) against the digest the build stamped over
the same bytes as it staged them (build/ebpf.rs, both lanes), so a
camera patched after the build refuses from the binary alone - the
D3 self-hash needs a published hash to compare against, D4 needs
nothing but itself. The constants come
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
certificate is not a certificate). And night-frontier-Z4 widens the
proof across the kernel span: the witness legs pack the musl
certificate test binary, render the SAME hermetic fixtures on the
BOOTED kernel (focal 5.4 -> cachyos 7.x - no camera, no wall clock,
so the render cannot depend on the host), relay the per-file digests
through the SANDBOX-RENDER sentinel rows, and the cross-dialect
verdict job diffs every leg against the host render - the law holds
cross-dialect, cross-decade, or the run page carries the
mismatching kernel and file by name. The kernel dialect corpus is the
parser lock made concrete: real kernel bytes (five BTF dialects
spanning 5.15 -> 7.x, a real /proc bundle captured one dialect BELOW
the attach floor, the pre-BTF 5.4 dialect pinned as a named
absence), committed whole, digests pinned through the tree's own
blake3, the derived walk tables pinned slot by slot - and the
DIFFERENCE between dialects pinned too, because a corpus that
carried one blob twice would prove nothing. The moving kernels stay
locked live on the witness legs; the corpus freezes the dialects
themselves, and the witness lane re-digests the frozen GA/mainline
packages on every push so the freeze cannot drift from the boots. The
provenance of every file lives in [corpus/README.md](corpus/README.md);
the certificate pins are `test/evidence/certificate_tests.rs` and
`test/ebpf/btf_corpus_tests.rs`, `test/corpus/proc_corpus_tests.rs`.

**17. The camera cost contract** (night-frontier-Z4;
`src/ebpf/cost.rs`, `scripts/supermassive/surfaces/camera-cost.sh`,
[docs/CAMERA-COST.md](CAMERA-COST.md)). The hole: "lightweight" is
a word every tool prints and none can prove. The cost contract
publishes arithmetic instead: the eBPF instruction count per program
(walked from the committed prebuilt object - a pure std ELF64 section
walk, 8 programs at 1092 instructions plus 346 shared, 1438 total),
the kernel-side ring bytes (3 x 256 KiB, scanned from the BPF
SOURCE so a resize moves the sum), and the runtime budgets (attach
<= 2000 ms, userland address space <= 64 MiB enforced with
`ulimit -v`, shipped binary <= 16 MiB) asserted live per push on
every root CI leg. Every derived number is pinned by a test - a
probe that grows, a ring that resizes, or a binary that balloons
fails the suite until the contract is consciously re-pinned in a
commit that says why. Pinned by `test/ebpf/cost_tests.rs`; the
live budgets by the camera-cost surface on the witness kernels.

**18. The actor identity in every record** (night-frontier-Z8, D5;
`src/ebpf/events.rs`, `ebpf/src/identity.rs`, the parse split
`src/ebpf/btf.rs` ([`parse_identity_offsets`]), the attribution
ladders `src/commands/lane.rs` / `src/commands/port/events.rs` /
`src/commands/port/json.rs`, [docs/CAMERA-COST.md](CAMERA-COST.md)).
The hole: the records carried `pid` - a number that answers nothing
on its own. The file rows resolved the actor's NAME through a /proc
round-trip at render time, and a short-lived writer that finished
and died inside the window left the row to the exit ring's mercy;
and no record knew WHERE its actor ran: in a container estate
(kube pods, systemd slices) the question "pid 8123 - who is that,
and from where" had no answer the camera could give. The close: every
`FileEvent` and every `SockEvent` now carries the actor's own
identity block, read by the kernel at event time - the cgroup id
(`bpf_get_current_cgroup_id`, the kernfs inode stat(2) reports for
the cgroup's directory - the number the pod spec names; helper-stable
under the kernel floor, no BTF walk), the comm (`bpf_get_current_comm`,
the ProcExitEvent precedent), and the network-namespace inode (the
ns_common.inum walk `task_struct.nsproxy` -> `nsproxy.net_ns` ->
`net.ns`, the integer /proc's ns/net symlink prints - the identity
lsns names, derived per host at attach and refused by name when a
field is absent - identity is CORE, not an additive capability). The
name the textbook order would guess (`nsproxy.net`) is proven absent
on every real dialect the corpus carries: the member is `net_ns`, and
the independent corpus pass is the reason the guess died before a
host met it. The record grew 40 -> 72 / 32 -> 64 bytes - the cost
contract re-pinned CONSCIOUSLY: the file ring doubled to 512 KiB so
the held-record window GREW under the wider record (6553 held at the
80-byte aya stride versus the 5461 the old contract measured; the
sock ring stays 256 KiB, its filter bounds it to transitions too rare
to need the memory), and the instruction table moved with the inline
identity fill (the whole camera 2165 -> 3416). The render carries the
depth: the raw lane names `comm=`, `cgroup=`, `netns=` per record,
and the attribution ladders gained an arm - a dead actor whose record
names it is attributed from the record itself (zero pid-reuse risk,
no /proc round-trip to outlive the actor), the exit ring only for the
failed-helper-read hole, the JSON lane typing the same story
(`"attribution":"recorded"` - the parity law holds). The legacy head
of both records never renumbers; the vocabulary's append-only law
holds, and the offsets map grew by four slots (18..21) written
EXPLICITLY, never by array position - the night-hunter-3 lesson is
the reason the identity parse rides its own slots. Pinned by
`test/ebpf/file_events_tests.rs` and `test/ebpf/ringbuf_tests.rs`
(the layout pins, every offset), `test/ebpf/btf_corpus_tests.rs`
(the identity chain per REAL dialect - nsproxy marches with the
kernel, net.ns re-packs on the 7.x line, inum 16 -> 88 on cachyos),
`test/ebpf/cost_tests.rs` (the conscious re-pin), and the new
attribution pins in `test/commands/lane_tests.rs`,
`test/commands/port/events_tests.rs`, and
`test/commands/port/json_tests.rs` (the record-comm arm, the
zeroed-comm hole, and the JSON parity).

**19. The off-path write truth** (night-frontier-Z7, D4;
`ebpf/src/offpath.rs`, the record-verification lane
`src/ebpf/verify_offpath.rs`, the anchor ladder
`src/ebpf/btf_offpath.rs`, [docs/EBPF_LIFECYCLE.md](EBPF_LIFECYCLE.md)
section 5). The hole: the Limitations line that stood for eras -
"they do not see mmap'd writes, async kiocb (io_uring/AIO),
splice-class copies" - was THE attacker's map: write a file through
a MAP_SHARED mapping and every kprobe write camera (this one
included) renders silence. The close is three lanes on the camera
the estate already runs, at the cost model no permanent monitor
ships: the kernel's own page-dirty path anchors the mmap truth
(the ladder `filemap_dirty_folio` -> `__set_page_dirty_nobuffers`
is chosen from the host's BTF at attach - the corpus proves BOTH
shapes across 5.15 -> 7.x: the folio-less 5.15 GA vouches the page
anchor, every folio-era dialect vouches the folio one - and the
descent's two hops, page.mapping at 24 and address_space.host at 0,
are the sturdiest walk values in the whole corpus), the splice
truth rides the write probe's own syscall tracepoint with BOTH
descriptors resolved through the fd-table walk (the direction
named: into the file, or the content moving away - the
exfiltration half the write-class records cannot express), and the
io_uring truth rides the submit tracepoint with the request
descended through BTF-walked offsets and the write-class opcode
filter (a tracked file's async READ never renders as a write).
Everything rides the tracked_inodes gate - the cost is bounded by
QUESTIONS, not host activity, the combination no per-syscall
monitor can copy without rebuilding its whole cost story. Every
capability is record-verified at attach (a REAL mmap store, a REAL
splice, a REAL raw-syscall io_uring write must come back through
the probe - the verify_write doctrine carried whole), named in the
attach summary, and a capability the host cannot vouch for is
unplanted and named down: the generation stamp's fourth slot
carries the capability mask, the presence law reads it, and a
named-down capability is never mistaken for a crashed attach. The
vocabulary grows append-only (ops 6-9; the rows name the silent
path: "wrote (mmap (dirty page))", "wrote (splice (into))",
"spliced out", "wrote (io_uring (async))"), the splice-out row is
its own kind, the cost table re-pinned consciously (the shared
text 346 -> 653 - the walks became bpf2bpf subprograms), and the
named residuals stay named: tmpfs/ramfs pages are never clean (an
mmap write to a memory-backed file stays outside the dirty
record), vmsplice's direction is flags-dependent, O_PATH peeks
never reach vfs_open (and the tmpfs/ramfs residual the dirty-record
sentence above names is the one night-frontier-Z9 closes - see
entry 20). Pinned by `test/ebpf/btf_offpath_tests.rs`
(the ladder's decision law, synthetic), `test/ebpf/btf_corpus_tests.rs`
(the off-path chains per real dialect), `test/ebpf/estate_tests.rs`
(the mask verdict), `test/ebpf/cost_tests.rs` (the conscious
re-pin), and the C77 root leg's live windows (a real mmap store and
a real splice inside real why windows, the rows demanded by name).

**20. The memory-backed write truth** (night-frontier-Z9, D6;
`ebpf/src/offpath.rs` (`membacked_fault_probe`), the ladder
`src/ebpf/btf_offpath.rs` (`verify_membacked_lane_in`), the memfd
record-verification door `src/ebpf/verify_offpath.rs`
(`verify_membacked_capability`), the offsets-map slots 22..24,
[docs/CAMERA-COST.md](CAMERA-COST.md)). The hole: the Z7 estate's
own named residual - "tmpfs/ramfs files keep no clean page to dirty,
so an mmap write to a memory-backed file stays outside the record
class" - was still an attacker's map: `memfd_create` secrets,
`/dev/shm` staging, any MAP_SHARED store to a memory-backed file
rendered silence, because the kernel SKIPS the dirty call for
no-writeback mappings and the two dirty anchors never fire there.
The close is the fault path itself, the one mechanism such a store
cannot skip: the shared-write fault funnel is the anchor
(`fault_dirty_shared_page`, arg0 `vm_fault`, on the 5.15-6.8
dialects; the surviving `wp_page_shared` arm on the 7.x line, where
the funnel is inlined past any symbol - the corpus pins the ladder's
verdict per dialect, ONE program serves both shapes), and the
probe's gate is the kernel's own registration table read at event
time: `inode.i_sb.s_type.name` must be `tmpfs` or `ramfs` - data,
never a compiled guess, and the reason a regular file's fault (which
crosses the same anchor) stays silent here while the dirty anchor
records it: one store, one record, whichever class the kernel put
the file in. The walk (vm_fault.page -> page.mapping ->
mapping.host -> the tracked_inodes gate, then the class gate) rides
the three new offsets-map slots 22..24, written explicitly like
every appended tail; the capability is record-verified at attach
with a REAL memfd (two store arms: the fresh-mapping store, and the
read-then-store ride for the write-protection arm), named in the
attach summary, and a host that cannot demonstrate its own record
carries the capability named down - the additive lanes' law. The
named residual narrows honestly: the 7.x line's non-present fault
arm is inlined past any vouchable symbol, so a FIRST store through a
fresh PTE there stays outside the record (the write-protection arm
still sees its faults; the coverage is partial, the corpus pins it,
and the capability plants only where the memfd door proves it).
The vocabulary grows append-only (op 10, the row "wrote (mmap
(memory-backed page))"), the cost contract re-pinned consciously
(one program, 287 instructions, zero new maps, zero new rings; .text
547 -> 583). Pinned by `test/ebpf/btf_corpus_tests.rs` (the ladder's
verdict and the walk chain per REAL dialect), the synthetic ladder
pins in `test/ebpf/btf_offpath_tests.rs`, the layout pins
(`test/ebpf/file_events_tests.rs`, the drift law's slots and names
in `test/ebpf/reverify_tests.rs`, the mask bit in
`test/ebpf/estate_tests.rs`, the conscious re-pin in
`test/ebpf/cost_tests.rs`), and the C77 root leg's live memfd window
(the row demanded by name where the capability proved itself, the
named-down direction asserted where it did not).

**21. The watch truth - the absence triad completes** (night-
frontier-Z10, D7; the generation map's fifth slot
`src/ebpf/estate.rs` ([`GEN_SLOT_ATTACHED_MONOTONIC`],
[`attach_facts`]), the pre-breath struct `src/ebpf/fileprobe.rs`
([`PreBreath`]), the materiality and the reader `src/info/clock.rs`
([`material_watch_gap_ns`], [`current_clocksource`]), the builders
`src/commands/lane_unaccounted.rs`, the drain wiring
`src/commands/lane.rs` ([`collect_live`])). The hole the triad's
first two legs left: the drains name the kernel's absences (the
drop census, Z1 - events the kernel saw but could not hold) and
the host's (the sleep blackout, Z6 - spans the stamps' clock did
not run through), but not the WATCHER's own - `why /x --since 30m`
on a camera planted two minutes ago read 28 minutes of silence
with every banner honest, because the one thing that can prove
"no event can exist there" is the attach instant, and nothing
compared it. The close is one compare in the stamps' own domain:
the generation map grows its fifth slot (append-only, the Z2 law)
carrying the attach instant in CLOCK_MONOTONIC nanoseconds - the
same clock the records stamp with, so the compare is
wall-independent (an NTP step can never invent a gap, a wall step
can never hide one) - and the capture's pre-breath grew from the
Z2 tuple to the `PreBreath` struct (four readings of one instant:
wall offset, sleep gap, monotonic stamp, clocksource regime). The
materiality bound is the one-second order (a sub-second edge is
the command's own startup cost), so a window fully inside the
camera's life adds NOTHING - the negative test pins the byte
silence - and a pre-Z10 estate (no monotonic slot) degrades to a
verbose trace, never a guessed gap. The detach-symmetric shape is
inherently named: a window that outlives the camera cannot drain
(the pins are gone), and the refusal IS the name. With this leg
the triad reads as one sentence no monitor vendor publishes:
**drop truth + sleep truth + watch truth = no silent absence** -
every span the render cannot account for is carried as evidence,
never as a hole.

**22. Clocksource regime honesty** (night-frontier-Z10, D7, the
same era; `src/info/clock.rs` [`current_clocksource`], the
`PreBreath` struct's fourth reading, the builder
`src/commands/lane_unaccounted.rs`
[`clocksource_switch_entry`]). Not one byte in the tree touched
the clocksource before this - and the stamps' precision is
delivered by the kernel's active clocksource (`tsc` vs
`hpet`/`acpi_pm`), which the watchdog can switch MID-CAPTURE (the
tsc-unstable fallback). The two-breath pairing the estate already
runs (wall offset Z2, boottime gap Z6) grew its third reading:
the regime at the window's open, re-read at render. A
demonstrable switch renders as an Unaccounted row ("the kernel's
clocksource switched across this capture (tsc -> hpet) - the
stamps stay one CLOCK_MONOTONIC domain, but the precision regime
the durations ride changed under the window"); a steady regime
adds nothing. Pure honesty, zero surface, one family with Z2/Z6.

**23. The reproducible release chain** (night-depth-hardening-Z1,
the cosmostrix D4 lineage; `.github/workflows/reproducible-release.yml`,
`scripts/release/repro-build.sh`, `build.rs`,
[VERIFY_RELEASE.md](VERIFY_RELEASE.md) section 4a). The hole: a
published hash proves an artifact is UNMODIFIED SINCE PUBLICATION -
it proves nothing about what the build process was; a modified
build (a tampered toolchain, a patched dependency, a flag drift)
ships a perfectly self-consistent hash of the wrong bytes. The
chain pins PROCESS identity: two independent CI runners build the
release shape from the same commit - same pinned toolchain (the
repo's rust-toolchain.toml and the nested eBPF nightly), same
SOURCE_DATE_EPOCH (the commit timestamp, honored by the build stamp),
same flag composition (the release matrix's own, plus the redacted
path prefixes), NO shared cache - and the verify job fails unless
the two artifacts are byte-identical (cmp). A rebuild on any machine
rides the same recipe (scripts/release/repro-build.sh, two cold
builds, one command), and the local proof has passed: two cold
builds byte-identical, the nested eBPF object included. Zero new
CLI surface: the knobs are build-time environment and CI; the
parity gate's -C token law is untouched (the redaction rides
--remap-path-prefix, not a -C token).

**24. The lazy loading helix** (night-ux-orion-1;
`src/output/spinner.rs`, wired into `src/update/mod.rs`). The hole:
an indeterminate wait and a hang were indistinguishable - the
update fetch blocks up to its 15 s curl ceiling with a silent
terminal, and the Ctrl+C a frozen-looking terminal invites is a bug
of perception. The close: a loading lane whose first frame lands
only after the operation crosses 100 ms (a fast path never draws -
silence stays byte-for-byte), then shows the DNA helix, two braille
strands running the same ten-frame sweep in opposite directions -
`HELIX[i]` pairs the sweep's `i`-th cell with its `(9-i)`-th, the
strands never collide because `i = 9 - i` has no integer answer,
and the two anti-parallel streams are the fetch itself: the request
out, the answer back. The fallbacks are detection, never flags: a
NO_COLOR terminal or a non-UTF-8 locale drops automatically to the
rotating ASCII dash (`- \ | /`), the paint rides the grammar-tier
grey ladder (bright black on Color16, the theme's own grey), the
line shares the countdown's bracket grammar and \r clear contract,
and a piped stderr stays silent - all pinned pure (frame tables,
style ladder, lazy slot clock) in `test/output/spinner_tests.rs`.
Zero new dependencies: std threads, two AtomicBools (the stop flag
and the drawn flag the clear rides), and tables of literals. Pinned
by `test/output/spinner_tests.rs` (the counter-phase table, the
style ladder's truth table, the lazy clock's 99/100/199/200 ms
boundaries).

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
