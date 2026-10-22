# Changelog

All notable changes to zejtron.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The changelog is split into per-era records so this one stays navigable:
this file carries ONLY the entries newer than the v11.0.0 stable release
— the fresh record for the upcoming version, with no legacy bulk. The
v10-era history (the v5-line entries through the v11.0.0 release, the
changelog blob as it stood at v11.0.0, 2026-07-09) is archived in
[docs/archive/CHANGELOG-V10.0.0-ERA.md](docs/archive/CHANGELOG-V10.0.0-ERA.md),
frozen verbatim.

## [Released]

v80.0.0-alpha.2
v80.0.0-alpha.1
v11.0.0

## [Unreleased]

### Added

- The Evidence Ledger is now a formal specification (v1, frozen).
  docs/EVIDENCE-LEDGER.md defines the four provenance tiers, the
  output grammar, and the UTC/deterministic laws. Any tool can now
  claim compliance with the Evidence Ledger v1. zejtron is no
  longer just a binary; it is the reference implementation of a
  standard. The spec is extracted from the code, not written over
  it: the four tiers ([observed], [measured], [inferred],
  [unaccounted]) are defined epistemologically - direct perception
  of events, direct perception of state, reconstruction from
  indirect evidence, and the named absence - the block grammar
  (header, mode line, evidence rows, Changes subsection,
  Unaccounted block, two-line verdict) is stated byte for byte as
  the renderer ships it, and the four laws (UTC everywhere with the
  first-row (UTC) declaration, deterministic ordering with no hash
  map iteration, zero escape bytes when piped, Unaccounted always
  present) are the rules the render and capability modules already
  enforce and pin. The escape hatch is on the record: a tool
  without the kernel lane labels its replayed rows [inferred] - the
  tag describes the source, never the ambition - and declares its
  lane honestly in the mode line. v1 is frozen: a grammar change is
  a new version and a breaking event, not an edit. The document and
  the code are clamped together by a drift pin (test/evidence/
  spec_tests.rs, wired test-only - the release binary is
  byte-identical): the spec carries a machine-readable tier block,
  the pin demands exactly the four code tags in tier order, and the
  pin's exhaustive match has no wildcard arm, so a fifth Provenance
  variant is a compile error in the test file before it can be a
  format break anywhere. Pure documentation pass - zero runtime
  code changes; README states the compliance fact near the top, and
  docs/README.md's map carries the new document.
- The reliability of the parsers is now a continuous guarantee. A
  cargo-fuzz lane runs against the BTF parser, the /proc parser, and
  the terminal sanitizer, proving that hostile or corrupted kernel
  inputs result in a clean error, never a panic. The detective does
  not break when the evidence is malformed. Three targets, one per
  critical surface (night-improve-43): `btf_parser` drives the two
  pure BTF entry points (`parse_btf_offsets`, `verify_writev_symbol_in`)
  over arbitrary bytes - the /sys/kernel/btf/vmlinux grammar a
  corrupted host could serve, short files, lying section bounds,
  truncated type records included; `proc_parser` drives the shared
  /proc and /etc grammar in `src/system/mod.rs` - the cmdline byte
  parser (extracted as the pure `parse_cmdline_bytes` behind
  `read_cmdline`, zero behavior change) plus the passwd, status, and
  cgroup string grammars behind the same UTF-8 gate the real readers
  sit in; `sanitize_display` asserts its two properties on every
  input the fuzzer invents - NO control character survives into a
  rendered row (the CWE-150 gate, terminal injection dead on
  arrival) and honest data comes back byte-identical. The harnesses
  path-include the parser sources instead of adding a lib target to
  the bin-only crate: the fuzzer compiles the same src/ebpf/btf.rs
  and src/system/mod.rs bytes the binary ships, so a guarantee the
  lane proves is a guarantee the binary carries, with no harness
  drift and no copied grammar. The lane rides nightly (cargo-fuzz's
  standard toolchain) with the stable pin untouched - the override
  is env-scoped to the fuzz lane's cargo invocations, the main
  crate's lanes never see it; each target runs a bounded 60 seconds
  per push with the corpus cached between runs, so depth accumulates
  and a regression fails CI with the crashing input in the log. The
  eBPF kernel-side code is deliberately not fuzzed: it runs behind
  the kernel verifier, not in userspace. Proven green the night it
  shipped - 1.39M BTF walks, 144K /proc grammars, and 269K sanitizer
  passes with zero crashes: the claim was already true, and now it
  is a standing test that stays true.

- A false-negative gap in the file-write arena is closed. zejtron now
  taps vfs_writev alongside vfs_write, ensuring that processes using
  vectorized I/O are not invisible to the Evidence Ledger - the
  detective no longer mistakes silence for the absence of writes.
  Before this pass, a writev(2)/pwritev(2) write never crossed the
  vfs_write kprobe: a database, a web server, or any vectorized
  logger could write the queried file THROUGH an open window while
  the ledger read silent - for a forensic tool, the wrongest kind of
  quiet. The fifth tap program (writev_tap) publishes op=4, rendered
  "wrote (writev)" in the ledger row and "write (writev)" on the raw
  lane, so the row names WHICH write path crossed; writev(2),
  pwritev(2), and pwritev2(2) all funnel through vfs_writev, so one
  probe covers the family. The attach symbol is verified from the
  host's own BTF at attach time - the argument-position sibling of
  the offsets law: vfs_writev's first argument must be a pointer to
  struct file (do_iter_write is the verified fallback; a symbol
  present but reshaped refuses by name, never a silent fallthrough;
  neither verifiable refuses the whole attach). The Writes-only
  window filter counts op=4 as a write, so the gap cannot be reborn
  one layer up in the filter. The honest cannot-lines and the
  README's Limitations now name the residuals that remain: mmap'd
  writes, async kiocb writes (io_uring/AIO ride call_write_iter
  directly), and splice-class copies. The pin set grows to fifteen
  (the writev tap's program/link pair); the doctor's Probes row
  names vfs_writev. Proven live, the same night, under TCG on the
  noble 6.8.0-31 witness: a real writev(2) - two iovecs through
  syscall 20 - surfaced as [observed] "wrote (writev)" with the
  writer's pid attributed in BOTH why and touch, fifteen pins
  planted and detached clean. The battery grows the proof with the
  first live event-window checks it has ever carried (the why and
  touch surfaces, gated on attach + perl): every push now re-proves
  the weapon absolute on the witnesses lane - the twin-run found and
  fixed the proof harness's own race before CI ever saw it (perl's
  redirected stdout is block-buffered; the writer now flushes its
  pid print at once).
- SECURITY.md carries a "Forensics scope (DFIR)" section - the
  incident-response claim stated with its own boundary. What the
  tool offers an investigator: read-only collection (the command
  surface writes nothing, so the mtime/ctime of the evidence stand
  as the kernel holds them - zejtron touch reads timestamps,
  never sets them), provenance on every Evidence Ledger row
  ([observed], [measured], [inferred], [unaccounted] - direct
  versus circumstantial, named per row), and deterministic
  UTC-stamped output that diffs between runs without translation.
  What it is not: a write-blocker or acquisition tool (no disk
  images, no chain of custody - it prints; filing the output is
  the operator's act), a rootkit hunter (a process that hides
  from the kernel hides from zejtron), or host-wide from inside a
  container (it reads the namespace's /proc). The one named
  residual: the opt-in eBPF attach lane plants and removes pins
  under /sys/fs/bpf/zejtron - the single state-changing surface,
  which an analyst preserving a byte-exact host image should not
  run. docs/README.md's map line for the security policy mentions
  the section.
- QA.md answers the monitoring question on the record (Q7, "Is
  zejtron a monitoring tool?"): no - zejtron collects evidence and
  exits; no daemon, no polling interval, no alerting, no data
  retention, nothing running after the process ends. The
  deterministic output exists so two separate invocations can be
  diffed, which is investigation, not monitoring; a workload that
  needs continuous watch needs a monitoring daemon, a different
  product class. The answer points at the front page's "Intended
  Environments and Users" section as the positioning source.
- The README now documents its own ground. A new "Intended
  Environments and Users" section under "Why zejtron?" states the two
  environments the tool is built for - production servers and
  containers (one binary, statically linked in the musl shape, no
  daemon, no background agent, writes nothing to disk, the
  deterministic UTC output diffable between runs and fileable as a
  post-mortem or compliance record) and developer desktops (who
  holds this port, what modified this config, where the RAM went -
  answered without installing a monitoring stack). The section names
  the target users - power users and sysadmins (the
  ss/lsof/ps/journalctl workflow carried in one grammar, every row
  tagged [observed] or [inferred]) and security/forensics (read-only
  by design: no state altered, no forensic timestamps disturbed,
  safe to run during an active incident) - and names who should NOT
  use zejtron: beginners who want a GUI dashboard, and anyone who
  needs continuous real-time monitoring. zejtron collects evidence
  and exits; it is an investigative CLI, not a monitoring daemon.
  docs/README.md's map line for the front page mentions the section.
- The CI witnesses lane (the owner's next-cycle ask, candidate b,
  riding candidate a's presets): `.github/workflows/
  supermassive-kernel-witnesses.yml` - a three-leg matrix (focal
  GA 5.4.0 below the floor, jammy GA 5.15.0 at the floor in
  report mode, noble GA 6.8.0 above the floor) that boots each
  witness's GA kernel in a KVM micro-VM on the runner and runs
  the FULL supermassive low leg inside it, per push, in report
  mode (the init reports the floor direction instead of gating
  the identity; the payload's exit code is the verdict). The lane
  runs the operator's own instrument - the SAME entrypoint,
  packer, and init as the local twin (`zejtron-sandbox.sh
  --kernel SUITE --battery`), so CI cannot drift from the
  operator's tool: they are one code path, and the kernel-span
  claim stops going stale the moment the tree moves. The witness
  cache (the suite's GA kernel deb, the base tarball, the
  iproute2 closure) rides actions/cache keyed by the packer's
  hash; the initramfs is rebuilt every run. The lane's first run
  found its own payload bug and the fix rode the same night: the
  gnu binary built on the glibc-2.39 runner refused to execute in
  the twin's ubuntu:22.04 userland (glibc 2.35) - every surface
  failed at execution on guests whose substrate probes all
  passed. The lane now builds and rides the STATIC musl shape
  (userland-free - the same shape the same-night live proofs
  rode: 276/276, 280/280, 280/280 under TCG); the floor lane keeps
  the gnu shape, its userland being the ubuntu:24.04 container
  the exact glibc the runner builds with.
- The witness presets for the kernel-floor sandbox (the owner's
  next-cycle ask, candidate a): `--kernel focal`, `--kernel jammy`,
  `--kernel noble` - ready-made witnesses that resolve that Ubuntu
  suite's GA release-day kernel from the LIVE archive's main pocket
  through one suite table in the packer (the same discipline the
  floor kernel rides: the GA suite frozen by archive policy, main
  carrying exactly one generic image per major.minor; verified live
  against the pockets - focal 5.4.0-26.30, noble 6.8.0-31.31). The
  report lane is now one word wide on either side of the floor
  line. Proven live, all three sides, under TCG on this agent box:
  focal 5.4.0-26 BELOW the floor - 276/276, 0 fail, 0 skip, the
  attach specs in the refusal direction, 11s wall of the 60s
  budget; jammy 5.15.0-25 at the floor on the report lane -
  280/280, the success direction, 12s; noble 6.8.0-31 ABOVE the
  floor - 280/280, 0 fail, 0 skip, the privileged attach lifecycle
  in the success direction on a second kernel generation (BTF
  readable on 6.8 GA), 19s - the first proof anywhere above the
  floor. The entrypoint's usage slice is repaired with the same
  edit: the old head-30 sizing was already leaking Requirements
  lines into -h; the block now ends at its own marker, and the
  option table grew the preset spelling without any fixed cap.
- The arbitrary-kernel lane for the kernel-floor sandbox (the
  owner's next-cycle ask): `zejtron-sandbox.sh --kernel PATH`
  now boots ANY local vmlinuz, not just the floor kernel. The
  lane rides a marker packed at `.sandbox/lane` (floor = the
  strict 5.15.0 identity gate, unchanged and still the CI lane's
  only mode; arbitrary = report mode): the init reports the
  floor direction of the booted release (at/above or below the
  5.15 floor - the same number the suite's capability
  computation reads) instead of gating the identity, the
  substrate probes (BTF, tracefs) become reports, and the
  payload's exit code is the verdict. Proven live both ways on
  this agent box (TCG): the REAL jammy GA 5.15.0-25 via PATH -
  280/280, the full privileged attach lifecycle in the success
  direction, 12s wall; and the REAL focal GA 5.4.0-26 (a kernel
  no stock runner can host and the floor lane would refuse by
  design) - 276/276, the attach specs in the refusal direction,
  BTF honestly reported unreadable (focal GA ships no BTF
  vmlinux), 9s wall. The instrument now proves zejtron on any
  kernel the operator chooses, from either side of the floor
  line.
- The kernel-floor micro-VM lane (night-improve-43, the owner's
  correction of its own first pass: the low-specs test must run on
  the REAL minimum kernel, not a computed agreement against a newer
  one - it boots a KVM micro-VM on the exact kernel the floor
  documents). The lane: `.github/workflows/
  supermassive-kernel-floor.yml` fetches the jammy GA release-day
  kernel (linux-image-unsigned-5.15.0-25-generic, the LIVE
  archive's jammy main pocket - frozen by archive policy, the
  weekly jammy-updates ABI bumps deliberately not configured; the
  5.15.0- resolution pins the floor number and fails loudly if the
  archive ever stops carrying it), boots it in a KVM micro-VM on
  the runner (direct kernel boot, host-passthrough CPU, no disk, no
  modules - every filesystem the suite touches is built into the
  Ubuntu generic kernel; a RAM-resident initramfs: the ubuntu:24.04
  container + the checkout + the release binary; the dynamic low
  envelope, quarter cores / eighth RAM floored at 1 vCPU / 1024 MB;
  panic=-1 + -no-reboot + an outer timeout; qemu's isa-debug-exit
  port device as the deterministic guest exit), and runs the FULL
  supermassive low leg inside it, as root, on exactly the oldest
  kernel zejtron promises to run on. What it proves that no other
  lane can: the at-floor direction of the kernel-floor agreement,
  LIVE (no stock GitHub runner ships a 5.15 kernel - the ubuntu
  images ride 6.x HWE kernels, so every other lane only computes
  the at/above direction); the privileged attach lifecycle for real
  (root + BTF + the floor kernel is the one CI place attach can
  succeed); and the whole suite on the floor userland shape.
- The local twin of the kernel-floor lane:
  `scripts/sandbox/zejtron-sandbox.sh` (one click: the low leg in
  the VM; `--run`, `--shell`, `--self-test` beside it) with
  `scripts/sandbox/rootfs-pack.py` (the rootless provisioner -
  the jammy GA floor kernel resolved from the same Packages index
  that provisions iproute2 by real dependency resolution, the
  ubuntu:22.04 base, the newc initramfs with the device nodes a
  non-root packer cannot mknod synthesized into the stream, every
  load-bearing lesson of the sibling's packer kept: the 4-byte
  header+name alignment, the usr-merge symlink rule, the atomic
  download cache) and `scripts/sandbox/sandbox-init.sh` (PID 1:
  the mounts, the lane's own floor guard - the booted release MUST
  be 5.15.0-* or the run fails before the payload - BTF
  readability, the binary's -V and doctor probes, and the
  SANDBOX-* sentinel verdict relay). KVM when /dev/kvm is writable,
  TCG software emulation otherwise (under TCG the low leg's 60s
  wall budget can breach without the binary being at fault - the
  budget is a real-hardware contract).
- The doctor surface's attach lifecycle specs grow the privileged
  direction (the missing low-spec spec the micro-VM lane exposed:
  --attach was pinned to the refusal contract unconditionally, so
  the suite could never run green on a host where attach actually
  works). The harness now computes the binary's own preflight
  (the floor direction from the same osrelease file, BTF
  readability, CAP_BPF + CAP_PERFMON from the effective set) and
  branches: a refusal keeps the verified contract (exit 1, "attach
  refused" naming its reason); a SUCCESS on a provably capable host
  carries its own contract (the tap names itself, the pin directory
  names itself, the BTF-verified offsets claim pins itself, the
  second attach is the honest idempotent nothing-to-do, the detach
  is the REAL unpin - the pin directory gone from the filesystem -
  and the second detach the idempotent nothing-to-detach); a
  success on a host the harness reads as incapable is a loud
  failure (the binary attached where its own preflight must
  refuse). The attach/detach invocations ride the leg's documented
  20s slow-class per-call budget (the one-shot loads four BPF
  programs and pins thirteen objects - the same vocabulary
  --check-update rides).
- The infra depth audit (night-total-lts-2, the second pass under
  the name - the first fixed the deny.toml schedule claim and the
  gate's tmpdir contract) hunts the stale-documentation cluster
  around the container lane and closes it. Three findings, three
  fixes, all in the same commit because they are one drift: (1)
  supermassive-container.yml's header still claimed "zejtron is a
  pure procfs/sysfs reader with no kernel surface" - a comment
  written before the eBPF lane landed, contradicting the very
  workflow that installs the eBPF build prerequisites three steps
  later; the paragraph now tells the truth (the lane's docker is
  unprivileged by design, the binary ships the full eBPF lane, the
  lane asserts the honest container-side rendering). (2) The
  supermassive README's known-skip list documented "root + BTF +
  kernel 5.15+ host - the privileged attach leg belongs to the
  container lane" - but no surface emits that skip and no container
  lane ever ran an attach leg; the list now carries the two skips
  that actually exist (the version pin's Cargo.toml lookup, the
  kernel-floor agreement's osrelease read) plus an honest note that
  the privileged attach leg has no CI seat anywhere by design.
  (3) docs/workflow/about-ci.md documented only one of the three
  supermassive lanes; the surface lane (supermassive-e2e.yml, the
  per-surface depth contract) and the container lane now have
  their own sections. The same pass hardens the container lane's
  supply chain: the alpine:3.20 test substrate is now pinned by
  its multi-arch manifest digest (the same discipline every
  SHA-pinned action and version-pinned tool already rides - a
  floating tag was the one dependency the lane pulled by name
  alone), with the deliberate-refresh procedure documented in the
  workflow; and the lane now asserts the [eBPF] section renders
  inside the container (the section is the binary's unconditional
  contract - a missing render inside docker is a regression the
  host battery cannot catch).
- The supermassive doctor surface grows the kernel-floor specs
  (night-improve-43). The depth audit found the suite pinned only
  the [eBPF] header, the Feature row, and the Lane row: the
  section's six remaining rows (Kernel, BTF, Lockdown, Caps,
  Probes, Pins) were unpinned, and no check anywhere tied the
  host's kernel release to the documented 5.15 floor
  (src/ebpf/mod.rs's KERNEL_FLOOR, the README's "kernel >= 5.15").
  The new checks, all against the real binary: every row key
  renders on every host (the values are host facts, the keys are
  the binary's contract); the Probes row carries the four tap
  names in planting order (sched_process_exec,
  inet_sock_set_state, vfs_open, vfs_write - the binary's
  contract, not host state); the Kernel row agrees with the host's
  own /proc/sys/kernel/osrelease (the harness reads the same file
  the binary reads); and the kernel-floor agreement check computes
  the floor direction harness-side and holds the render to it from
  BOTH sides of the line - at or above 5.15 the Lane row never
  carries a false floor refusal, below 5.15 (or an unparsable
  release, the binary's refuse-what-it-cannot-verify law) the Lane
  row AND the doctor --attach refusal name "below the 5.15 floor"
  by word. The floor number rides the matched string, so a floor
  bump without a suite bump fails the check. Honest scope: no
  stock GitHub runner ships a below-floor kernel today (the
  ubuntu-22.04 image rides a 6.8 HWE kernel), so the CI legs pin
  the at/above direction only; the below-floor direction pins
  itself wherever a maintainer runs the suite on an old-kernel
  host. The suite's README grows the same contract in its
  lane-honesty list.
- The supermassive suite lands: every surface — path, recent, port,
  proc, holds, touch, why, net, doctor, doctor --symptom ram,
  -h/--help, -V/--version — is exercised end to end on both a
  low-spec and a best-spec runner, with success, error,
  determinism, and color-tritest checks per surface. Every SKIP
  names its reason; no surface has fewer than five checks. The
  suite's exit code is trustworthy: 0 means every surface was
  tested (or honestly skipped), 1 means any failure. It is not a
  gimmick — it is the proof zejtron works. The suite is bash +
  coreutils only, lives at scripts/supermassive/ (supermassive.sh,
  the lib.sh engine with its own self-test, one file per surface,
  the low.sh / best.sh legs), and is wired into CI by
  .github/workflows/supermassive-e2e.yml: two jobs - the low-spec
  leg on the MSRV floor (1.98.1, 60s wall budget) and the
  best-spec leg on the stable frontier (stable, 300s wall budget) -
  both running the IDENTICAL check depth, both failing the
  pipeline on any FAIL. Depth audit from the landing run (265
  checks, 0 fail, 0 skip, wall 2s against the 60s low budget):

  | Surface              | Checks | Succ | Err | Det | Color |
  |----------------------|--------|------|-----|-----|-------|
  | path                 |   17   |  y   |  y  |  y  |   y   |
  | recent               |   20   |  y   |  y  |  y  |   y   |
  | port                 |   38   |  y   |  y  |  y  |   y   |
  | proc                 |   25   |  y   |  y  |  y  |   y   |
  | holds                |   27   |  y   |  y  |  y  |   y   |
  | touch                |   22   |  y   |  y  |  y  |   y   |
  | why                  |   27   |  y   |  y  |  y  |   y   |
  | net                  |   14   |  y   |  y  |  y  |   y   |
  | doctor               |   23   |  y   |  y  |  y  |   y   |
  | doctor --symptom ram |   13   |  y   |  y  |  y  |   y   |
  | -h / --help          |   22   |  y   |  y  |  y  |   y   |
  | -V / --version       |   17   |  y   |  y  |  y  |   y   |

  The documented flag estate is covered end to end (the runner's
  gap report prints UNTESTED FLAGS: none). The suite has NO dormant
  leg on purpose: the eBPF support is unconditional by owner law
  (night-weekly-maintenance-1, "always enable, permanent" - no
  build flag can produce a dormant binary), so the lane surfaces
  carry lane-honesty checks instead: the Mode-line declaration and
  the no-fake-[observed]-rows rule in snapshot mode, the [eBPF]
  Feature/Lane declarations, and the honest event-window header.
  Every contract the suite pins was verified against the real
  binary first, including the honest exception that `path
  <missing>` is a report (exit 0), not a failure.

- The README now names the current version twice: once as the
  canonical current-release line near the top, once as the TAG
  variable in the install command. Everywhere else the prose refers
  to "the current release" or "this alpha." The next version bump is
  a single-line change to the canonical line and the TAG line — not
  a grep across ten places. The boring part of boring-and-serious.

- The prebuilt lane's fail-closed verdict now has a push-time CI
  seat. gate-keepers.sh grows section 16: on every push the
  Gate-keepers lane runs regenerate-ebpf-prebuilt.sh --check - the
  same read-only verdict the commit-time hook runs - so a stale tree
  pin, a tampered staged object, or a broken version mirror turns
  the push red. The gap was real: the build-time arm (build/ebpf.rs's
  auto-heal) repairs a stale lane for every local cargo build, which
  is right for the developer but wrong as the only CI mirror - a
  heal inside the runner leaves the pushed manifest stale and the
  run green, so a lane that missed its regeneration (or an object
  tampered with after it) sailed through every existing workflow
  unnoticed; the manifest even parsed as valid TOML while carrying
  rebase conflict markers, because no CI seat ever recomputed the
  pins. The verdict needs the pinned digest tool, so the
  Gate-keepers workflow now installs b3sum 1.8.7 from the official
  BLAKE3 release under the bytes-are-the-pin contract (sha256-pinned
  like shellcheck, shfmt, and actionlint), and the version constant
  rides check-rust-version-sync.sh's B3SUM lockstep check beside
  bootstrap-ebpf.sh and the regenerator - the workflow cannot drift
  from the scripts' pin. Tamper-verified before landing, the honest
  way: a one-byte flip in the staged object, a source edit under
  ebpf/ without regeneration, and a version-mirror drift each fail
  the verdict with the broken pin named in the error, and the
  restored tree passes clean. Locally the section skips with a
  warning when b3sum is absent (the wholesale contract); in CI the
  tool is always installed, so the seat never sleeps.

- The logo's legal record is now explicit instead of implied
  (night-improve-45). TRADEMARK.md section 1 now states the
  artwork's origin on the record: the zejtron logo was created
  through AI-assisted generation under the direct, original creative
  direction and specific prompting of the owner, and is claimed and
  used exclusively as the project's brand identity (Trademark). The
  statement is deliberately two-sided - an honest disclosure of how
  the image was produced, and a firm claim of who directed its
  creation - because the trademark claim rests on the owner's
  creative direction, not on the tool that rendered it. NOTICE's
  trademark block carries the same origin sentence so the two legal
  surfaces agree, and the README footer appends the identical
  trademark sentence TRADEMARK.md already closes with ("zejtron and
  the zejtron logo are trademarks of rezky_nightky (oxyzenQ)"), so
  the claim reads the same in all three places. Pure legal
  documentation pass - zero runtime code changes, and the
  GPL-3.0-only terms for the source code are untouched.

- The actions-pin sweep's verdict now has a push-time CI seat, and
  the sweep can actually see the pins it polices. The hunt's ask
  was the seat: the freshness
  check ran only at commit time (advisory, check-commit-gate.sh
  section 3) - no workflow ever recomputed it, the exact gap shape
  the prebuilt lane had before section 16. Wiring the seat
  honestly forced the engine fixes first, because a strict seat
  over a blind sweep is theater: the sweep read every `uses:`
  ref's slug as `org/repo`, so a subdirectory action
  (github/codeql-action/init@v4) queried
  .../codeql-action/init/releases/latest, read the permanent 404
  as "API unreachable", and skipped forever - the estate's only
  tag pins (the codeql trio) had never received a real verdict.
  The /tags fallback was equally dead: it ran only when
  releases/latest returned no tag_name, never for the 404 of a
  release-less repo (the one case it was written for) nor for a
  release line pointing at a non-v tag (codeql-action's latest
  release is a bundle tag; the action's own v-tags carry the
  version truth). And the /tags fallback's own extraction was
  shape-blind: the API answers the sweep's User-Agent with one
  compact line - zero newlines, verified live - where the
  line-based sed degenerates to its LAST match, an arbitrary tag
  (a v3 read as "latest" while v4.39.1 sat in the same body),
  and the page's ordering is not a contract either. The sweep now
  looks the REPO up (the first two segments), a 404 and a non-v
  latest tag both fall through to the /tags fallback, the
  fallback extracts every v-tag token regardless of body shape
  and takes the highest (grep -oE plus sort -V), and the heal
  rewrites the full ref head
  (path included) - verified against the live API: the codeql
  trio reads CURRENT (v4 pins, v4.39.1 upstream) where it
  previously read "unreachable". The seat itself is one new
  section, not a new lane: gate-keepers.sh section 17 runs
  check-actions-pins.sh --strict, the Gate-keepers workflow maps
  the runner's GITHUB_TOKEN into the wholesale run (the
  authenticated quota; read-only, sent as a Bearer header, never
  written), and the only red the seat can produce is a
  KNOWN-stale tag pin - a fact upstream itself answered. Every
  skip reason stays a skip in every seat (offline, quota low,
  branch pins, SHA pins), an offline local run passes honestly,
  curl-less machines warn-skip per the wholesale contract, and
  the commit hook keeps its advisory shape. Tamper-verified
  before landing, both directions and both action shapes: a
  stale flat pin (actions/checkout@v3) and a stale subdirectory
  pin (github/codeql-action/init@v3) each fail the strict
  verdict and the full gate with exactly section 17 red, and the
  restored tree passes clean.

- The /tags read now names its own transport failures. The seat's
  landing commit exposed the residual through its own hook run:
  the advisory sweep, running unauthenticated, hit the IP quota on
  the /tags read (403) and reported the codeql pins as "no upstream
  release or semver tags" - a fake no-versions verdict, the exact
  lie the script's header promises never to tell ("an unreachable
  API and a low quota are SKIP reasons of their own - never a fake
  'no versions upstream'"). The /tags read now classifies its own
  failure with the same split the releases/latest read applies
  (403/429 names the quota with the set-GITHUB_TOKEN hint, anything
  else names unreachable), and only a read that SUCCEEDED and still
  found no v-tag reports the human-decision skip. Zero verdict
  changes: every case stays a skip, and the authenticated strict
  CI seat is unaffected - verified live in both modes, the
  unauthenticated run now reports the quota skip truthfully and
  the authenticated run still reads the codeql trio CURRENT.

- The eBPF lifecycle is now a doctrine with a citable document
  (night-improve-46, the Lazy Camera). docs/EBPF_LIFECYCLE.md
  defines how the lane lives on a host: the two modes a surface
  can ride (snapshot - a /proc read of what holds; live - a
  kernel-recorded event of what happened, with the acting PID),
  the Lazy Camera concept itself (the kernel-side programs record
  into bounded ring buffers that live in kernel memory - nothing
  streams to userspace, nothing is written to disk, and no
  zejtron process exists between commands), the four-step
  lifecycle (attach once per boot - the pins live on bpffs and
  the per-boot shape is physics, not policy; the kernel records;
  a command drains its window, prints, and exits; optional
  detach leaves the same zero footprint a never-attached host
  has), and the non-monitoring argument in full: no daemon, no
  agent, no telemetry, zero userspace footprint between
  invocations, nothing written to disk, and a camera that only
  answers when asked. The honest limits ride with the doctrine -
  the rolling window, the consumption semantics, the filter
  discipline, the pre-attach past, and the probe floor. The
  doctor's [eBPF] section carries the doctrine's own posture as
  a new Mode row between Lane and Probes: "Mode: Lazy Camera
  (Kernel: recording | CLI: asleep)" on an attached host, "Mode:
  Lazy Camera (Kernel: not recording | CLI: asleep)" on every
  other verdict - the row is verdict-driven, so it can never
  claim a recording that is not happening. README gains "The
  Lazy Camera" section under the eBPF lane pointing at the
  document, and docs/README.md's map carries it. The display row
  is the only code touched - no behavior, no flags, no grammar
  change beyond the new row.

- The ram symptom can now see the freshly dead
  (night-improve-47, the post-mortem doctor). A process that
  allocated memory and exited three seconds before
  `doctor --symptom ram` runs is invisible to every /proc read -
  the hole night-improve-34 named in the Unaccounted block as
  "attribution lost" is now partly closable, honestly: the exit
  half of the lifecycle tap returns with a new consumer and a new
  shape. The kernel object grows a sixth program, the
  sched/sched_process_exit tracepoint (ebpf/src/exits.rs, its own
  module under the LOC cap), filtered to the thread-group leader -
  one record per process exit, carrying the pid, the process's
  own name (bpf_get_current_comm, the same bytes /proc's Name:
  field would have shown), and a monotonic timestamp in the new
  32-byte ProcExitEvent record - published to the new proc_events
  ring (256 KiB, 8192 records), unfiltered by design because the
  doctor cannot know in advance which exit will be the one it is
  asked about and the ring's rolling window is the bound. The
  loader plants the sixth program and its map (the pin estate
  grows from fifteen to eighteen: exit_tap, exit_tap_link,
  proc_events), the attach summary and the doctor's Probes row
  carry the sixth name, and the prebuilt lane is regenerated
  through its one writer (object blake3 bfea9123..., tree blake3
  728bc45f..., toolchain and version mirror unchanged). The
  doctor drains once, keeps the last five seconds, prints, and
  exits - the Lazy Camera contract holds: no daemon, no stream,
  nothing written to disk. The ram report gains the
  "Recently exited (eBPF, last 5s)" section with
  `<HH:MM:SS UTC>  PID <pid> (<comm>)  exited  [observed]` rows
  (the strongest provenance tier - the kernel itself recorded the
  exit as it happened), capped at the report's own TOP_N; the
  mode line names the lane's state ("snapshot + post-mortem ...
  drained" when it ran, the not-attached truth otherwise); and
  the Unaccounted block replaces the static night-improve-34
  sentence with the lane's three truths - not attached: "eBPF is
  not attached - processes that exited before this snapshot are
  invisible" (the spec's own sentence); drained: exits before the
  5-second window are not named; drain-failed: the verbatim error
  rides the report, never a silent empty section. The monotonic
  companions (the /proc/uptime "now", the wall offset, the
  HH:MM:SS UTC renderer) moved from port's private copies to the
  civil clock module - one source, two surfaces, the same dedup
  law the unavailability sentence landed under. Upgrade note: an
  attach planted before this pass carries no exit tap - the
  doctor reports not-attached honestly until
  `sudo zejtron doctor --attach` runs once more (the partial pin
  set self-heals into the full eighteen). README, the Lazy Camera
  doctrine document, the ebpf crate description, and the
  supermassive doctor surface carry the six-program estate.

- The symptom lane is now a family of five: `cpu`, `disk`,
  `network`, and `gpu` are implemented answers, and `slow` is the
  one honest deferral left (night-improve-48, the symptom
  expansion). The flag does not change - `--symptom SYMPTOM`,
  one flag on the doctor, the surface count stays nine - and the
  vocabulary it speaks is now six names: `ram`, `cpu`, `disk`,
  `network`, `gpu`, and `slow`. Three of the new lanes ride a
  shared delta engine (src/commands/doctor/delta.rs): read the
  kernel's tables, sleep exactly 1.0 seconds, read them again,
  print, exit - the wait IS the measurement, once per run, never
  a loop, a delta snapshot and not a monitor. The engine owns
  what the three surfaces need identically: the /proc/stat
  aggregate parser (the eight floor-kernel fields, the
  later-appended guest fields read past, not double-counted),
  the /proc/<pid>/stat parser (the comm taken whole between the
  outermost parens so a process named "yes R" parses, sanitized
  at the parse boundary under the zero-escape law; the state
  letter; the utime+stime tick pair), the /proc/<pid>/io parser
  (read_bytes/write_bytes, the block-backed pair - NOT
  rchar/wchar, which count cache hits and terminal writes), and
  the sampling-gap constant stated once. The cpu lane prints
  tick-RATIO percentages (pid tick delta over total tick delta -
  honest on every USER_HZ, no clock-frequency guess), a ranked
  top-consumer table, and the Load/stuck section htop cannot
  give without being left running: the D-state processes by pid
  and name at the second sample, plus the stuck signature
  verdict - the 1-minute load above the core count while the
  CPU is quiet below 20% busy is named as processes waiting on
  I/O, a fact the user verifies, never an instruction. The disk
  lane rides the block-backed byte pair per process and the
  iowait share of the window's ticks, counts every permission
  refusal (another user's /proc/<pid>/io is root-or-owner only)
  into the Unaccounted block, and its --raw drill-down re-reads
  the top processes' io files verbatim at render time. The
  network lane reads /proc/net/dev twice for per-interface
  byte/packet deltas, censuses /proc/net/tcp and tcp6 for the
  two stall signatures (TIME_WAIT and CLOSE_WAIT), and walks the
  fd tables for the socket-holder census - with the 1024
  TIME_WAIT boundary named in the verdict as the port-exhaustion
  risk, a named number, not a mood. The gpu lane takes no delta
  at all - the question is who holds the device open, and
  /proc/<pid>/fd answers it at the instant of the command: the
  fd link-target classifier names the DRI cards, the render
  nodes, and the NVIDIA character devices; the AMD/amdgpu VRAM
  pair renders from sysfs when the driver exports it; and the
  proprietary NVIDIA marker is named [unaccounted] - the VRAM
  truth lives behind nvidia-smi, an external tool zejtron does
  not run, so the card's memory is never guessed ("No active
  GPU processes observed." is the spec's own honest empty
  scene). All four lanes drain the post-mortem exit ring
  night-improve-47 planted when the tap is attached - a
  2-second overlay slice (wide enough to cover their own
  1.0-second window plus the drain's skew; ram keeps its five),
  so a process that died inside the sampling window is named
  [observed] beside the numbers it can no longer explain - and
  the not-attached shape is the spec's own sentence: "processes
  that started and exited within the window: not attributed
  (zejtron samples, it does not watch)". The mode-line and
  sampling-boundary builders live in the engine, one source for
  four surfaces, so the ledgers cannot drift; the exit drain
  itself is parameterized now (ram asks for five seconds, the
  delta lanes for two, the window label riding beside the number
  so header and boundary text cannot drift apart). The deferral
  arm is the honest one, not a stub: `slow` prints the
  implemented list quoted from the dispatch's own source and
  exits 0 - the umbrella needs the per-lane reports to compose
  first. Every lane names its permission refusals in its
  Unaccounted block, the CLI help and the pro-mode help carry
  the six-name grammar, and the supermassive suite grows four
  surface rows (the doctor-ram precedent: success shape, --raw
  drill-down, structural determinism, the color tri-test) plus
  the six-name grammar pin, with the volatile-field table
  growing the two genuinely-moving gauge shapes the delta
  reports render (the window tick deltas, the 1-minute load
  gauge) and the spell-check vocabulary growing the renderD
  device-node name (the AMD render node is a kernel name, not
  a typo for "rendered"). The tests pin the parsers, the
  delta tables, the boundary counters, the six mode lines, the
  three sampling-boundary truths, and every render shape
  with synthetic samples - the report is the contract, not
  the host (417 tests, +49).

- The fuzz lane grows seed anchors and a weekly deep session
  (night-improve-50): fuzz/seeds/ carries three hand-built BTF
  blobs - the kernel 6.18 unnamed-union shape night-improve-49
  taught the member walk to descend, a two-level anonymous nest
  that pins the qualifier resolution and the offset
  accumulation, and the direct-member layout carrying a
  verifiable vfs_writev so both pure entry points the harness
  drives are anchored - and the fuzz workflow copies them into
  the working corpus after every cache restore, so a 60-second
  run starts inside the anonymous-descent paths instead of
  spending its budget rediscovering a valid BTF header byte by
  byte. The seeds are the lane's definition and travel with the
  repo (the same law as the targets and the manifests, and the
  fuzz/.gitignore comment now says which side each artifact
  belongs to); the corpus the fuzzer grows between runs stays
  out of git as before. The same workflow now also runs a
  weekly deep session every Monday 07:30 WIB - 15 minutes per
  target instead of 60 seconds, both sessions sharing the one
  corpus cache, the budget the only difference (the low/best
  leg law the supermassive suite already carries) - the
  owner-lazy insurance the continuous regression net cannot
  buy. No parser byte changed: the seeds are data, verified
  against an independent walk of the same shapes the unit
  suite pins, and the lane's guarantee stays what it was -
  hostile bytes in, a named error out, never a panic.

### Changed

- The CI trigger surface is simplified to unfiltered (the owner's
  cost-maintenance call): the estate-wide path spelling and the
  branch law are retired whole - every push (any branch, any tag)
  and every pull request (any base) now burns every lane, because
  the filters' sync tax across ten workflow files (the six-glob
  spelling kept identical everywhere, the no-drift law between the
  push and pull_request blocks, the branch scoping) cost more than
  the runner minutes they saved. A docs-only change now burns the
  build lanes too; gate-keepers, docs-ci, audit, codeql, and miri
  ride the same blind posture. The scheduled clocks stay, honestly
  re-scoped: audit.yml's Monday run watches the advisory DB (a new
  advisory lands against an unchanged tree - no change event can
  carry that signal), and miri.yml's Sunday run watches the moving
  nightly (new miri findings against an unchanged tree). The one
  deliberate exception, exactly as the owner specified it: the
  publish lanes (release.yml, crates-io.yml) are not blind - they
  keep their dedicated v* tag trigger, so a publish stays the
  owner's deliberate act, never a consequence of an arbitrary
  change. Docs updated to match: about-ci.md (every trigger
  paragraph plus the CI section), QA.md, docs/v5.md's CI
  requirement, and each edited workflow's header comment.
- This alpha is the first public release of zejtron, and this
  pass makes it publishable: the prebuilt lane lands so a crates.io
  install gets the full eBPF-enabled binary without a toolchain on
  the target machine, the ebpf feature becomes default with
  --no-default-features as the explicit dormant opt-out, and
  cargo publish --dry-run passes end-to-end. The version stays
  alpha.1 because the surface is not frozen: real usage will drive
  QC passes, and a future commit will bump to 80.0.0 stable and
  freeze. This pass does not publish. The owner does, from a
  personal laptop, after reviewing the checklist.
- The prebuilt lane (night-improve-5) is what the registry install
  proves: `ebpf-prebuilt/` rides the tarball with the
  maintainer-built kernel object and its provenance manifest
  (toolchain pin, linker pin, ebpf/ tree hash, object sha256, the six
  attach targets, and the version mirror), so a registry install
  stages a manifest-verified object and embeds it - no nightly, no
  bpf-linker, no nested build on the target machine. The lane is
  written by one script
  (scripts/dev/regenerate-ebpf-prebuilt.sh), enforced at commit time
  by the fail-closed parity sections of the commit gate, verified
  again inside the build (build/prebuilt.rs refuses to embed bytes
  the manifest does not describe), and stamped into the binary
  (ZEJTRON_EBPF_LANE: source-built on a checkout, registry-prebuilt
  from a tarball). The version stays this alpha - not 80.0.0
  stable - because the freeze belongs to a later pass: the alpha is
  the iteration room where real usage drives the QC passes, and
  cargo's pre-release rule keeps it opt-in until the stable bump
  makes the default install lane the frozen one.
- Every surface zejtron prints now carries a consistent color scheme: green for primary content (section headers, field labels, verb names, the strongest provenance tags), grey for secondary content (mode lines, hints, timestamps, the weaker provenance tags, examples), white for the values. The scheme degrades honestly through truecolor, 256, 16, and plain text; piped output carries zero escape bytes and NO_COLOR is honored everywhere. All twelve render paths were audited — the audit is in the commit body, not implied.
- The unavailability sentence now has exactly one source. The
  Evidence Ledger renderer and port's window printed the same
  refusal line from two hand-maintained copies
  (src/evidence/render.rs and src/commands/port/window.rs - the
  duplication was itself the documented contract, a cross-reference
  each copy pointed at the other); a one-character drift in either
  copy would have desynchronized the two surfaces' honesty with no
  gate to catch it. The sentence's single source now lives in the
  evidence renderer (pub unavailability_line), the layering
  unchanged: evidence still stands alone below the commands, and
  port's window delegates down through its Duration-taking facade,
  the shape its callers and tests already speak. Zero behavior
  change, proven the honest way before landing: the full unit
  suite (347 tests) runs green on the identical bytes, including
  the window suite's refusal-line pins and the renderer suite's
  unavailability pin, with rustfmt and clippy clean.

### Added

- The eBPF infrastructure lands as an opt-in cargo feature (`cargo
  build --release --features ebpf`): a detached `ebpf/` workspace
  cross-compiles one pure-Rust aya-ebpf program (no C, no clang, no
  libbpf — the repo-local `bpfel-unknown-none` spec with
  `atomic-cas: true` and cpu v3 for the BPF_ATOMIC counter), the root
  build.rs stages the object into `OUT_DIR` after structural ELF
  validation (the zylaxion hardening: prerequisite preflight that
  panics with the one-command fix, the host-RUSTFLAGS poison strip,
  the v3 force), and the host embeds it through the AlignedElf wrapper
  and loads it with aya 0.14 — the upstream pairing of the ebpf
  crate's aya-ebpf 0.2.1. The loader plants every pin under
  /sys/fs/bpf/zejtron/ (program, link, map — link first on removal),
  `doctor --attach`/`--detach` drive the verbs in every build (a
  featureless binary refuses by name and exits non-zero, never a
  silent no-op), and the doctor's report closes with an
  always-present [eBPF] section: feature, kernel, BTF, lockdown,
  capabilities, the lane verdict, and the pin state — one probe
  feeding both surfaces, no drift. The counter readback rides the
  pinned map (`MapData::from_pin`), the attach moment rides the pin's
  own mtime, and `scripts/dev/bootstrap-ebpf.sh` installs the two
  build-time prerequisites idempotently (the dated nightly pin +
  the sha256-verified bpf-linker 0.11.1 release binary). The reading
  that shaped the pass: the zelynic/zylaxion ebpf workspace layouts
  (detached workspace, dated nightly pin, custom bpfel spec,
  bpf-linker preflight, the /sys/fs/bpf/<name>/ pin discipline, the
  MapData::from_pin readback, the AlignedElf alignment lesson, the
  dormant honest-refusal lane), Phase 0's tree at 3348738 (the
  #[path]-wired single test tree, the doctor's CheckResult report
  shape, the curated tarball include list that keeps the registry
  lane snapshot-only), and the aya 0.14 API verified against source:
  take_link lives on the program (not the Ebpf object), and
  FdLink::pin consumes the fd link into a PinnedLink with no
  detach-on-drop — which is exactly what keeps the tap alive after
  the attaching process exits. (night-improve-1)

  Phase 1 lands the eBPF infrastructure: a no-op tap on
  sched_process_exec proves the chain works end-to-end — the BPF
  program loads, the verifier accepts it, the tracepoint fires, the
  counter increments, the loader reads it back, detach unpins every
  pin. The ebpf feature is opt-in; cargo install zejtron without it
  still ships the snapshot-only binary. No business logic changed;
  the chain is proven, and later phases upgrade the first surface.

- The port surface gains its event window (night-improve-2): a
  second BPF program on tracepoint sock/inet_sock_set_state reads
  the socket facts at the offsets verified against vmlinux BTF
  (skaddr 8, oldstate 16, newstate 20, sport 24, dport 26, family
  28, protocol 30 — a prefix layout stable since 4.16), filters to
  the port-surface transitions (TCP LISTEN enter/leave, UDP close —
  the shared predicate in src/ebpf/events.rs, single-sourced into
  the BPF crate via #[path] so the kernel side and the host tests
  compile the same bytes), and publishes a 32-byte SockEvent record
  to the pinned sock_events ring buffer with the pid of the process
  whose syscall made the change. Every offset inside the record is
  pinned by test (timestamp_ns 0 through pid 28); the ring holds
  256 KiB (8192 records) and the host drains it through the pin
  into a rolling 4096-entry window — the pump runs for the
  command's lifetime only, no daemon, no thread. `port` gains
  `--since <s|m|h>` (default 60s, clamped to [1s, 1h]),
  `--events-only`, and `--snapshot-only`; every row carries its
  provenance — [snapshot] or [event] — and the unaccounted block
  counts the events whose pid is no longer visible (a namespace
  boundary, or an exit between the change and the query). The
  doctor's [eBPF] section gains one row (Tracepoints) and the pin
  set grows to six: sock_tap, sock_tap_link, and sock_events join
  tap, tap_link, and stats; attach plants both programs, detach
  unpins all six, idempotent as before.

  The reading that shaped the pass: the phase-1 port answered one
  question — which ports are open and who holds them — from a
  snapshot assembled by parsing /proc/net at one instant and
  scanning /proc/*/fd at another, a two-instant race the tool could
  disclose but never close, while the doctor's [eBPF] section
  already carried the lane verdict and the counter readback. This
  pass adds the second question — what changed recently — answered
  by the kernel itself: the record is written at the moment of the
  state change, not inferred from a later scan. The port surface now
  tells two truths instead of one: what is listening at the instant
  of the query (snapshot, from /proc as before), and what entered or
  left LISTEN in the last N seconds (events, from
  inet_sock_set_state via eBPF). Every row carries its provenance —
  [snapshot] or [event] — and the unaccounted block names what
  neither can see. The race condition between the /proc/net parse
  and the /proc/*/fd scan stops mattering: the event window already
  recorded who made the change, at the moment it happened. Without
  the ebpf feature, port is the snapshot-only tool it was — same
  output, same behavior, no degradation.

  Two semantics named honestly: a ring buffer read consumes, so each
  `port` shows the events accumulated since the previous drain (or
  since attach, for the first); and the event record carries the
  port and the changer but not the bind address — the address stays
  the snapshot's truth, so an event row prints `*:<port>` with the
  family riding the protocol token (TCP4/TCP6/UDP4/UDP6).

- night-improve-3. The Evidence Ledger lands:
  holds, touch, and why now answer three questions instead of one —
  what happened, how do you know, and what can't you see. Every row
  carries a provenance tag ([observed] from eBPF events, [measured]
  from the snapshot, [inferred] from indirect evidence, [unaccounted]
  from what the report cannot see). The event windows come from
  vfs_open and vfs_write kprobes, filtered in the kernel by the
  tracked inodes map so only the queried file's events reach the
  ring. Without the ebpf feature, journalctl remains the fallback
  lane — the primary evidence path is no longer journalctl, it is
  the kernel itself. The format is one grammar across three
  surfaces; defensibility is the point.

  The reading that shaped the pass: the three surfaces each answered
  one question from one instant. `holds` parsed /proc into a holders
  tree (who has this open NOW — a snapshot that ages the moment it
  prints, blind to everything before it); `touch` replayed audit.log
  and journalctl for the last modification (a log's memory of a
  write, best-effort, retention-bounded, and the log lane cannot
  distinguish an open from a write); `why` cross-referenced both
  into a synthesis tree whose evidence line named the parsers but
  never the gaps. This pass adds the second truth to all three: the
  event window, recorded by the kernel at the moment the action
  happened, with the acting process's pid — plus the format that
  makes every row name its source and every report name its
  blindness. The three surfaces keep their parsers untouched; the
  Ledger wraps their output, it does not rewrite them.

  The shape of the added machinery, named piece by piece: two
  kprobes (open_tap on vfs_open, write_tap on vfs_write — exported
  symbols, stable first-argument shapes, role-named programs with
  the kernel symbol passed at attach); the tracked_inodes filter map
  (BPF_HASH<u64, u8>, 1024 entries, key (inode << 32) | device, the
  in-kernel price control — vfs_open fires on every open on the
  host, and only the queried file's events are allowed to cross);
  the file_events ring (256 KiB, 40-byte records, the same
  rolling-cap drain the sock ring rides); and the offsets config
  map, written at attach from the host's own /sys/kernel/btf/vmlinux
  (src/ebpf/btf.rs) — every struct walk in the kprobes reads its
  offset from that map, never from compiled-in constants, because
  struct inode's i_ino sat at @64 on this repo's reference probe
  where the textbook order would say @16: offsets that vary by
  version or build config are data, not code, and a wrong hardcoded
  offset goes blind silently. Refusing to attach without a
  BTF-verified set is the loud alternative.

  Three honest skips, named: no vfs_unlink kprobe (its signature
  churned across the floor — mnt_userns prepended in 5.12 moved
  dentry from arg1 to arg2 — so no single offset serves the range;
  op=3 stays reserved in the record contract); the write tap
  records write(2) at entry, so writev, pwritev, and mmap'd writes
  never cross it (the log lane may still catch them; the verdict
  names the gap); and the live lane collects over its duration —
  `holds --since 30s` waits 30 seconds, because the filter map only
  lets the queried file's events cross while the key is in the map.
  A ring read still consumes; the default build, and the feature
  build without a live chain, are the Phase 2 surfaces wrapped in
  the Ledger — byte-identical facts, verified against a Phase 2
  worktree (every holder, fd, mmap, cwd, size, perm, inode, actor,
  count, and note mapped into the new grammar, zero missing; the
  feature build's fallback renders byte-identical to the default
  build's).

  `why` gains `--since` with `--trace` (the explainability ladder:
  how zejtron knows each class of row — which probe, which parser,
  which fallback) and `--raw` (the kernel records as drained, for
  drill-down). The doctor's [eBPF] section renames its Tracepoints
  row to Probes and lists all four attach points; the pin set grows
  from six to thirteen (4 links, 4 programs, 5 maps).

- The help surface now teaches: every verb in the -h output carries
  a one-line example, and a Quick examples block at the bottom
  shows the five most useful invocations for a new user. Colors
  follow the tree's tier (green for primary, grey for secondary),
  degrade to plain text on pipe and under NO_COLOR. The flag list
  itself is unchanged; the examples were the missing piece. The
  verb about lines ride the same pass (night-improve-35): each
  description is reworded to the question the verb answers, so the
  example under it reads as the answer, and the example rows live
  in one data table whose completeness the tests pin — a verb added
  without an example row fails the suite.

### Changed

- journalctl is now a fallback lane, not the primary evidence path
  (night-improve-3): holds, touch, and why consult it (audit.log
  first, journalctl second) only when the kernel lane cannot serve,
  and its rows carry [inferred], never [observed] — the tag is the
  truth about the source, not marketing. The mode line names the
  lane that ran; the log lane's row actions are source-true (an
  audit record is `modified (audit log)`, a journal grep hit is a
  `journal mention` — the log cannot distinguish an open from a
  write, and the actions say so).
- `port` now shows the event window when the ebpf feature is built
  in and the chain is attached; snapshot-only otherwise — same
  output shape, richer evidence when the chain is live. The default
  build, and the feature build without a live chain, are
  byte-identical to phase 1 for any given host (the fallback
  contract: nothing degrades, nothing upgrades); `--events-only` on
  a run that cannot capture events prints the named refusal line
  instead of a fake empty window, and `--snapshot-only` is the
  phase-1 behavior in every lane.

- The release checksum lane's fast hash upgrades from BLAKE2b-512
  to BLAKE3: every release tarball now ships a `*.b3sum` sibling
  generated by the official `b3sum` utility (installed on the
  release runner from its own apt archive, Ubuntu 24.04 universe),
  replacing the retired `*.b2sum` files. The SHA-512 and SHAKE256
  lanes are unchanged, the release page's verification section and
  the docs tree tell the new file names and the `b3sum -c`
  verification command, and the asset-inventory tripwire pins the
  new suffix (night-weekly-maintenance-1).

- The README's pitch is sharpened: the consolidation table now
  names the origin projects by name (pidnest, Zenlixem) and a
  second table names the tools zejtron replaces (which, ss, lsof,
  ps, systemctl, journalctl, env). The "read-only" claim is
  qualified to "system files" so the env snapshot write is named
  honestly. The speed boundary is stated (kernel-native tools are
  faster for the single-question case; zejtron is the
  multi-question tool). MSRV is named from rust-toolchain.toml.
  A container-visibility limitation is added. No code, tests, or
  CLI surfaces touched.

  The README now says what it was already doing: the consolidation
  of pidnest and Zenlixem is named as history, the replacement of
  which/ss/lsof/ps/systemctl/journalctl is named as the pitch, and
  the boundary of the 'read-only' claim is the system, not the
  user's own state directory. The boring and serious surface tells
  the truth about its own shape.

- The `path` surface's package ownership on Arch reads
  `/var/lib/pacman/local` directly (each package's `desc` for the
  name and version, its `files` for the path list, walked lazily for
  the queried path - no whole-tree index, no pacman binary). An
  unowned file on an Arch host now prints "unowned by any package"
  - the database's own answer - where the old shell-out fell
  through to "unknown"; non-Arch hosts are unchanged (the
  dpkg/rpm/apk backends still shell out, and `/var/lib/pacman`
  absent means the pacman backend simply reports nothing). The row
  shape is unchanged. (night-improve-0)

### Removed

- The four wrapper subcommands: `env` (`--filter` was `env | grep`;
  `save`/`delete` wrote files - the only writes zejtron ever made;
  `diff` required persisted state a stateless tool does not carry),
  `shell` (`echo $SHELL`, `pwd`, `$0` - the shell already answers),
  `git` (shelled out to `git`, which is richer than any partial
  reimplementation), and `service` (shelled out to `systemctl`; a
  D-Bus client would be a new heavy dependency for state only
  systemd knows, and systemd ships `systemctl`). Running any of them
  now returns clap's standard unknown-subcommand error - no
  deprecation alias, that is the honest answer. The pidnest/Zenlixem
  migration redirects (whoholds, lasttouch, whyopen, envpath) are
  untouched and land on surviving surfaces.

  Four wrapper subcommands died today — env, shell, git, service.
  None of them read the kernel or the filesystem directly; each
  shelled out to a binary whose presence was guaranteed only when
  the wrapper's own dependency was already in use. The
  read-only-by-design claim is now literal: env save was the only
  write, and it is gone. The path surface replaces pacman -Qo with
  a native reader of /var/lib/pacman — one fewer external binary,
  one more source-of-truth read. External binaries: 5 → 4.

- night-improve-4 (Phase 4) lands the memory mystery's answer and
  its completing stream. `doctor --symptom <ram|slow|disk|network>`
  puts one flag on the doctor - no new verb, the surface count stays
  nine - and implements `ram` only: the report reads /proc directly
  (no eBPF, no capabilities, available to every `cargo install
  zejtron` user) and renders the Evidence Ledger grammar for RAM -
  per-process PSS (top 10, the proportional-set-size truth RSS
  overstates), tmpfs files with their holder pids (the view htop
  cannot produce), deleted-but-open files sized through the fd
  magic link, memfd files, page cache net of shmem, buffers, shmem,
  the top five slab caches (with the honest named absence when
  /proc/slabinfo is root-only), and the residual named unaccounted.
  The residual arithmetic sums the kernel-level buckets exactly
  once (tmpfs and memfd pages already ride them) so the 15 percent
  heuristic means something; every read another user's process
  refuses is counted by class (permission versus exited-mid-scan)
  and named in the Unaccounted block, never silently dropped;
  --raw appends the verbatim /proc reads for drill-down.
  slow/disk/network print the honest deferral line and exit 0 - not
  a stub, not a promise. `proc --live` completes the story: the
  sched_process_fork and sched_process_exit tracepoints join the
  tap (proctap.rs), the exec tap gains the event emission, and the
  lifecycle stream renders exec/fork/exit records with PID, comm,
  ppid (the fork tracepoint's own pair; the BTF-verified
  task_struct.real_parent walk for exec and exit), and the runtime
  a paired birth and death show - so a 4 GiB allocation that
  appeared and vanished within seconds can be named by PID, comm,
  and timestamp even though the process is already gone. The
  offsets map grows from eight to thirteen slots (the fork/exit
  tracepoint contexts and the task_struct pair, parsed from the
  host's own BTF at attach, hard refusal naming the missing struct
  - the Phase 3 pattern applied to tracepoint contexts), the pin
  set grows from thirteen to eighteen (one link/program pair per
  new tracepoint, the proc_events ring map), the lifecycle window
  rides the shared window grammar with its own clamp ([1s, 10m],
  default 30s), and the old refresh-loop --live dies honestly:
  --interval is gone, the snapshot-shaping flags are refused by
  name on --live, and the unused ctrlc dependency leaves the graph
  with the loop that needed it.

  The memory mystery has its answer: `zejtron doctor --symptom ram`
  reads /proc directly (no eBPF required) and names every consumer
  the kernel exposes — per-process PSS, tmpfs files with their
  holders, deleted-but-open files, memfd files, page cache, and
  slab — with the residual named as unaccounted. `proc --live`
  completes the story: from sched_process_exec, _fork, and _exit,
  the lifecycle stream names processes that have already exited,
  so a 4 GiB allocation that appeared and vanished within seconds
  can be named by PID, comm, and timestamp. Two fixes land
  alongside: the ebpf/Cargo.toml version mirrors the root crate
  (the mirror law restored), and `port --since` is honest about
  its window. The verdict engine names facts, never actions —
  zejtron remains read-only. When the user has the answer, they
  act manually; zejtron records, the user decides.

- The two publish blockers night-improve-3 carried: ebpf/Cargo.toml
  mirrored the stale 11.0.0 while the root crate moved to
  the alpha version (the mirror law broken since the alpha bump; the
  lockfile now mirrors it too, and the -V doc example renders the
  version shape as vX.Y.Z so it cannot go stale again), and
  `port --since` reported an instant ring read as a window -
  the event window now collects over its duration (the same
  grammar holds/touch/why speak: the wait IS the collection, the
  ring held open and drained in 100 ms slices), so a section
  labeled "last Ns" is backed by real observation, and
  --snapshot-only stays the instant path.

- `proc --live` and the sched_process_fork/_exit stream it drove
  are removed. zejtron is a read-only detective, not a monitor.
  The Evidence Ledger's --since windows on holds/touch/why/port
  survive because they collect evidence and report once — that is
  investigation, not surveillance. The trade-off is named honestly:
  processes that allocated memory and exited before the snapshot
  can no longer be attributed; the Unaccounted block in
  `doctor --symptom ram` says so.

  The removal is whole (night-improve-34): the `--live` flag and
  its `--watch` alias
  and the lifecycle `--since` window (clap's unknown-argument error
  is the answer - no deprecation alias), the two lifecycle
  tracepoint programs and the proc_events ring buffer (the object
  shrinks to four programs, five maps), the ProcEvent record and
  the drain_proc_events reader, the exec tap's event emission (the
  tap is the counter again - the chain proof the doctor reads),
  the five lifecycle pins (the set is thirteen: 4 links, 4
  programs, 5 maps), and the five process-stream BTF offset slots
  (the offsets map is the eight file-walk slots again, never
  renumbered). `sched_process_exec` stays: it increments stats[0],
  the counter is diagnostic, and the doctor's [eBPF] section still
  reads it. The prebuilt lane is regenerated in the same commit
  (the manifest's attach_targets list is the four remaining
  targets); the demo video of the removed surface
  (assets/demo-proc-live.webm) is gone with it, and the
  dependency audit's dead `ctrlc` row - its justification named
  the removed refresh loop - is dropped.

### Fixed

- The duration parsers saturate instead of overflowing
  (night-total-lts-1, the sharpest-skill depth audit's one real
  find). Both `--since` grammars multiplied the parsed u64 amount
  by the unit multiplier with plain `*`: recent's day arm by
  86400, the port window's hour arm by 3600. An absurd input
  (`--since 5124095576030432h` - exactly 2^64 seconds) wrapped to
  ZERO seconds in release builds: recent silently filtered to
  nothing-but-instant files, and the port window's clamp then
  shaped the wrapped zero into the 1s floor - an ask for the
  maximum window produced the smallest one. Debug builds (the
  test lane) panicked on the same input. Every arm now rides
  saturating_mul: an absurd age ask is "older than everything"
  (u64::MAX seconds), an absurd window ask saturates to the
  ceiling that clamp_window then shapes into the honest 1h
  maximum. Two regression tests pin the exact wrap-to-zero input
  and the saturate-then-clamp shape, one per grammar, alongside
  the existing sane-input pins (unchanged - no behavior moves for
  any in-range value).
- The README's Limitations list named two dead subcommands (`service`
  needing systemd/systemctl, `git` needing the git binary) and one
  dead verb in a survivors list (`env`) - all four wrappers died in
  phase 0 and no surviving surface shells out anymore. The list now
  names the surviving truth: no subcommand wraps an external tool,
  the nine surfaces read /proc and /sys directly, and the only
  optional external evidence sources are auditctl/journalctl and
  pacman.
- The name-case gate checked the sibling name (zylaxion) but not the
  project's own: a capitalized or all-caps form of the project name
  in any tracked file passed unnoticed - a gate gap that would have
  shipped to the first publish. The gate now enforces the lowercase
  law for both family names (docs/BRANDING.md section 7), and the 33
  stale capitalized occurrences it immediately caught - across the
  design docs, the branding prescriptions, the CLI about string, two
  source comments, and one workflow banner - were lowercased. The
  README, this changelog, and Cargo.toml were already clean; the
  lowercase convention the v80 passes wrote in is now the enforced
  law for every file the repo tracks.
- The doctor's proc_net check no longer false-alarms on an idle
  network namespace: the verdict now rides on how many /proc/net
  files are readable (the surface working), not on how many sockets
  the files carry. A fresh container netns reads every net file
  with zero socket rows and was reported FAIL for exactly that -
  the Container E2E lane's first real doctor run caught it, a run
  the lane could never reach before. FAIL stays reserved for the
  broken-procfs shape (not one net file readable); the OK and WARN
  message shapes are unchanged (night-weekly-maintenance-1).
- Attach refused on every kernel of the 6.18 line, observed live
  on the owner's own host (probed: 6.18.55-2-cachyos-lts): the BTF
  offsets parser looked for struct file's members among the
  struct's direct members only, and 6.18 wraps `f_path` inside an
  unnamed union (`const struct path f_path` beside a writable
  `struct path __f_path`, Al Viro's constification merged for the
  6.18 line), so the lookup answered "struct file has no member
  f_path in BTF" and the tap refused to plant - the refusal
  doctrine working exactly as designed against a kernel layout
  the parser had not been taught (night-improve-49, the
  anonymous-union descent). The member walk now descends
  anonymous struct/union members, and only those - `file->f_path`
  names a direct member or a member of an anonymous aggregate in
  C, never a named nested aggregate's field - resolving through
  const/volatile/restrict/typedef wrappers and accumulating bit
  offsets across the levels, so the eight probe offsets still
  come from THE HOST's own /sys/kernel/btf/vmlinux, never from a
  compiled-in guess. The refusal keeps both its law and its
  wording: a member still unfound after the descent is still the
  named error, and a bitfield found through the descent is still
  refused on its accumulated offset. The synthetic-blob pins
  grow the 6.18 shape (a full struct file whose f_path rides the
  union, parsed end to end through the same eight lookups the
  attach runs), the two-level offset accumulation through a
  const-wrapped inner aggregate, the named-aggregate guard, the
  refusal that survives a descent that finds nothing, and the
  accumulated bitfield refusal - built on the shared blob table
  the original pins built, now pub(super) for the flatten twin
  module (422 tests, +5).

## History

The changelog's per-era split, newest era first:

- This file — the fresh record: every entry since the v11.0.0 stable
  release (2026-07-09, "dragon hunts the meal").
- [docs/archive/CHANGELOG-V10.0.0-ERA.md](docs/archive/CHANGELOG-V10.0.0-ERA.md)
  — the v10-era record: the v5-line entries through the v11.0.0
  release, frozen at the night-improve-5 split (2026-10-17).
