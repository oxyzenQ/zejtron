<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# supermassive — the end-to-end depth suite

The pass that proves zejtron works. Every surface, every flag, every
error path, exercised against the REAL compiled binary — a shell
harness around the release build, not a unit test, not a smoke test,
not a single happy path. The name is the sibling projects' (zelynic's
and zylaxion's supermassive suites): not a gimmick — the proof.

## What "end to end depth" means here

For every one of the eighteen surfaces (path, recent, port, proc,
holds, touch, why, net, doctor, `doctor --symptom ram`,
`doctor --symptom cpu`, `doctor --symptom disk`,
`doctor --symptom network`, `doctor --symptom gpu`, `-h/--help`,
`-V/--version`, the realtime storm, and the server incident
simulation):

1. **Real invocation.** The actual compiled binary, called by the
   suite. Assertions pin exit codes, not just "it ran".
2. **Success path.** Valid input, and the render's STRUCTURE pinned:
   section headers present, verdict lines present, never all-white
   content.
3. **Error path.** Invalid input, the exact exit contract (clap
   usage errors exit 2, runtime failures exit 1, and the one honest
   exception: a missing `path` argument is a REPORT, exit 0), and
   the error NAMED by its message (`invalid port`, `path not
   found`, `attach refused`, ...).
4. **Flag coverage.** Every documented flag exercised at least once.
   Flags nothing exercised are printed as UNTESTED by name at the
   end of the run — the honest gap report, never a silent skip.
5. **Determinism.** Same host state + same invocation = same bytes,
   modulo a documented volatile-field table (timestamps, PIDs,
   durations, gauges, the presence-volatile unreadable-process note
   that live process churn toggles between two adjacent runs). Live
   kernel surfaces (port, proc, net,
   doctor) use structural determinism: the stable skeleton of
   top-level labeled lines plus the report frame's furniture (the
   heavy-bar banner, bracket-led section headers, indented colon-key
   rows), because their data rows move under the suite by
   definition. Both flavors are labeled in the check names.
6. **Color tri-test.** Three passes of the same invocation: piped
   (zero escapes on both streams), NO_COLOR (byte-equal to the piped
   pass, same exit status; normalized for gauge surfaces, stable
   skeleton for rank-sampled ones whose row order follows the moving
   gauge), forced truecolor (`CLICOLOR_FORCE=1` + `COLORTERM=truecolor` + a
   recognized `TERM` carries 24-bit RGB escapes and is NOT
   byte-identical to the plain pass). The capability ladder these
   tests pin lives in `src/output/mod.rs`; the 16-color forced floor
   gets its own check on the help surface.

## The dormant build (why there isn't one)

The sibling projects' suites exercise a `--no-default-features`
"dormant" build. zejtron does not have one, by owner law:
`Cargo.toml` (night-weekly-maintenance-1, the "always enable,
permanent" law) made aya a plain dependency — there is no
`[features]` table and NO build flag can produce a dormant binary. A
suite leg that pretended otherwise would be exactly the gimmick this
suite exists to prevent.

The honest substitute is the LANE-HONESTY checks, which every
surface file carries where a lane applies:

- holds / touch / why: the Mode line must declare the lane that
  actually ran, and while the snapshot lane is active the render
  must NOT carry fake `[observed]` rows (that tag belongs to the probe
  lane only).
- doctor: the `[eBPF]` section must render its Feature and Lane
  declarations on every host, whatever state they report
  (night-improve-43 grows the estate): the section's full row
  estate (Kernel, BTF, Lockdown, Caps, Probes, Pins) must render
  its keys on every host; the Probes row must carry the five probe
  names in planting order (the binary's contract, not host state);
  and the kernel-floor agreement check reads
  /proc/sys/kernel/osrelease on the harness side and holds the
  Lane row to the documented 5.15 floor from BOTH sides of the
  line - at or above the floor no false floor refusal, below the
  floor the refusal names the floor (and `doctor --attach`'s
  refusal names it too). No stock GitHub runner ships a
  below-floor kernel (the ubuntu images ride 6.x HWE kernels), so
  the ordinary CI legs pin the at/above direction; the below-floor
  direction pins itself wherever a maintainer runs the suite on an
  old-kernel host. The attach lifecycle itself is pinned from BOTH
  directions too: the refusal contract on incapable hosts, and on
  a host the harness proves capable (floor met + BTF readable +
  CAP_BPF/CAP_PERFMON in the effective set) the success contract
  (the probe names itself, the idempotent second attach, the real
  detach unpin, the pin directory gone) - a success on a host the
  harness reads as incapable is a loud failure, the binary
  attached where its own preflight must refuse.
- port --events-only: the event window must state its capture
  ability plainly (unavailable or observed — never a fake event
  table).

These checks are live on every host: on an unprivileged or
old-kernel runner they pin the honest unavailability rendering; on a
privileged 5.15+ host they pin the probe lane's declaration.

## Run it

```
./scripts/supermassive/legs/low.sh                 # 60s wall budget
./scripts/supermassive/legs/best.sh                # 300s wall budget
./scripts/supermassive/supermassive.sh --leg low --bin PATH   # explicit binary
./scripts/supermassive/supermassive.sh --self-test # the engine alone
```

The binary is NOT built by the suite: the suite exercises whatever
binary the caller hands it (default: `$ZEJTRON_BIN_PATH`, then
discovery in `target/` through the shared resolver
`scripts/lib/zejtron-bin.sh` - the custom cargo profile dirs first
(the alias lanes, e.g. `target/pro-linux-amd64-v3-musl/zejtron` or
`target/x86_64-unknown-linux-musl/pro-linux-amd64-v3-musl/zejtron`),
the basic `release`/`debug` lanes last; newest binary within a
tier). The CI legs build first, then hand the
binary to the leg script. A missing binary is a hard error with a
build hint — never a skip.

## What a SKIP means

A SKIP is allowed only when the host genuinely cannot run the check,
and EVERY skip names its reason in the log. A bare SKIP is a harness
bug (the engine converts it to a failure by law). Known legitimate
skips:

- "Cargo.toml not found next to the suite" — the version pin needs
  the tree.
- "/proc/sys/kernel/osrelease unreadable" — the kernel-floor
  agreement (night-improve-43) cannot compute the floor direction
  without the same file the binary reads.

Anything else that skips should be read as a question, not a pass.

The privileged attach leg (root, BTF, kernel 5.15+, on the host
kernel) HAS a seat now, and the seat is the kernel-floor micro-VM
lane (night-improve-43): `.github/workflows/
supermassive-kernel-floor.yml` boots the REAL jammy GA 5.15.0
kernel (linux-image-unsigned-5.15.0-25-generic, the exact
documented minimum) in a KVM micro-VM on the runner and runs the
full low leg inside it as root - the one CI place where attach
can succeed for real, which is exactly why the doctor surface's
attach specs grew the success-direction contract the same night.
The local twin is `scripts/sandbox/zejtron-sandbox.sh` (the same
boot shape, rootless-packed, KVM when `/dev/kvm` is writable, TCG
software emulation otherwise). This entry replaces the stale
"the privileged attach leg belongs to the container lane" claim
(night-total-lts-2): the container lane runs unprivileged docker
and never attached - the claim documented a leg that did not
exist until the micro-VM lane built one.

The realtime storm surface (night-improve-51) is the depth
contract's realtime leg - the owner's ask that the E2E suite prove
the binary under concurrent load, not only at rest. Four churn
writers run a fixed six-second window of plain write(2) appends
while the poller asks `why` about the hot files mid-storm: on the
probe lane (the kernel-floor and witness micro-VMs, the owner's
laptop) the churn must be [observed] WHILE it happens - the
realtime claim, with the ledger's `wrote` rows and the raw lane's
op=write records - and on the snapshot lane the same load must
render the honest mode line with no fake [observed] rows, the
no-fabrication law live under concurrency, a stronger seat than
the idle-host version. The missing-path error path refuses by
name mid-storm, and the surface ends clean by its own
attach/detach hand (the probe it attached, the detach that unpins
it, the pin directory gone - the lifecycle the doctor surface
pins, re-proven under load). The runner closes the loop both
ways: leftover pins are detached at startup (the lane
normalization law) and the post-leg cleanup guarantee re-checks
at shutdown - a pin directory that survives the suite's own
detach is a recorded FAIL, and a bare wait reaps any surface
child that outlived its surface. When the probe lane's write rows are
absent on a whole kernel generation (the 7.2 moving-latest
witness found exactly this on its first boot: the open and
writev lanes observed, the plain-write lane silent - and ftrace
proved write(2) crosses neither vfs_write nor vfs_writev on that
build), the failure carries its own post-mortem - the [observed]
rows the renders actually saw, the kallsyms census of the write
family (compiler clones included), the ftrace-available list, and
probe counts for one controlled write across the whole family
(where tracefs is writable, root inside the witness VMs) - so a
rerouted or cloned write path names itself in one round, never a
bare FAIL (the named-never-swallowed law).

The server incident simulation is the suite's scenario leg. As
night-badass-8 it staged one rogue: a single process on port 9999
holding 100 MiB. Night-dragon-4 upgrades it to the ultra-scale
inferno — a full host under fire that would crash or OOM a normal
monitoring tool, staged by the surface itself and survived by the
detective: 2000 dummy processes (`sleep 300`), a 500-rogue python3
fleet — four HEAVY rogues on the deterministic table
20000/20017/20033/20050 (the :20050 pin is the night-dragon-2
contract), each holding 200 MiB so the fleet cracks a busy host's
top-10 RAM table (the night-dragon-3 finding), plus 496 LIGHT rogues
on kernel-assigned random ports carrying a governed buffer — one
holder keeping 2000 read descriptors open (the soft ceiling rises to
the hard limit inside the holder), a 500 MiB dd I/O burst written by
ONE dd process that reads stdin fed by a fork-free printf feeder
(the night-dragon-3 post-mortem: a feeder piped into
`dd if=/dev/zero` paced nothing, because dd ignores stdin when if=
is given — the writer finished inside a second and the live lane's
why render found a cold trail), and a bounded localhost socket
storm. Two governors keep the inferno honest about its host: the
fork governor fits the fleet into the task budget (threads-max minus
the live tasks; a budget under the floor is a named SKIP, a smaller
budget scales the fleet down, named), and the memory governor caps
the python fleet at 60% of MemAvailable — the night-dragon-4 letter
(500 x 20 MiB) is 16 GiB of resident python on a 16 GiB runner, so
the fleet's COUNT is the scale law and the buffer adapts, clamped at
the spec's own 20 MiB, every scaledown named. Each rogue carries a
RLIMIT_AS backstop and the staging preflight demands 2 GiB
MemAvailable before anything spawns — the runner cannot be OOMed by
this surface. Under that fire, on the typed JSON lane
the automation contract pins: `proc --me --print-json` must finish
in under 1 second (measured with EPOCHREALTIME, the forkless clock
— a forked `date` lies under fork pressure) and capture more
processes than the spawner staged (at full spec scale that is the
> 2000 law); `port 20050 --print-json --snapshot-only` must name
the pinned heavy rogue as the listener's owner (the window law:
--snapshot-only returns instantly, the owner rows resolve from
/proc either way); `doctor --symptom ram --print-json` must rank
the heavy fleet above the 100 MB bar: at least one census row per
heavy rogue carrying PSS above the bar (the process table is a
top-10 census, so a fat desktop's own consumers can crowd a live
rogue out of the named rows while it holds every byte — the
night-dragon-5 live finding), and the harness picks the read's
moment: a bounded readiness gate polls each heavy rogue's
smaps_rollup Pss until all four clear the bar (one 0.25s beat at
a time, 3s of patience, early exit the beat all four are fat — a
busy desktop boots its interpreters under load, and a rogue
mid-allocation is a rogue the census has not met yet); the
per-rogue teeth stay (the first named heavy rogue clears the bar
by pid);
`why <io file> --since 2s --print-json` must ride the live lane
(gated on the `doctor --attach` preflight, the refusal direction
staying the storm surface's contract) and attribute the writes to
dd by name and pid, the dd actor on the measured state rows and
the observed provenance on the changes rows ([observed] is the
kernel lane's event tag and never a state row's — the
night-dragon-5 finding; the report's snapshot facts and its
kernel-event facts are different arrays and the asserts read
each where it lives) — every filter a typed jq check on the flat
Spec v3 grammar, every lane pure-JSON on stdout and silent on
stderr. The teardown is a check, not a hope: TERM, a
grace beat, KILL, a bare wait that reaps every child, and a /proc
sweep asserting zero zombies among the tracked pids. The surface
ends with the massive-scale report — one line carrying the real
tallies (dummies, rogues, fds staged, socket connects, the measured
proc latency under fire), computed from sidecars, never from
constants — the CI log's badge for the leg. Every staged actor is
self-bounded by its own sleep or loop bound; a host without python3
or dd, under the staging memory bar, under a task budget below the
fleet floor, with a rogue port already bound, or under an fd ceiling
below the storm, skips (or scales down, named) with the reason
named; any other rogue death is a FAIL. The JSON assertions
are typed (night-dragon-4): every `--print-json` lane must return
pure JSON on stdout with silent stderr, and the shape checks ride
`jq` filters on the flat Spec v3 grammar - jq is a harness-side
dependency only (the runner refuses to start without it); the
binary itself stays jq-free.

The local twin grew the arbitrary-kernel lane for the same
reason: `--kernel PATH` boots any vmlinuz the operator chooses,
the init reports the floor direction instead of gating the
identity, and the suite adapts by its own capability computation
- proven live on the REAL focal GA 5.4.0-26 (below the floor,
no BTF: the attach specs run the refusal direction, 276/276) and
on the floor kernel itself via PATH (280/280, the success
direction).

The witness presets name the GA suites so the operator never
hands the instrument a PATH by hand: `--kernel focal`, `--kernel
jammy`, `--kernel noble` resolve that Ubuntu suite's GA
release-day kernel from the LIVE archive's main pocket (the GA
suite frozen by archive policy; verified live against the
pockets: focal 5.4.0-26.30, noble 6.8.0-31.31) through the
packer's one suite table. Proven live the same night, all three
sides of the floor line, under TCG (KVM is the CI lane's
contract): focal 5.4.0-26 BELOW the floor - 276/276, the attach
specs in the refusal direction, 11s wall of the 60s budget;
jammy 5.15.0-25 at the floor - 280/280, the success direction,
12s; noble 6.8.0-31 ABOVE the floor - 280/280, the privileged
attach lifecycle in the success direction on a second kernel
generation, 19s.

The cachyos preset (night-improve-53) is the moving-latest
witness - the owner's own distro line, unpinned: the packer
resolves the repo's CURRENT flagship kernel (linux-cachyos,
resolved live at 7.2.7-1) and re-checks the repo index on every
call through the .ver sidecar, so the witness can never boot a
stale "latest"; it rides the best envelope (every core / three
quarters RAM), the newest-software half of the suite's low/best
span. The boot proof rides CI (the witnesses lane boots it under
KVM on the best envelope); the resolution itself is proven live
on the development box - the fetch through the repo's CDN (the
named User-Agent the bare python-urllib agent needs), the
arch-layout extraction (usr/lib/modules/<version>/vmlinuz - the
package ships no /boot entry), and the cache-reuse path.

## The exit code

- `0` = every check passed or skipped WITH its named reason, and the
  wall budget held.
- `1` = any check failed, OR the leg breached its own wall budget.

Both legs (low and best) run the IDENTICAL surface list and check
depth. The budget buys headroom, never depth: best is faster, not
deeper, and low is never shallower.

## Where it runs

Not part of `cargo test` — cargo test covers units, supermassive
covers the binary a user actually runs. The suite is wired into CI
by four lanes:

- `.github/workflows/supermassive-e2e.yml` (three jobs: the
  low-spec leg on the MSRV floor, the best-spec leg on the stable
  frontier, and the titled server-simulation showcase lane, the
  best leg filtered to the one surface) - the surface depth, on
  the runner's own kernel.
- `.github/workflows/supermassive-kernel-floor.yml` (the micro-VM
  lane, night-improve-43) - the full low leg booted inside the
  REAL jammy GA 5.15.0 floor kernel in a KVM micro-VM, as root:
  the at-floor direction of the kernel-floor agreement, LIVE, and
  the one CI seat where the privileged attach lifecycle runs for
  real. No stock GitHub runner ships a 5.15 kernel (the ubuntu
  images ride 6.x HWE kernels), so the floor is booted, not
  assumed.
- `.github/workflows/supermassive-kernel-witnesses.yml` (the
  report lane) - the GA kernels on either side of the floor line
  (focal 5.4.0 below, jammy 5.15.0 at, noble 6.8.0 above), the
  FULL low leg per witness in report mode, per push, through the
  local twin's own code path - one implementation, two seats, so
  CI cannot drift from the operator's instrument.
- the local twin `scripts/sandbox/zejtron-sandbox.sh --battery` -
  the same VM on a developer box (KVM when `/dev/kvm` is
  writable, TCG software emulation otherwise; under TCG the low
  leg's 60s wall budget can breach without the binary being at
  fault - the budget is a real-hardware contract).

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
