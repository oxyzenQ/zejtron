<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# supermassive — the end-to-end depth suite

The pass that proves zejtron works. Every surface, every flag, every
error path, exercised against the REAL compiled binary — a shell
harness around the release build, not a unit test, not a smoke test,
not a single happy path. The name is the sibling projects' (zelynic's
and zylaxion's supermassive suites): not a gimmick — the proof.

## What "end to end depth" means here

For every one of the seventeen surfaces (path, recent, port, proc,
holds, touch, why, net, doctor, `doctor --symptom ram`,
`doctor --symptom cpu`, `doctor --symptom disk`,
`doctor --symptom network`, `doctor --symptom gpu`, `-h/--help`,
`-V/--version`, and the realtime storm):

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
   durations, gauges). Live kernel surfaces (port, proc, net,
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
  must NOT carry fake `[observed]` rows (that tag belongs to the tap
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
  (the tap names itself, the idempotent second attach, the real
  detach unpin, the pin directory gone) - a success on a host the
  harness reads as incapable is a loud failure, the binary
  attached where its own preflight must refuse.
- port --events-only: the event window must state its capture
  ability plainly (unavailable or observed — never a fake event
  table).

These checks are live on every host: on an unprivileged or
old-kernel runner they pin the honest unavailability rendering; on a
privileged 5.15+ host they pin the tap lane's declaration.

## Run it

```
./scripts/supermassive/legs/low.sh                 # 60s wall budget
./scripts/supermassive/legs/best.sh                # 300s wall budget
./scripts/supermassive/supermassive.sh --leg low --bin PATH   # explicit binary
./scripts/supermassive/supermassive.sh --self-test # the engine alone
```

The binary is NOT built by the suite: the suite exercises whatever
binary the caller hands it (default: `$ZEJTRON_BIN_PATH`, then
`target/release/zejtron`). The CI legs build first, then hand the
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
tap lane (the kernel-floor and witness micro-VMs, the owner's
laptop) the churn must be [observed] WHILE it happens - the
realtime claim, with the ledger's `wrote` rows and the raw lane's
op=write records - and on the snapshot lane the same load must
render the honest mode line with no fake [observed] rows, the
no-fabrication law live under concurrency, a stronger seat than
the idle-host version. The missing-path error path refuses by
name mid-storm, and the surface ends clean by its own
attach/detach hand (the tap it attached, the detach that unpins
it, the pin directory gone - the lifecycle the doctor surface
pins, re-proven under load). When the tap lane's write rows are
absent on a whole kernel generation (the 7.2 moving-latest
witness found exactly this on its first boot: the open and
writev lanes observed, the plain-write lane silent), the
failure carries its own post-mortem - the [observed] rows the
renders actually saw, plus the ftrace probe counts for one
controlled write where tracefs is writable (root inside the
witness VMs) - so a rerouted write path names the generation it
went silent on, never a bare FAIL (the named-never-swallowed
law).

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

- `.github/workflows/supermassive-e2e.yml` (two jobs: the
  low-spec leg on the MSRV floor, the best-spec leg on the stable
  frontier) - the surface depth, on the runner's own kernel.
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
