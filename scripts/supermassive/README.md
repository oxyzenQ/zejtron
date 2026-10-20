<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# supermassive — the end-to-end depth suite

The pass that proves zejtron works. Every surface, every flag, every
error path, exercised against the REAL compiled binary — a shell
harness around the release build, not a unit test, not a smoke test,
not a single happy path. The name is the sibling projects' (zelynic's
and zylaxion's supermassive suites): not a gimmick — the proof.

## What "end to end depth" means here

For every one of the twelve surfaces (path, recent, port, proc,
holds, touch, why, net, doctor, `doctor --symptom ram`, `-h/--help`,
`-V/--version`):

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
   top-level labeled lines, because their data rows move under the
   suite by definition. Both flavors are labeled in the check names.
6. **Color tri-test.** Three passes of the same invocation: piped
   (zero escapes on both streams), NO_COLOR (byte-equal to the piped
   pass, same exit status; normalized for gauge surfaces), forced
   truecolor (`CLICOLOR_FORCE=1` + `COLORTERM=truecolor` + a
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
  declarations on every host, whatever state they report.
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

- "root + BTF + kernel 5.15+ host" — the privileged attach leg
  belongs to the container lane; the host battery pins the refusal
  instead.
- "Cargo.toml not found next to the suite" — the version pin needs
  the tree.

Anything else that skips should be read as a question, not a pass.

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
by `.github/workflows/supermassive-e2e.yml` (two jobs: the low-spec
leg on the MSRV floor, the best-spec leg on the stable frontier).
