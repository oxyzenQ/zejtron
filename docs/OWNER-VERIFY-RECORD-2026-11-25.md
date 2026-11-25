<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->

# The Owner-Verify Record, Closed (2026-11-25)

The manual lane (night-witness-pids) ran its full owner-verify on the
host's own kernel three times in one day, and the third run closed
every row the audit list asks for: the planted hide rendered by the
live camera, the hidden-pids entry typed and counted, the pins swept
by the project's own detach. This record is the release-side summary
the protocol promised; the raw results directories stay gitignored
residue (the dist/ class - a product of the machine, never a commit).

## The runs

- **Host:** nightpc (rezky) · **Kernel:** 6.18.60-3-cachyos-lts ·
  **Lane:** `sudo bash scripts/release/owner-verify.sh`
- **Binary under test:** `/usr/bin/zejtron`, `v80.6.0-dragon.1`,
  built from `6e0e3dd` (`local-pro-linux-amd64-v3-musl`, 2026-11-25
  14:33Z) - constant across all three runs; every fix in between was
  script-side, and each run's build-sha ATTENTION (binary vs
  checkout) names that shape honestly.
- **Run 1 - `owner-verify-20261125T143553Z` (checkout `6e0e3dd`).**
  The runner's first real-machine run caught the runner's own bug:
  `runlog` shifted twice - the step name, then the binary - so every
  zejtron step executed its bare arguments as commands (rc=127). The
  five z11 legs still PASSED 5/5 (the detector lane rides its own
  mechanism, not the broken helper), and the manual ride planted
  marker pid 48316 with the `/proc`-vs-listing disagreement live.
  The honest-failure rule held: every red line was a finding, and
  the finding was true. Fixed as `6d4f041`.
- **Run 2 - `owner-verify-20261125T145204Z` (checkout `6d4f041`).**
  All formerly-broken rows pass: version, the `sig` REFUSED row (the
  designed fail-closed shape on an unsigned dev HEAD), doctor
  (ok=11 warn=1 - the audit-log WARN is the host's own truth), the
  negative control `unaccounted: []` PASS. The z11 legs PASSED 5/5 a
  second consecutive time. One finding left: both `why` windows rode
  `"journal fallback"` and honest-emptied while the hide was LIVE -
  the ladder law (`src/commands/lane.rs`) reads the pins when they
  are present and never attaches lazily, and the detector's section-4
  detach had removed every pin. The marker loop's 50ms write stream
  went unwitnessed by every lane. Fixed as `d95d320`: the ride
  re-arms with `doctor --attach` before the plant - the same seat
  leg-b rides.
- **Run 3 - `owner-verify-20261125T153617Z` (checkout `d95d320`).
  The closed run.**

## Run 3, by the numbers

- `doctor --attach` rc=0: 12 programs, 12 links, 8 maps - Lazy
  Camera recording; the results carry the `lane re-armed` note.
- Loader planted marker pid 72760; `/proc/72760` resolved while the
  listing omitted it - the disagreement the windows render.
- The text window rendered the live stream: hundreds of
  `[observed]` `opened`/`wrote` rows, every one actor
  `sh (pid 72760, root)`.
- Text unaccounted: `390 hidden pids` - `the 390 events carry
  1 distinct pid; sample: pid 72760 x390`.
- JSON window (`mode: live`): `count 362`, category `hidden pids`,
  `1 distinct pid` - the second window's own watch after the first
  drained (the drains-on-read semantics, demonstrated, not claimed).
- The honesty row the window prints on its own leading edge:
  `1 pre-attach watch gap` - the requested window began 8s before
  the camera was planted, and no event can exist in a span nothing
  watched.
- The verdict's cannot-support line names what no write probe can
  see: mmap'd writes, async kiocb (io_uring/AIO), splice-class
  copies.
- Math block: **EVENTS 362 / DISTINCT 1** - the audit question
  (events vs processes) answered by the entry's own sample clause.
  The rows-vs-clause cross-check printed 0 against the clause's 1:
  the pattern matched neither render shape - fixed as the rowfix
  commit alongside this record.
- Step 6: `doctor --detach` removed **28 real pins** (the bpf-rm
  law exercised on every run now, not skipped as "nothing to
  detach"); the pin estate absent, no pidhide processes remain.

## What this record closes, and what it leaves open

Closed: the manual lane's owner-verify record - five legs green
(three consecutive real-machine runs), the planted hide caught by
the live camera and counted honestly, the cleanup verified, every
row's full output teed to the results directories.

Open (the release list): the D5 commit-signature row REFUSED by
design on this unsigned dev HEAD - the release closes it through the
pinned maintainer key (`47A50AEF4B65AAC2`, docs/VERIFY_RELEASE.md):
sign the release commit or cut the release from a signed tag, rebuild
from that commit, and the D5 row verifies at build time. The version
bump stays owner-reserved. Until then, `sig`'s refusal is the
provenance chain telling the truth about itself.
