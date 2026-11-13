<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# night-cafe-1 - the shell palette, the artifact walls, and how to verify both locally

Task date: 2026-11-13. This document is the handoff for the night-cafe-1
session on zejtron: what changed, why each change is load-bearing, and the
one-command local verification. The reference for the shape is the sibling
repo's `scripts/labs-exp/VERIFY_LOCAL_HARDENING_1.md`; the reference for
the palette is the sibling's `scripts/lib/ux_palette.sh` - the bash twin
of its CLI's color tiers.

## The task in one paragraph

night-cafe-1 makes the SCRIPT surfaces match the CLI, and makes local
binaries impossible to leak into git. Two laws, both already true of the
sibling repo, both now mechanically true of zejtron:

1. The palette law: every owner-facing script surface renders the SAME
   color tiers the CLI renders (`src/output/mod.rs`'s `Tier::open`
   table), at the depth the terminal actually supports, and plain text
   when piped - byte-identical to the previous plain render in mono, so
   no existing grep, test, or CI consumer sees a single different byte.
2. The artifact law: a locally built or patched zejtron binary is a
   product of the machine, never a tracked file. The tracked lane is the
   packaged pair - the `.gz` archive and its `.b3sum` sidecar - so
   another machine verifies what it receives without trusting raw bytes
   in git.

## What is in this change set

| File | Permissions | Purpose |
| --- | --- | --- |
| `scripts/lib/ux_palette.sh` | 644 | The shell brand palette: `UX_BRAND` #A855F7, `UX_OK` #50FA7B, `UX_ERR` #FF5A5A, `UX_WARN` #FFEB3C, `UX_GREY` #8B8B8B, `UX_WHITE` #DCEBFF, `UX_RESET`. Sourced, never executed (no shebang, the lib law). The depth ladder mirrors the CLI's capability probe. |
| `scripts/package/pack-local.sh` | 755 | The packaging law's producer: packs a raw binary into the `.gz` + `.b3sum` pair (gzip -9 -n for diff-stable archives), proves the round trip and the sidecar, and probes the `.gitignore` walls as part of its verdict. |
| `.gitignore` | - | The walls: `scripts/labs-exp/zejtron-fixed-*` ignored at any suffix shape; the `.gz` and `.b3sum` sidecars of the same names negated back to trackable; `dist/` staging ignored. |
| `scripts/labs-exp/zejtron-cli-ux-verify.sh` | 755 | Wired: PASS/FAIL verdicts in green/red, section rails in brand purple, the summary line in crystal white, refusal lane in red. Piped output unchanged. |
| `scripts/labs-exp/zejtron-forensic-proof.sh` | 755 | Wired: the pass/fail helpers, the refusal and stale-build lanes, the section rails. Piped output unchanged. |
| `scripts/labs-exp/verify-night-cafe-1.sh` | 755 | The verification lab - see below. |

## The tier contract (one palette across the family)

| Tier | RGB | 256 rung | 16 rung | Seat |
| --- | --- | --- | --- | --- |
| `UX_BRAND` | #A855F7 | 135 | 35 | banners and section rails |
| `UX_OK` | #50FA7B | 84 | 32 | affirmative verdicts, PASS lines |
| `UX_ERR` | #FF5A5A | 203 | 31 | failures, refusals, violations |
| `UX_WARN` | #FFEB3C | 220 | 33 | cautions and non-fatal drift |
| `UX_GREY` | #8B8B8B | 245 | 90 | labels and grammar ("context, not content") |
| `UX_WHITE` | #DCEBFF | 255 | 97 | the script-side emphasis seat |

The five tiers the CLI carries match the CLI byte-for-byte at every
depth - the RGB triples, the 256 rungs, and the 16 rungs are the CLI's
own documented fallbacks in `src/output/mod.rs` (`Tier::open`). The
crystal-white seat is the sibling's ladder addition: the CLI keeps KV
values on the terminal default (the field law - values are the data the
user came for), so a script uses `UX_WHITE` sparingly, on the one line a
surface must out-shout (a verdict summary), never on KV values.

The depth ladder, probed once at source time:

| Condition | Result |
| --- | --- |
| `NO_COLOR` set, or `CLICOLOR=0` | mono (every tier is the empty string) |
| stdout not a TTY, unless `CLICOLOR_FORCE=1` | mono |
| `COLORTERM=truecolor/24bit`, `TERM` `-direct`/`-truecolor`, or a truecolor-native terminal name | RGB escapes |
| `TERM` carries `256color` | the 256 rungs |
| anything else | the 16 rungs |

## How to verify locally

One command:

```
scripts/labs-exp/verify-night-cafe-1.sh
```

Exit code 0 = all green. The lab needs no root and no built binary.
What each section proves:

- A1: the palette lib exists at the sourced-lib shape (644, no shebang).
- A2: the mechanical parity proof - the lab re-derives the escape
  tables from `src/output/mod.rs` and from the palette lib and diffs
  them. The five CLI tiers must be a byte-for-byte subset at every
  depth; the only allowed additions are the crystal-white rungs. A
  future edit to either side that drifts one byte fails here.
- A3: the depth ladder exercised in four forced lanes (NO_COLOR mono,
  `COLORTERM=truecolor`, `TERM=xterm-256color`, forced-dumb 16 floor).
- B1: the artifact walls probed with `git check-ignore` - the raw name
  class ignored, the `.gz`/`.b3sum` sidecars trackable, `dist/` ignored.
- B2: one real `pack-local.sh` pack on a copy of `/bin/true` under a
  lab-owned name, the sidecar verified, then everything the lab
  produced removed (leave-as-found). Without `b3sum` on PATH this
  section names itself skipped - install the digest tool with
  `cargo install b3sum` for the full verdict.
- C: the wiring - the three owner-facing surfaces must source the lib.

## The packaging workflow this change set prescribes

A local hardening drop (a fixed or patched binary) lands like this:

```
# pack: raw binary in, verified pair out (walls probed as part of it)
scripts/package/pack-local.sh target/release/zejtron zejtron-fixed-cli-hardening-1

# on another machine: verify the bytes before running them
b3sum -c scripts/labs-exp/zejtron-fixed-cli-hardening-1.b3sum
gunzip -c scripts/labs-exp/zejtron-fixed-cli-hardening-1.gz > zejtron
chmod 755 zejtron
```

The raw binary stays a local file (already git-ignored under its name
class); the pair is what a commit carries. The archive is timestamp-free
(`gzip -n`), so re-packing the same bytes yields the same archive bytes
and a clean diff.

## What was deliberately NOT changed

- The CLI's Rust color table: it already matched the sibling's palette
  values exactly (the parity lab proves it mechanically); no Rust change
  was justified, so none was made.
- The CI/gate scripts: they run piped, where the palette is mono by
  design - painting them adds bytes for no viewer. The owner-facing
  local surfaces are the seats that pay for the palette.
- The eBPF prebuilt lane (`ebpf-prebuilt/zejtron-ebpf.o`): a manifest
  pinned, blake3-gated build input the registry lane embeds by design -
  tracked on purpose, with `scripts/gates/check-commit-gate.sh` and
  `scripts/dev/regenerate-ebpf-prebuilt.sh --check` guarding its pins.
  It is not the local-artifact leak class night-cafe-1 closes.
