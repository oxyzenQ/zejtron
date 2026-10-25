<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# zejtron Brand Guidelines

This document defines the visual identity and communication standards for the zejtron project. It ensures consistent branding across all touchpoints — from the GitHub repository to the CLI output and documentation.

---

## 1. Brand Identity

**zejtron** is a lightweight, efficient terminal utility. The brand reflects:

- **Simplicity** — focused functionality
- **Performance** — fast, Rust-powered execution
- **Utility** — practical, everyday terminal enhancement

---

## 2. Name Usage

The project name is **zejtron** (all lowercase) in every context —
prose, titles, headings, code, CLI output, comments, commit subjects,
and file paths. There is no context where a capital first letter or
an internal capital is correct, including the start of a sentence.

| Context | Format |
|---|---|
| Running text / prose | zejtron |
| Titles / headings | zejtron |
| Code / CLI | `zejtron` (lowercase) |

The one uppercase family that survives is identifiers, never the
name itself: the `ZEJTRON_*` environment variables and build stamps
(`ZEJTRON_GIT_HASH`, `ZEJTRON_BUILD_TIME`, ...), plus the all-caps
banner comment titles heading the scripts/ gate files — shell and
identifier conventions, not brand displays.

Incorrect forms (the name-case gate rejects every one of them):

- a capitalized first letter, or any internal capital, in any
  context — even at the start of a sentence;
- all-caps prose uses outside the identifier family;
- derivative forms with a suffix glued to any casing of the name.

Since night-improve-1.5 the rule is machine-enforced for this name
exactly as it already was for the sibling name (section 7 below).

---

## 3. Logo

### 3.1. Logo file

The official logo is located at [`assets/zejtron-logo-new.png`](assets/zejtron-logo-new.png).

### 3.2. Usage rules

- **Clear space**: maintain padding equal to at least 25% of the logo height on all sides
- **Aspect ratio**: always preserve the original aspect ratio — do not stretch or distort

---

## 4. Tone of Voice

zejtron's communication should be direct, technical, and helpful.

- **Factual** — describe capabilities clearly
- **Concise** — respect the user's time
- **Professional** — maintain technical accuracy

---

## 5. Color System

The CLI speaks one palette on two surfaces, both anchored to the same values:

| Tier | Value | Surface |
|---|---|---|
| Brand purple | `#A855F7` (168,85,247) | clap headings (`Usage`, `Commands`, `Options`) in `-h`/`--help` and errors; the report banners (`━━━ ... ━━━`, bold) on the doctor and the update check; the `-V` version-report header - name, version, and description in one regular-weight wrap (256-cube index 135, the sibling default theme's exact index for this RGB) |
| Calm grey | `#8B8B8B` (139,139,139) | the self-painted grammar rows - the Pro mode flag estate, the example lines' lead-in and argument spelling, the `valid` suggestion candidates - plus timestamps, tree glyphs, footers, and the weaker provenance tags on the data surfaces |
| Error red | `#FF5A5A` (255,90,90) | the `error:` label (bold) and body of every runtime error; clap error labels; the doctor's `FAIL` status token (bold) |
| Warning yellow | `#FFEB3C` (255,235,60) | invalid-input highlights on the clap lane; the doctor's `WARN` status token (bold), the unprivileged `Mode:` verdict (bold), and degraded `[eBPF]` verdicts (bold); the update check's "update available" verdict (bold) |
| Status green | `#50FA7B` (80,250,123) | affirmative verdicts (bold): the doctor's `OK` status token and privileged `Mode:` verdict, the `[eBPF]` section's `enabled`/`present`/`live`/`none` verdicts, the update check's "up to date" verdict; regular weight carries the tree node labels, the verb tokens and example commands on the help surface, and the strongest provenance tags |

The report frame (night-weekly-maintenance-2, the sibling project's
masterclass law): every report surface opens with the `━━━ <title> ━━━`
banner in bold purple, and lays its facts out as KV rows whose keys
stay plain (aligned to one column) while the values carry the tiers.
Verdict tokens ride the bold tiers; keys are the frame, never the
paint. The `-V` body renders plain everywhere - the sibling's version
law: the header carries the purple, the build facts a script greps
carry nothing. clap's own rendered literals (verb names and flag
spellings in Usage, Commands, Options) ride bold in the terminal
default color - the sibling's clap contract; the grey grammar tier
stays the seat of the rows zejtron paints itself.

One ladder, the sibling's rungs byte-for-byte: the 256-color rung
carries the sibling's exact cube indexes (error 203, warn 220, ok 84,
brand 135, grey 245) and the 16-color floor its exact SGR slots
(error 31, ok 32, warn 33, brand 35, grey 90) - one tier is one color
on every rung in both projects.

Implementation: the clap lane renders through `src/cli/styles.rs`, the
runtime lane through `src/output/mod.rs`; one palette, two modules.

Capability ladder (the runtime lane): TrueColor 24-bit when
`COLORTERM=truecolor/24bit` or the terminal names a truecolor-native
emulator; 256-color (nearest cube index) when `TERM` carries
`256color`; plain text otherwise - `NO_COLOR`, `CLICOLOR=0`,
`TERM=dumb`, a non-terminal stderr (unless `CLICOLOR_FORCE=1`), or an
unrecognized terminal all render byte-clean plain text. Piped output
never carries escape bytes.

Deliberately uncolored: "No X found" empty-result lines (informational,
not errors) and content facts such as touch's `actor: unknown` - tiers
mark verdicts, not prose.

---

## 5.1 The Civil Clock (UTC Markers)

Every wall-clock surface renders through `src/clock.rs` - Howard
Hinnant's `civil_from_days` algorithm on `std::time` only, no time
crate, no timezone database in the binary:

- `-V`/`--version` carries `Build-time: M/D/YYYY HH:MM (UTC)`, stamped
  by `build.rs` at compile time (minute precision, identical across
  build hosts).
- `touch` evidence timestamps render as
  `YYYY-MM-DD HH:MM:SS (UTC)` - the tree's long-standing zero-padded
  core with an explicit UTC marker instead of a silently wrong local
  guess on hosts without a timezone database (containers included).
- The doctor's `build_meta` row appends `built <stamp>` from the same
  compile-time source.

---

## 6. Third-party Usage

External projects or articles referencing zejtron should:

- Use the correct project name: zejtron (lowercase, per section 2)
- Link to the official repository: <https://github.com/oxyzenQ/zejtron>

---

## 7. The Family Names (lowercase law)

Both family names — the sibling `zylaxion` and this project's own
`zejtron` — are lowercase in every context they appear in this
repository: prose, titles, headings, code, CLI output, comments,
commit subjects, and file paths — the nginx/curl convention
(night-improve-20 for the sibling name, night-improve-1.5 for the
project's own). A capitalized, internally capitalized, or all-caps
prose form of either name in any tracked file is a gate failure.

Two legal exceptions, per name:

- **Identifier family** — the all-caps form attached with `_` or `-`
  (an environment-variable prefix such as `ZYLAXION_MODE` or
  `ZEJTRON_BIN_PATH`, a marker such as `ZEJTRON-DISCLAIMER`).
- **Banner titles** — the all-caps comment titles heading the
  `scripts/` gate files.

Enforcement: `scripts/gates/check-name-case.py` (gate-keepers section
15) scans every tracked file and every tracked path via `git ls-files`
— nothing excluded — and fails with `file:line:token` on any casing
outside the two families above, for either name. The checker is
self-clean by construction: every all-caps form is built at runtime
from the lowercase name.

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
