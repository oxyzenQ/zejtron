<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# The Evidence Ledger Specification

**Evidence Ledger Specification v1 (Frozen)**

This document is the citable definition of the Evidence Ledger
output format - the block structure zejtron prints for every
question it answers. v1 is frozen: the grammar, the tier vocabulary,
and the laws below do not change under this version line. A change
to any of them is a new specification version and a breaking event,
not an edit.

The reference implementation is zejtron's `src/evidence/` module,
and the repository carries a drift pin: a test reads this document's
tier block and fails the build the moment the code's vocabulary and
the spec's vocabulary disagree. This document and the implementation
are two renderings of one contract; if they ever conflict, the
newer of the two is wrong and the fix is one commit.

## Scope and conformance

A tool conforms to this specification when every report it prints
follows all three of: the provenance tier vocabulary (section 2),
the output grammar (section 3), and the four laws (section 4). A
tool that cannot reach the kernel's event lanes has a defined
compliance path - the escape hatch (section 5) - and it does not
reduce that tool's conformance.

The format is pure text. It has no dependency on a terminal, a
color system, a locale, or a library: every conformant report is
byte-stable, diffable, and renderable on a printer from 1978.

## 1. The four provenance tiers

Every piece of evidence in a report carries exactly one tier tag,
bracketed and lowercase, as the last token of its row. The
vocabulary is exactly four tiers - there is no fifth, and a source
class that does not fit must be described inside one of the four.
The tag is a statement about the SOURCE of the row, never about
confidence or quality: an audit record naming a PID is still
[inferred], because the source is a replayed log, not the kernel's
own perception.

```ledger-tiers
[observed]
[measured]
[inferred]
[unaccounted]
```

- **[observed]** - the kernel itself recorded the action as it
  happened. The eBPF programs attached to kernel entry points saw
  the event in flight and captured it with the acting PID. This is
  direct perception of the event, the strongest tier a report can
  carry: nothing stands between the fact and the record.

- **[measured]** - the tool read state directly at the instant of
  the command: /proc, /sys, stat, the socket tables. This is direct
  perception of what HOLDS, not of what happened - a photograph of
  the scene, not a recording of the act.

- **[inferred]** - the row is a reconstruction from indirect
  evidence: a log replayed (audit.log, journalctl), a modification
  timestamp implying a write, an absence implying a boundary. The
  reading may be strong, but something stands between the fact and
  the record, and the tag says so honestly.

- **[unaccounted]** - the report cannot see this, and says so
  instead of guessing. The tier does not annotate rows; it names
  the boundary of the whole report in its own block (section 3).
  Its seat in the vocabulary exists so that silence can never be
  mistaken for evidence.

The strength ordering is real and worth stating once:
[observed] and [measured] are direct perception (of events and of
state respectively); [inferred] is reconstruction; [unaccounted] is
the named absence. A presentation may color these differently, but
conformance never requires color - the tags themselves carry the
epistemology.

## 2. The output grammar

Every conformant report is a block with exactly this shape:

```text
Evidence report: <subject>
Mode: <mode> (window <N><unit><lane qualifier>)

Evidence:
  <timestamp>  <action>  <actor>  [<tier>]
  ...
  Changes in the last <window label>:
  <event rows | (no events in the window) | unavailability line>

Unaccounted:
  <N> <category> (<reason>)
  ...

Verdict:
  The evidence supports: <one line>
  The evidence cannot support: <one line>
```

The block's parts, locked:

- **Header** - `Evidence report: <subject>`, where `<subject>` is
  the thing the report is about: a path, a port, a process.

- **Mode line** - `Mode: <mode> (window <label><qualifier>)`. The
  mode is one of exactly three emitted values plus one reserved:
  `live` (the kernel event lane ran and captured the window),
  `snapshot` with the qualifier `, journal fallback` (the log lane
  served the window), `snapshot` with the qualifier `, no event
  lane available` (no lane could serve), and `mixed` (reserved for
  a report drawing rows from more than one lane at once; no
  exclusive-lane tool emits it, the grammar carries it so no future
  report has to break the shape to say it). The window label is the
  same token in the mode line and the Changes header - one fact,
  stated twice, from one source.

- **Evidence rows** - each row is four fields separated by exactly
  two spaces: `<timestamp>  <action>  <actor>  [<tier>]`.
  The timestamp is UTC civil time, `YYYY-MM-DD HH:MM:SS` (section
  3's first law governs the marker), or the literal `unknown` when
  the fact's time is absent - an absent fact stays absent, never
  guessed. The action is the fact itself. The actor is the acting
  identity - `name (pid N, user)` for a process - or `—` for pure
  state that has no actor. The tier tag is the row's last token.

- **Changes subsection** - rides under the state rows whenever the
  report has event-lane state to name. Three truths, kept
  distinct: event rows when there are any; `(no events in the
  window)` when the lane RAN and came back empty - an empty window
  is a finding; and the named unavailability line when no lane
  could serve at all - an absent lane is a different truth from an
  empty one, and the grammar keeps them different.

- **Unaccounted block** - always present (section 3's fourth law).
  Each entry is `<N> <category> (<reason>)`: how much the report
  cannot see, of what, and the honest reason why. An empty block
  renders the single line `(none observed)` - present, explicit,
  never omitted.

- **Verdict** - always present, exactly two lines: what the
  evidence supports, and what it cannot support. Sparse evidence
  gets a sparse verdict that names the sparseness. A verdict line
  the rows do not back is a spec violation, not a style choice.

## 3. The laws

Four laws hold for every conformant report. They are the
format's contract with machines and with courtrooms.

1. **UTC everywhere, explicitly marked.** Every timestamp is
   Coordinated Universal Time rendered as civil time
   (`YYYY-MM-DD HH:MM:SS`). The FIRST timestamped row of a report
   carries the literal suffix ` (UTC)` - one declaration for the
   whole column; every row after it stays bare. A row whose time
   is absent renders `unknown`. No local time, no implicit zone,
   no guessed time.

2. **Deterministic ordering.** Same facts in, same bytes out - per
   run. The renderer never reorders and never iterates a hash map;
   ordering is the caller's deterministic contract (by time, by
   pid for peers), and the output carries no randomness, no
   address-dependent values, no environment-dependent bytes. Two
   conformant runs over an unchanged host diff to empty.

3. **Zero escape bytes when piped.** A report written to a
   non-terminal stream is plain bytes: no ANSI/CSI escape
   sequences, no color codes, no cursor controls - regardless of
   what the error stream or the environment is doing. Color is a
   terminal-only presentation tier and may never enter a pipe,
   a file, or a redirect. This law is what makes the output
   diffable, citable, and safe to embed in an incident record.

4. **Unaccounted is always present.** Every report carries the
   Unaccounted block; a report that cannot name anything outside
   its sight still prints `(none observed)`. Silence about the
   boundary is the one dishonesty the grammar cannot express -
   so it does not exist.

## 4. The escape hatch

A tool that cannot attach to the kernel's event lanes - a
container without privileges, a host without eBPF, a lane that
only logs - conforms through the same grammar with one discipline:
label the source, never the ambition.

- Rows reconstructed from logs, timestamps, or any indirect record
  are `[inferred]` - however strong the underlying record reads,
  however much it names the PID. The tag describes the source;
  replayed evidence is not kernel perception.
- The Mode line declares the lane truthfully: a log-served window
  is `snapshot` with the fallback qualifier, never `live`. A tool
  that printed `live` for a journal replay would violate the spec
  in exactly one word.
- What the lane cannot see goes to Unaccounted with a reason, by
  name. The escape hatch is a compliance path, not a lesser
  conformance: the honesty contract is identical, only the
  perception is smaller.

## Conformance checklist

- Every evidence row ends in one of the four tier tags.
- No tier outside the four appears anywhere in the report.
- The block shape matches section 2, byte for byte, in the plain
  rendering.
- Timestamps are UTC civil time with the first-row ` (UTC)`
  declaration; absent times render `unknown`.
- Two runs over an unchanged host produce identical bytes.
- A piped or redirected report contains zero escape bytes.
- The Unaccounted block is present; empty prints
  `(none observed)`.
- The Verdict is present and is exactly two lines.
- Non-eBPF sources are tagged `[inferred]` and the mode line says
  which lane served.
