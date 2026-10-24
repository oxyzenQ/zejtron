<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# The Evidence Ledger Specification

**Evidence Ledger Specification v3**

This document is the citable definition of the Evidence Ledger
output format - the block structure zejtron prints for every
question it answers. v1 (Frozen) and v2 (Frozen) remain citable
history: every consumer pinned against them can find their
contracts in the archive below. v3 changes exactly two things,
both in the JSON row (section 5): the typed evidence fields sit
at the row root (v2 carried them under a nested `action` object),
and the actor became the typed name/pid/user object (v1 and v2
carried a pre-rendered string; the pure-state actor is JSON null).
The text grammar, the tier vocabulary, and the four laws are
unchanged from v1. A change to any of them is a new specification
version and a breaking event, not an edit.

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

## 5. The JSON surface (`--print-json`)

Every data surface can answer with its report as one line of JSON
(`zejtron why /etc/passwd --print-json | jq .`): the ledger trio
(`holds`, `touch`, `why`), the doctor (readiness and the five
symptom lanes), and - since night-badass-9/10, the universal JSON
law - `path`, `recent`, `port`, `proc`, and `net`. The JSON lane is
a second rendering of the SAME report object - not a second truth:
the fields mirror the text grammar field for field, and the
byte-determinism law holds (same rows in, same bytes out). The
serializer is std-only by the dependency law: no serde, no new
crates.

Field map:

- `ledger_version` - `3`, the specification version this report
  conforms to (v1 carried `1`; v2 typed the action; v3 flattened
  the row and typed the actor).
- `subject`, `window` - the header and mode line's window label,
  the same tokens the text block carries.
- `mode` - the base word: `live`, `snapshot`, or `mixed`.
- `lane` - the mode line's lane qualifier without the comma
  (`journal fallback`, `no event lane available`), or `null` for
  the unqualified lanes (`live`, `mixed`).
- `measured`, `changes.rows` - arrays of row objects. A row is
  `{"unix_secs": <seconds | null>, "timestamp_utc": <"YYYY-MM-DD
  HH:MM:SS (UTC)" | null>, "kind": "...", <the kind's raw
  fields>, "actor": <the typed actor object | null>,
  "provenance": "<tier>"}`. An absent time is JSON `null` in both
  time fields - the machine-native form of the text renderer's
  `unknown`; the fact stays absent, never guessed.
  `provenance` is one of the four tier tags, the locked
  vocabulary.
- The row's typed fields (v3's change: at the row root; v2
  carried them under a nested `action` object) hold the fact as
  typed data, not a pre-rendered string. `kind` is one token per
  row kind - the same vocabulary the text phrase renders ("size
  884 bytes" is `"kind":"size","bytes":884`) - and the variant's
  raw fields ride beside it at the same level: numbers stay
  numbers, strings stay strings, and an absent optional part is
  JSON `null`. The kinds this version speaks:
  - `type` - `{"file_type": "..."}` (the stat(2) class word).
  - `symlink-target` - `{"target": "..."}`.
  - `size` - `{"bytes": N}`.
  - `owner` - `{"user": "...", "group": "...", "uid": N,
    "gid": N}` (resolved names AND raw ids).
  - `perms` - `{"octal": "..."}` (the mode's octal text).
  - `inode` - `{"id": N, "dev": N}` (the lane's identity key).
  - `modified` - `{"via": "audit log" | null}` (the carrying
    record, when the row rode a lane).
  - `accessed`, `changed` - no payload (the atime/ctime facts).
  - `held` - `{"via": "fd 3 (rw)"}` (the holds evidence label).
  - `cwd` - `{"path": "..." | null}` (null = unreadable, the
    named boundary).
  - `runs` - `{"cmd": "..." | null, "unit": "..." | null}` (the
    enrichment halves, each present only when read).
  - `opened` - no payload (the kernel's own open record).
  - `wrote` - `{"via": "writev" | null}` (the syscall family).
  - `journal-mention` - no payload (the log lane's weakest hit).
  A new kind is a specification event: the variant joins the
  code's enum, this list, and a version line - never silently.
- The `actor` (v3's other change) is the typed acting identity:
  `{"name": "...", "pid": N, "user": "..."}`, with JSON `null`
  for each part the source did not name (a log record that
  carried no pid, a username-only record), and JSON `null` for
  the whole actor when the row is pure state - the
  machine-native form of the text grammar's `—`. The live
  holders and event rows carry all three (the name, the pid, and
  the user resolved from the uid); the log-replayed rows carry
  what the record said. `jq 'select(.actor.pid == 2985)'`
  selects without parsing a parenthesized string.
- `changes.unavailable` - the absent-lane truth beside the rows:
  `true` when no event lane could serve, `false` when it ran (an
  empty window with a present lane is `false` with an empty `rows`
  array - an empty window is a finding, not an absence).
- `unaccounted` - always present (empty array when nothing is
  named); each entry is `{"count": N, "category": "...",
  "reason": "..."}`.
- `verdict` - always exactly `{"supports": "...",
  "cannot_support": "..."}`.

Strings are JSON-escaped: quote and backslash take their
representations, control bytes are named (`\n`, `\t`, `\u00xx`),
and UTF-8 passes through verbatim. `why`'s `--trace` and `--raw`
are text-only drill-downs and the CLI refuses their combination
with `--print-json` - the JSON line stays byte-clean on stdout,
always.

### The per-surface JSON lanes (night-badass-9/10)

`path`, `recent`, `port`, `proc`, and `net` are not ledger reports,
so their JSON carries no `ledger_version` - each speaks its own
typed schema, the same selection the text renders, serialized by
the same shared writers (the escaped string, the array grammar, the
typed-absence nulls):

- `path` - `{"command": "...", "found": <bool>, "active":
  <match | null>, "duplicates": [<match>]}`, where a match is
  `{"path": "...", "executable": <bool>, "symlink_chain": [...],
  "package": "..." | null}`. The chain is the full resolution (the
  text display truncates at three hops; the wire carries what the
  kernel answered), and a package no backend named is `null` - the
  text's `unknown` word is a display verdict, not a fact.
- `recent` - `{"path": "...", "files": [{"path": "...",
  "mtime_unix_secs": N, "changed_unix_secs": N, "size_bytes": N,
  "uid": N, "owner": "...", "perms": "0644"}]}` - the same
  selection (limit, window, newest-first); paths are the raw bytes
  JSON-escaped (the terminal neutralizer is a render concern).
- `port` - `{"subject": ":9999" | null, "mode": "snapshot" |
  "live", "window": "60s", "ports": [{"protocol": "tcp",
  "local_addr": "0.0.0.0:9999", "state": "LISTEN", "owners":
  [{"pid": N, "process": "...", "user": "..."}]}], "changes":
  {"available": <bool>, "reason": <token | null>, "events":
  [{"kind": "listened" | "left-listen" | "closed", "protocol":
  "tcp4", "port": N, "pid": N, "process": "...", "time_utc":
  "HH:MM:SS UTC"}], "unaccounted": N}, "scan":
  {"unreadable_processes": N, "unreadable_fds": N}}`. The lane
  honesty carries: an unavailable window is `available: false` with
  a stable reason token (`snapshot-only`, `lane-not-attached`),
  never a fabricated event list. The table is not a ledger report;
  `holds`/`why` remain the ledger's port view.
- `proc` - `{"subject": "...", "processes": [{"pid": N,
  "ppid": N, "comm": "...", "uid": N, "state": "S",
  "vm_rss_kb": N, "vm_size_kb": N, "threads": N, "cmdline":
  "..." | null}], "unreadable_statuses": N}` - the flat scan,
  ascending by pid, the `--find` selection applied through the same
  matcher the tree prunes with; `--depth` stays the render limiter
  it is (the list is the data, not the drawing).
- `net` - the `NetReport` model one-to-one: `interfaces` (name,
  state, mtu, mac, ipv4, ipv6, the eight counters),
  `arp_neighbors`, `routes`, `default_route`, `resolver` - every
  fact the /proc read could not answer rides as `null`.

### v2 archive (Frozen)

Evidence Ledger Specification v2 (Frozen) is the pre-v3 contract,
citable verbatim: identical to this document except section 5,
where v2's row carried the typed evidence fields under a nested
`"action": {...}` object (v3 flattened them to the row root) and
the actor as the pre-rendered string ("systemd (pid 1, root)")
that v3 replaced with the typed name/pid/user object. `ledger_version`
was `2`, and no other field differed. The text grammar (section
2), the tier vocabulary (section 1), and the four laws (section
3) are byte-identical between v2 and v3.

### v1 archive (Frozen)

Evidence Ledger Specification v1 (Frozen) is the pre-v2 contract,
citable verbatim: identical to this document except section 5,
where v1's row was `{"unix_secs": <seconds | null>,
"timestamp_utc": <"YYYY-MM-DD HH:MM:SS (UTC)" | null>, "action":
"...", "actor": "...", "provenance": "<tier>"}` - the action was
the rendered text phrase (`"size 884 bytes"`), `ledger_version`
was `1`, and no other field differed. The text grammar (section
2), the tier vocabulary (section 1), and the four laws (section
3) are byte-identical between v1 and v2.

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
