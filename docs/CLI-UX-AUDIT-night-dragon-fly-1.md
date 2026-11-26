<!-- SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ) -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR Commercial -->
<!-- NON_LATIN_FIXTURE: the multibyte --since unit probes are the test vectors themselves (the parser must refuse them cleanly, no panic, night-dragon-lts-1); the CJK characters are the fixture, not prose. -->

# CLI/UX end-to-end audit battery - night-dragon-fly-1

Status: research instrument (not a release doc). Source of truth:
`src/**/*.rs` - every expectation below names the file and line it was
derived from. This document may go stale when the CLI changes; the
battery script fails loudly in that case, which is the point.

Purpose: one pass over EVERY lane the help surface advertises - root,
all ten verbs, every flag, the parse-error and runtime-error lanes, the
JSON lanes, the window clamp, the color capability ladder, and the exit
codes - captured with streams separated and exit codes recorded, so
the wording/UX/JSON audit lands on bytes, not memory.

## How to run

Automated (preferred - one captured file, ~100 probes):

```sh
cargo build
bash scripts/dev/cli-ux-audit-battery.sh > battery-output.txt 2>&1
```

Send `battery-output.txt` back. Optional toggles:

- `ZEJTRON_BIN=/path/to/zejtron` - probe a specific binary
- `ZEJTRON_BATTERY_MAX_LINES=0` - no per-stream truncation (default 120)
- `ZEJTRON_BATTERY_WITH_ROOT=1` - add the privileged `doctor
  --attach/--detach` probes (run as root)

Manual mode: every probe is listed below as a command with its
expectation. The `[Xn]` ids match the script's output headers.

Legend: parse errors exit 2 on stderr with the brand render
(`src/cli/ux.rs:412`); runtime failures exit 1 with the `error:` labeled
block (`src/output/mod.rs:422`); help/version exit 0 on stdout;
a SIGPIPE death exits 141 (`src/main.rs:53`).

## A. Root surface

```sh
zejtron                      # [A1] bare: same bytes as -h (cli/mod.rs:120)
zejtron -h                   # [A2] banner + about + usage + 10 verbs + Options + Pro mode + Quick examples
zejtron --help               # [A3] byte-identical to A2
zejtron -V                   # [A4] full version report (info::version_report_text)
zejtron --version            # [A5] byte-identical to A4
zejtron -v                   # [A6] verbose alone dispatches nothing: bare help, exit 0
zejtron --check-update       # [A7] network; branded status report or exit 1 'update check failed: ...'
zejtron -h | cat -v          # [A8] pipe lane: zero escape bytes
NO_COLOR=1 zejtron -h | cat -v            # [A9] plain bytes on a tty too
CLICOLOR_FORCE=1 zejtron -h | cat -v      # [A10] escapes present (output/capability.rs ladder)
```

Audit questions: does A1 equal A2 byte for byte; do the Pro mode rows
match the verb help rows verbatim (see finding F1); does the usage line
read `zejtron [command] or [options] e.g zejtron port -v`
(`cli/mod.rs:131`); are the Example rows present under every verb
(`cli/examples.rs:43` pins the table).

## B. Per-verb help surfaces

```sh
for v in path recent port proc holds touch why doctor net sig; do zejtron $v -h; done   # [B]
zejtron signature --help    # alias resolves to sig help (cli/mod.rs:427)
zejtron path -V             # version short-circuit beats the required positional
zejtron proc -V
zejtron holds -V
zejtron touch -V
zejtron why -V
zejtron net -v              # global flag order freedom
```

Audit questions: is the row order pinned on every verb (`-V, -v, -h`
and the verb's own flags; `cli/mod.rs:70` display_order pins); does
each verb's usage line carry the `e.g` invocation; do the `--print-json`
help rows use the one house phrasing ("... as JSON (one line,
jq-ready)").

## C. Happy paths

```sh
zejtron path sh
zejtron path definitely-not-a-command-xyz        # exit 1: 'command not found in PATH:' (commands/path.rs:71)
zejtron recent .
zejtron recent --limit 5 .
zejtron recent --since 1h .
zejtron port
zejtron port --tcp --numeric
zejtron port 22
zejtron port --listen
zejtron port --group
zejtron port --no-pid
zejtron port --events-only
zejtron port --snapshot-only
zejtron proc --me
zejtron proc --find ssh
zejtron proc --me --depth 2
zejtron proc --me --no-pid --no-color
zejtron holds /etc/resolv.conf
zejtron holds 22                                  # bare port number is a legal target
zejtron touch /etc/hosts
zejtron why /etc/passwd
zejtron why /etc/passwd --trace
zejtron why /etc/passwd --raw
zejtron why /etc/passwd --trace --raw             # both drill-downs stack
zejtron doctor
zejtron doctor --symptom ram
zejtron doctor --symptom slow
zejtron doctor --symptom gpu                      # honest no-gpu shape on hosts without one
zejtron doctor --symptom ram --raw
zejtron net
zejtron sig
```

## D. Parse-error lanes (exit 2, stderr, the one-tip contract)

```sh
zejtron stat                  # tip: 'sig (signature)' or 'doctor (status)' (cli/ux.rs:69)
zejtron status                # same two-successor tip
zejtron PORT                  # case-insensitive subcommand fallback -> 'port'
zejtron WHOHOLDS              # redirect table is exact-match only; CI fallback answers
zejtron whoholds              # redirect -> 'holds' (cli/ux.rs:41)
zejtron lasttouch             # redirect -> 'touch'
zejtron whyopen               # redirect -> 'why'
zejtron envpath               # redirect -> 'path'
zejtron help                  # tip: to see the reference, run 'zejtron --help' (cli/ux.rs:54)
zejtron zzzqqq                # honest generic miss
zejtron proc --ME             # case-insensitive flag fallback -> '--me'
zejtron --ME                  # proc-scoped flag at root scope: observe the tip-less shape
zejtron --check-updated       # retired alias rescue -> '--check-update' (cli/ux.rs:80)
zejtron port --tcpp           # -> '--tcp'
zejtron holds --tcp           # foreign flag: observe whether any tip lands
zejtron net --since 5m        # foreign flag: observe the tip lane
zejtron port --listen --all                    # clap conflict, exit 2
zejtron port --events-only --snapshot-only     # clap conflict (port.rs:96 is the second layer)
zejtron why /etc/passwd --trace --print-json   # conflict
zejtron doctor --attach --detach               # conflict
zejtron doctor --attach --print-json           # conflict
zejtron proc root --me                         # target group exclusivity
zejtron doctor --raw                           # RUNTIME exit 1, not clap exit 2 (see finding F3)
zejtron recent --limit 1000001 .               # named range refusal (cli/mod.rs:199)
zejtron recent --limit -1 .
zejtron recent --limit abc .
zejtron recent --limit 99999999999999999999 .
zejtron proc --me --depth 0                    # range 1-1024 refusal
zejtron proc --me --depth 1025
zejtron proc --me --depth -5                   # allow_hyphen_values rides the parser
zejtron holds -- --tcp                         # escape hatch: '--tcp' becomes the operand
zejtron path ""
zejtron holds $'\xff\xfe'                      # non-UTF-8 argv: exit 2, clap's 'invalid UTF-8 was detected in one or more arguments' render, never panic 101
```

## E. Runtime error lanes (exit 1, `error:` labeled block)

```sh
zejtron port abc              # 'error: invalid port: abc' (commands/port.rs:143)
zejtron port 0                # port 0 refused (commands/port.rs:148)
zejtron port 99999            # u16 overflow refusal
zejtron port ""               # 'the port is empty (e.g. zejtron port 22)' (commands/port.rs:137)
zejtron holds /nonexistent-path-xyz    # 'path not found: /nonexistent-path-xyz' (commands/holds.rs:235)
zejtron touch /nonexistent-path-xyz    # 'path not found: /nonexistent-path-xyz' (commands/touch.rs:94)
zejtron proc nouserxyz123     # 'unknown user: nouserxyz123' (commands/proc.rs:223)
zejtron doctor --symptom xyz  # the KNOWN list echoed back (commands/doctor/symptom.rs:57)
zejtron port --since 3x       # 'invalid duration: 3x (use e.g. 30s, 10m, 1h, 7d)' (commands/port/window.rs:79)
zejtron recent --since 3x     # '... (use e.g. 30s, 10m, 2h, 7d)' (commands/recent.rs:167) - examples share the s/m/h/d grammar now (the F2 close)
zejtron recent --since 5分    # multibyte unit: clean refusal, no panic (night-dragon-lts-1)
zejtron recent --limit 0 .    # the render must NAME the limit-0 cut (commands/recent.rs:223)
```

## F. JSON lanes

```sh
zejtron path sh --print-json
zejtron recent --limit 3 . --print-json
zejtron port --print-json
zejtron proc --me --print-json
zejtron holds /etc/resolv.conf --print-json
zejtron touch /etc/hosts --print-json
zejtron why /etc/passwd --print-json
zejtron doctor --print-json
zejtron doctor --symptom ram --print-json
zejtron net --print-json
zejtron sig --print-json

# per verb, where jq exists:
zejtron port --print-json | jq -e . >/dev/null && echo VALID
zejtron port --print-json | wc -l            # exactly 1 line
zejtron why /etc/passwd --print-json | jq -c 'keys'
zejtron port --print-json | jq -c 'keys'
zejtron doctor --print-json | jq -c 'keys'
```

Audit questions: one line, trailing newline, no ANSI, exit 0; top-level
key naming consistent (snake_case); the JSON lane never mixes with the
banner frame.

## G. Window clamp lanes

```sh
zejtron port --since 100h --snapshot-only                # stderr: 'warning: --since 100h exceeds the 1h maximum - clamped to 1h'
zejtron port --since 100h --snapshot-only 2>/dev/null    # stdout byte-clean
zejtron port --since 100h --snapshot-only 2>&1 >/dev/null
zejtron port --since 0s --snapshot-only                  # below-floor note
zejtron port --since 7d --snapshot-only                  # 'd' accepted and documented now (s/m/h/d, the F2 close), clamped to 1h
zejtron port --since 18446744073709551h --snapshot-only  # u64 saturation -> clamp, no panic
zejtron recent --since 100h .                            # NO clamp note by design (cli/mod.rs:215)
zejtron holds /etc/resolv.conf --since 500m
zejtron port --since 100h --print-json 2>/dev/null | wc -l   # JSON purity under the clamp note
```

## H. Exit codes and pipe citizenship

```sh
zejtron -h >/dev/null 2>&1; echo $?                    # 0
zejtron >/dev/null 2>&1; echo $?                       # 0
zejtron -V >/dev/null 2>&1; echo $?                    # 0
zejtron zzzqqq >/dev/null 2>&1; echo $?                # 2
zejtron --zzz >/dev/null 2>&1; echo $?                 # 2
zejtron port --listen --all >/dev/null 2>&1; echo $?   # 2
zejtron port abc >/dev/null 2>&1; echo $?              # 1
zejtron doctor --symptom xyz >/dev/null 2>&1; echo $?  # 1 (finding F3)
zejtron doctor --raw >/dev/null 2>&1; echo $?          # 1 (finding F3)
zejtron proc --print-json 2>&1 | head -c 10 >/dev/null; echo ${PIPESTATUS[0]}   # 0 when the render fits the pipe buffer, 141 when it exceeds it; never a panic
zejtron -h 2>&1 | head -n 1                            # no broken-pipe panic
zejtron net -v 2>/dev/null | head -n 5                 # verbose stays on stderr
```

## I. Color capability on a data surface

```sh
zejtron sig | cat -v | head -n 30
CLICOLOR_FORCE=1 zejtron sig | cat -v | head -n 30
NO_COLOR=1 zejtron doctor --symptom ram | cat -v | head -n 30
CLICOLOR_FORCE=1 zejtron port abc 2>&1 >/dev/null | cat -v    # 'error:' label bold red
```

## J. Privileged eBPF probes (root only, optional)

```sh
zejtron doctor --attach
zejtron doctor --detach                   # idempotent
zejtron doctor --attach --print-json      # observe which lane owns attach+json
```

## Static findings (from source, pending the battery bytes)

These are the hypotheses this battery is built to confirm or refute,
honestly labeled: they come from reading the source at the pinned
commit, not from running the binary. A sandbox battery run on
2026-11-25 (debug build, piped stdout, no root) already confirmed the
runtime-visible ones - the archived output of that run rides with the
audit deliverables, not in the repository; run the battery on your own
terminal for the color-lane and host-specific halves.

- **F1 - Pro mode rows drift from the verb help rows (4 rows).**
  `src/cli/pro_mode.rs:11` states the contract: each spelling mirrors
  the verb's own help string verbatim, one wording authority (the CLI
  structs). Four rows violate it today:
  - `recent --since`: verb help says "(s/m/h/d, no window clamp)"
    (`cli/mod.rs:215`), Pro mode drops the qualifier
    (`pro_mode.rs:65`).
  - `port --listen`: verb help says "Show listening or bound sockets"
    (`cli/mod.rs:235`), Pro mode adds "(excludes --all)"
    (`pro_mode.rs:80`) - the conflict is real (`conflicts_with = "all"`)
    but only Pro mode names it.
  - `why --print-json`: Pro mode adds "; excludes --trace and --raw"
    (`pro_mode.rs:161`), verb help does not (`cli/mod.rs:375`).
  - `doctor --print-json`: Pro mode adds "; excludes --attach,
    --detach, --raw" (`pro_mode.rs:186`), verb help does not
    (`cli/mod.rs:412`).
  The direction differs per row, so this is drift, not a policy. Two
  honest fix directions (owner's call): enrich the four verb helps so
  clap's own rows name the conflicts, or trim the Pro mode rows back to
  verbatim. Confirmed at runtime: the four Pro mode rows render the
  divergent text verbatim in `zejtron -h`.

- **F2 - the window grammar documents s/m/h but accepts s/m/h/d.
  [CLOSED night-dragon-fly-2: the documenting direction landed - the
  helps, the Pro mode mirrors, and the refusal example read s/m/h/d
  now; see the close-out below.]**
  `commands/port/window.rs:108` parses `d`; the four window helps say
  "(s/m/h, default ...)" (`cli/mod.rs:248,327,343,363`) and the invalid
  duration example says "(use e.g. 30s, 10m, 1h)" (`window.rs:79`).
  `recent` accepts and documents `d` consistently
  (`cli/mod.rs:215`, `recent.rs:167`). So `zejtron port --since 7d` is
  accepted (then clamped to 1h) on a grammar the surface denies twice.
  Confirmed at runtime: `port --since 7d` exits 0 with the clamp note,
  and the two invalid-duration refusals visibly disagree
  ("use e.g. 30s, 10m, 1h" vs "use e.g. 30s, 10m, 2h, 7d").
  Fix direction: either document `s/m/h/d` on the window helps and the
  refusal example, or reject `d` in the window lane; recent's behavior
  stays as-is either way.

- **F3 - usage-shaped refusals riding the runtime exit code.**
  `doctor --raw` without `--symptom` is refused at runtime with exit 1
  (`commands/doctor.rs:82`), and the source comment at
  `commands/doctor/symptom.rs:50` calls an unknown symptom "a usage
  error" that exits 1 - while the house law (`src/cli/ux.rs:19`)
  routes usage errors to exit 2. Both refusals are expressible at
  parse time (clap `requires = "symptom"` on `--raw`; a fixed-set
  value parser on `--symptom`), which would move them to the clap lane,
  exit 2, with the standard usage render - and remove two hand-written
  error strings. Design question first: the current shape may be a
  deliberate runtime-lane choice. Confirmed at runtime: both refusals
  render through the `error:` block and exit 1
  (`--raw requires --symptom (it appends the raw /proc reads the
  memory report rode on)`, and the unknown-symptom line that echoes the
  full KNOWN list).

- **F4 - the clamp warning rides a bare, unpainted eprintln.
  [CLOSED night-dragon-fly-2 for the em-dash family: the two clamp
  notes and the root-refusal line render ASCII " - " now; the
  warn-tier paint candidate stays open, owner's call. See the
  close-out below.]**
  `commands/port.rs:111` prints `truncation_note` output
  (`window.rs:129`) as a plain stderr line, while every runtime error
  rides the branded `error:` block (`output/mod.rs:422`) and the
  palette carries a warning yellow tier with no caller on stderr
  (`output/mod.rs:266-279` removed the other lanes). The note also uses
  an em dash (`window.rs:131`) where the help surfaces use ASCII " - ".
  Candidate improvement: a `warn:` labeled line in the warning tier on
  stderr, keeping stdout byte-clean. Confirmed at runtime: the note
  renders as a bare unpainted line carrying the em dash
  ("warning: --since 100h exceeds the 1h maximum — clamped to 1h").

- **F5 - mixed terminal punctuation in the Commands list.**
  Seven verb abouts are questions ending in "?" and three are
  statements ending in "." (`cli/mod.rs:171,350,380,425`). Defensible
  typography, worth a one-line policy decision for the LTS freeze.

- **F6 - hyphenation drift inside the sig verb.** "depth-matrix
  self-check" (`cli/mod.rs:425`) vs "signature depth matrix"
  (`cli/mod.rs:433`). Micro.

- **F7 - negative range asks do not name the range.**
  `proc --depth 1025` renders "1025 is not in 1..=1024" (the range in
  the message, the LTS posture), but `proc --depth -5` renders
  "invalid digit found in string" - the u64 parser rejects the sign
  before the range check, so the refusal loses the range name
  (confirmed at runtime). Micro wording gap; a signed-range parser or
  a pre-parse sign check would restore the symmetric refusal.

- **F8 - deliberate gaps verified as designed.** The `--ME`-at-root
  tip-less shape ("unexpected argument '--ME' found", no tip), the
  exact-match-only redirect tables, the foreign-flag misses that keep
  clap's escape-hatch tip only (`holds --tcp` renders the one
  "to pass '--tcp' as a value, use '-- --tcp'" tip - correct guidance,
  one tip), and the no-shadowed-suggestion boundary are all documented
  decisions (`cli/ux.rs:23-25,41-46`), not bugs. The battery captures
  their bytes so the freeze has them on record.

- **F9 - honest-render checks that passed.** `recent --limit 0`
  names the cut ("0 of 429 modified files shown (--limit 0)"), the
  path miss renders a plain stdout report with exit 1, JSON top-level
  keys are snake_case and shape-consistent across verbs (why, port,
  doctor inspected), the clamp note stays off stdout under
  `--print-json`, and `path ""` has its own empty-operand guard
  ("the command name is empty (e.g. zejtron path sh)").

- **F10 - the holds missing-path refusal names the errno, not the
  house shape. [CLOSED night-dragon-fly-2: holds (both lanes) AND
  recent (the hunt's catch) harmonized to the "path not found:
  " prefix; the remedy suffix stays why's own. See the close-out
  below.]** `touch` and `why` refuse a missing path with
  "path not found: <path>" (`touch` exits 1 with the plain shape, `why`
  appends the deleted-path remedies), while `holds` renders the raw
  errno string "<path>: no such file or directory" - the same ask
  answered in two vocabularies across sibling surfaces. Confirmed at
  runtime on 2026-11-26 by the manual battery. Fix direction (owner's
  call, a byte change under the freeze): harmonize holds to the
  "path not found:" prefix, optionally carrying why's remedy
  suggestions; the battery's expectation pins the CURRENT bytes until
  the owner rules.

- **F11 - the bare render carries one extra trailing newline.**
  `src/main.rs:176-183` (the `None` branch) calls
  `print_help().map(|_| println!())`, and clap's `print_help` already
  ends with the newline - so bare `zejtron` ends "...slow\n\n" while
  `zejtron -h` ends "...slow\n". Measured on the 2026-11-26
  pro-native-musl build of e88876b: bare = `-h` + one trailing blank
  line, so the `[A1] bare: same bytes as -h` note above is wrong
  today. No test pins either shape. Two honest fix directions (owner's
  call): drop the `println!()` so bare equals `-h` byte for byte, or
  correct the `[A1]` note to name the trailing blank line.

- **F12 - the Pro mode global group order differs from the Options
  block.** The root Options block lists `-V, --version`, then
  `-v, --verbose`, then `--check-update` (`cli/mod.rs:70-72`
  display_order pins), while the Pro mode `global:` group lists
  `--check-update`, then `-V, --version`, then `-v, --verbose`
  (`pro_mode.rs:205-217`). The same three flags render in two orders
  on one surface. Micro; a row reorder in GROUPS (or a matching
  display_order change) unifies them. Byte change under the freeze:
  owner's call.

## The manual lane (night-dragon-fly-1 continuation, 2026-11-26)

The copy-paste battery the audit pass runs with: the complete
source-derived surface in one shot - every verb's -h, every flag lane
on the text and JSON side, the clamp and ceiling refusals, the UX
bridge rescues (help, whoholds, lasttouch, whyopen, envpath, stat,
status, the --ME and --Print-Json case rescues, --check-updated), the
retired-lifecycle-flag refusals, the SIGPIPE exit-141 law, and the
privileged attach/detach lane behind `ZEJTRON_BATTERY_ROOT=1`:

```sh
bash scripts/labs-exp/zejtron-manual-battery.sh
sudo ZEJTRON_BATTERY_ROOT=1 bash scripts/labs-exp/zejtron-manual-battery.sh
```

Every probe prints the exact command before its output, so the report
doubles as the manual; the report lands at
`zejtron-manual-battery-report.txt` (override:
`ZEJTRON_BATTERY_OUT`). The binary resolve order matches the shared
resolver (`ZEJTRON_BIN_PATH`, then target/debug, target/release, the
musl release lane, then $PATH).

Sandbox verdict (no root, kernel below the 5.15 floor, piped stdout):
122 passed, 0 failed, 3 recorded, 1 skipped (the privileged lane). The
signature lane rode exit-recorded then; night-dragon-lts-4 (2026-11-26)
made it verdict-driven - AUTHENTIC verifies at exit 0 on a signed tree,
UNSIGNED refuses at exit 1 on an unsigned tree - so the lane now judges
the verdict/exit agreement on both tree shapes instead of pinning one
era's exit code.

The owner's privileged run (2026-11-26, /usr/bin/zejtron at
local-pro-linux-amd64-v3-musl e88876b) exposed the battery's own wait
bug: with a live event lane every port probe opened the shipped 60s
shutter and the 2h clamp probe waited its clamped 1h - the run died on
a ^C there. The battery now rides the fast lane by default: every
window probe takes the 1s floor and the clamp probe is carried with
--snapshot-only, which verifies the clamp wording without opening the
shutter; ZEJTRON_BATTERY_FULL=1 restores the shipped widths for the
deep run. Both lanes hold the full verdict set (122 passed, 0 failed,
3 recorded, 1 skipped); the fast lane runs in seconds. The owner's
captured sections before the kill were green end to end on real
hardware, and the sudo lane's root-refusal line carries the F4
em-dash family into the runtime error lane.

The confirmation run closed the privileged evidence (2026-11-26
21:11, nightpc, /usr/bin/zejtron at e88876b, the fast lane after
pulling d0f7e6e..87a498f): 127 passed, 0 failed, 3 recorded,
0 skipped - the full verdict set with the live lane exercised end to
end (the 12-program attach, the pre-attach watch gap verdict naming
the honest no-event-can-exist span, the 28-pin detach, idempotent
re-detach). sig carried 6/6 depths AUTHENTIC with the D5 GPG commit
signature verified against the pinned maintainer key. The run also
re-observed the night-dragon-lts-3 holds-seam on this estate - the
doubled "(UTC) (UTC)" in the pre-attach watch gap wording - the third
independent sighting across two hardware estates; the freeze window
opened the same day and the seam dropped (night-dragon-fly-2), the
pin now holding the single-UTC render. The manual-lane audit is
complete: two hardware estates, privileged and unprivileged, the
fast lane, all expectations held.

The
mismatch hunt that produced F10 ran against this report: the first
pass carried 8 mismatches, 7 of which were the battery's own wrong
expectations (clap's `is not in 0..=1000000` range shape, the v4
ledger field map where `rows` is the retired v3 name and the tiers
ride row-level `provenance`, `doctor --raw` being a runtime refusal at
exit 1, `sig --print-json` exiting 1 with the JSON whole on the
unsigned verdict) and one - F10 - a real wording seam. The battery now
pins the verified bytes.

## The freeze-window close-out (night-dragon-fly-2, 2026-11-26)

The recorded queue moved to resolved bytes in one gated session, one
task per commit, every pin moving in lockstep:

- F4 closed: the clamp warning pair (window.rs) and the root-refusal
  line (system/mod.rs) render the ASCII " - " separator; the pinned
  unit tests hold the new bytes. The stdout em-dash sites - the LEFT
  LISTEN event-row note, the TAMPERED verdict line, the brand banner,
  the evidence table's no-data glyph - are observed, not queued: they
  are stdout render/identity bytes, not the stderr runtime family the
  finding named.
- F10 closed, wider than the finding: the hunt found recent's scan
  root and holds' ledger lane (the site the run() path answers
  through) carrying the errno vocabulary too; all four surfaces -
  touch, why, holds, recent - now refuse with "path not found: X",
  and the supermassive asserts plus both batteries moved in lockstep.
- F2 closed on the documenting direction: the parser has accepted d
  since the night-total-hardening-1 grammar unification, so the four
  window helps, their Pro mode mirrors, and the refusal example read
  s/m/h/d now; recent's documented grammar is the CLI-wide shape.
- night-dragon-lts-3 closed: the wrapper's "(UTC)" dropped after the
  three independent sightings, the pin holds the single-UTC
  production render with an anti-doubling guard, and the hunt's sweep
  over every format_unix_secs consumer caught the same family on the
  Z11 silent-deletion entry (the live render carried
  "(at ... (UTC) UTC)") - closed the same window, same law.

No version move, no tag: the release engineering seat stays the
owner's.

## The manual estate verdict (night-dragon-fly-3, 2026-11-26)

The manual lane's privileged run on the dragon-3 binary (e76c87b,
the fly-2 tree, pro-linux-amd64-v3-musl) came back 127 passed,
0 failed, 3 recorded, 0 skipped across sections 0-13 - the full
-h/--help estate, the rescue bridge, the pipe law, and the
privileged attach lane, on a second hardware estate. Every fly-2
close-out re-verified from the live bytes:

- the pre-attach watch gap renders single "(UTC)" (lts-3 closed);
- the ledger verbs refuse with the house "path not found" shape
  (F10 closed, the remedy suffix riding why's own);
- the window helps read s/m/h/d (F2 closed) and the clamp/refusal
  stderr rides the ASCII separator (F4 closed for the em-dash
  family);
- attach/detach idempotence held (12 programs, 12 links, 8 maps;
  28 pins removed; re-detach answers "nothing to detach");
- the honesty laws stayed visible in the dump: the root-refused
  update check ("recorded, not judged"), the ram verdict's named
  15% threshold ("this is unusual; investigate"), the sig verdict
  deciding the exit code, and the "snapshot and event window can
  disagree - that is the point" law.

Still open, all owner-decision wording seats (none are correctness
or safety defects): F1 (the four Pro mode rows drifting from the
verb helps), F3 (usage-shaped refusals riding the runtime exit
code), F4's warn-tier paint candidate, F5 (Commands-list punctuation
policy), F6 (sig hyphenation drift), F7 (negative range asks losing
the range name), F11 (the bare render's extra trailing newline),
F12 (the Pro mode global group order).

New observations from the same dump, recorded per the holds-seam
law - named in this window, not patched in it:

- the singular renders "1 ticks" (`doctor --symptom cpu`,
  `src/commands/doctor/cpu.rs:340`) and "1 packets" (twice per
  interface row, `doctor --symptom network`,
  `src/commands/doctor/network.rs:341`) - cosmetic, live values,
  no byte pin yet;
- the ID Plane detail nests two parenthetical groups
  ("unavailable (no pin estate (nothing to reconcile))");
- the event-window header writes "15:20:32 UTC" while every stamp
  writes "15:20:32 (UTC)" - two UTC conventions on one surface.

Release readiness note: the current lineage (e76c87b through
d19ef03) is GPG-unsigned, so the embedded depth-matrix honestly
verifies 5/6 with the D5 refusal ("bind releases to signed
commits/tags"). The signed era was e88876b (6/6 AUTHENTIC). Binding
the freeze lineage back to a signed commit or a signed tag is the
owner's release-engineering seat, not this session's.

CI seat: the wholesale gate went red from d0f7e6e onward and the
hunt found the real failure - shellcheck SC2086 on the manual
battery's intentional `$PORT_WIN` word splitting. The local sandbox
gate had warn-and-skipped 1b (no shellcheck installed there), a
blind spot, not a pass. Fixed in d19ef03: the window vars
(PORT_WIN, LEDGER_WIN, CLAMP_WIN) ride arrays with quoted
expansion - the same argv bytes, no SC2086. The wrong runner-umask
workflow step (37bdd5a) was reverted in abd323f with the corrected
record: the runner's checkout verifies 644/755 clean, the 664/775
artifact lived only in a local umask-0002 sandbox. Local parity now
carries the full pinned set (shellcheck 0.10.0, shfmt 3.10.0,
yamllint 1.38.0, actionlint 1.7.7, b3sum 1.8.7, bpf-linker 0.11.1,
nightly-2026-09-18) - a local gate without the tools is a blind
spot, and the record now says so.

The sweep instrument: `scripts/labs-exp/zejtron-manual-sweep.sh`
(night-dragon-fly-3) covers the whole -h/--help estate plus the
lanes the battery does not ride: the shadow-duplicate PATH lane,
the ceiling-accept and below-floor window boundaries, the d-unit
clamp interplay on the clamped lanes, the device and symlink
targets, the `--print-json`/`--raw` conflict, the
`doctor --symptom ram --raw` drill-down, the byte-equality laws
(bare vs -h vs --help, -V vs --version, `sig --print-json`
determinism), and the JSON validity pass on every --print-json
lane. The report lands at `zejtron-manual-sweep-report.txt`
(`ZEJTRON_SWEEP_OUT` overrides); the next wording/UX/JSON audit
runs on its dump.

## What the audit pass needs back

The captured `battery-output.txt` (or the pasted sections A, D, E, G,
H if size forces a split). Sections C/F/I can be trimmed to their
headers and exit lines on a first pass; the wording audit runs on A, B,
D, E, G and the JSON key shapes from F. The manual lane's
`zejtron-manual-battery-report.txt` (the privileged run included when
the host allows it) is the complete replacement: one file, every
probe's exact command beside its captured bytes, the JSON lanes whole.

## The fast-lane sweep confirmation (night-dragon-fly-5, 2026-11-26)

The sweep instrument (fly-3, the fast lane per fly-4: every window
probe rides the 1s floor, `ZEJTRON_SWEEP_FULL=1` restores the shipped
widths - no hourly waits anywhere) ran end to end on the owner's
machine against the installed dragon-3 binary (`/usr/bin/zejtron`,
e76c87b). Verdict: **150 passed, 0 failed, 15 recorded, 0 skipped**
across SW0-SW11 - the byte-equality laws, all ten verb flag matrices,
the clamp interplay, every `--print-json` lane, the UX bridge, the
pipe law, and the privileged attach lane.

Chain of trust for the dump: the net `git diff e76c87b..HEAD` touches
only `CHANGELOG.md`, this audit doc, and the two manual lab scripts -
no `src/`, `ebpf/`, or `test/` bytes move, so the swept binary carries
exactly the HEAD shipped code (59d6adf, seven commits later). CI rode
17/17 green at 59d6adf (CI,
Gate-keepers, the Supermassive legs including Kernel Witnesses, the
Floor, Alpine, E2E, Proofs, Miri, Fuzz, netrunner, Docs, CodeQL,
Security Audit, Reproducible Release). The window's earlier reds were
each remediated by their follow-up commits (the SC2086 quad fix
d19ef03, the umask revert abd323f, the sweep indent churn 59d6adf) -
the record rides the commit messages.

Third independent confirmation across two hardware estates and one
binary lineage; every fly-2 close-out re-verified from the live
bytes: the pre-attach watch gap renders single "(UTC)" (lts-3
closed); the ledger refusals speak the house shape with why's own
remedy suffix (F10 closed); the window helps read s/m/h/d (F2
closed) and the clamp stderr rides the ASCII separator (F4 closed);
attach/detach idempotence held (12 programs, 12 links, 8 maps; 28
pins removed; "nothing to detach" twice); the honesty laws stayed
visible - the pipe exit recorded with the 0/141 race named, the sig
verdict deciding the exit code with the JSON whole (UNSIGNED 5/6 on
the unsigned lineage), the ram verdict naming the 15% threshold in
text and JSON ("this is unusual; investigate"), and the unattached
port lane naming its remedy ("attach first: sudo zejtron doctor
--attach").

The recorded seams persist by construction, and the dump says so: the
F11 bare-render record stays open (the probe moves with the fix when
the owner closes it); the singular tick row fired again ("1 ticks";
the "1 packets" row did not fire this run - live counts rode above
1); the ID Plane nested parentheticals render ("unavailable (no pin
estate (nothing to reconcile))"); the two UTC conventions share the
why surface ("16:56:35 UTC" in the event-window header vs "(UTC)" in
the stamps). New observation, recorded per the holds-seam law - named
in this window, not patched in it: `port --print-json` owners ride
`OwnerIdentity` (pid, process, user - the Hash+Eq contract behind
`--group`) and omit the fd, so SO_REUSEPORT listeners (four distinct
fds on 127.0.0.1:53) render as identical JSON rows while the text
render names each fd. The rows are honest raw kernel rows; the JSON
disambiguation seat is the owner's call (N1).

Verdict: the fast-lane sweep is the final pre-release audit lane and
it holds - the whole -h/--help estate stays deterministic, honest,
and self-describing on the unprivileged default lane and on the
privileged attach lane. Nothing in the dump blocks the mature LTS
verdict. What remains is the owner's release-engineering seat (bind
the lineage to a signed commit or tag so D5 returns 6/6) and the
open wording seats (F1, F3, F4's paint candidate, F5, F6, F7, F11,
F12, N1) - all owner-decision items, none correctness or safety.

The sweep report landed and is audited above; no further capture is
owed for this label.

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
