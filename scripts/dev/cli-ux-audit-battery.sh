#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial
# OS: Linux only - zejtron is a Linux introspection tool.
#
# NON_LATIN_FIXTURE: the multibyte --since unit probes are the test
# vectors themselves (the parser must refuse them cleanly, no panic,
# night-dragon-lts-1); the CJK characters are the fixture, not prose.

# night-dragon-fly-1: the CLI/UX end-to-end audit battery.
#
# Runs every command the help surface advertises (root, all ten verbs,
# every flag lane) plus the parse-error, runtime-error, JSON, window
# clamp, color-capability, and exit-code lanes. Every probe captures
# stdout and stderr separately and records the exit code, so the
# captured file carries the full evidence an audit needs.
#
# Usage:
#   bash scripts/dev/cli-ux-audit-battery.sh > battery-output.txt 2>&1
#
# Environment:
#   ZEJTRON_BIN                 path to the binary to probe
#                               (default: target/debug/zejtron, then
#                               target/release/zejtron, then $PATH)
#   ZEJTRON_BATTERY_MAX_LINES   per-stream capture cap (default 120;
#                               0 = unlimited)
#   ZEJTRON_BATTERY_WITH_ROOT   1 = include the privileged eBPF
#                               probes (doctor --attach/--detach);
#                               default 0 = skip them
#
# Every probe line carries the expected behavior named from source
# (the CLI structs and the command modules are the wording authority).
# Send the whole captured file back for the audit pass.

set -u

MAX_LINES="${ZEJTRON_BATTERY_MAX_LINES:-120}"
WITH_ROOT="${ZEJTRON_BATTERY_WITH_ROOT:-0}"

ZEJTRON_BIN="${ZEJTRON_BIN:-}"
if [ -z "$ZEJTRON_BIN" ]; then
	for candidate in target/debug/zejtron target/release/zejtron; do
		if [ -x "$candidate" ]; then
			ZEJTRON_BIN="$candidate"
			break
		fi
	done
fi
if [ -z "$ZEJTRON_BIN" ]; then
	ZEJTRON_BIN="$(command -v zejtron 2>/dev/null || true)"
fi
if [ ! -x "${ZEJTRON_BIN:-}" ]; then
	echo "zejtron binary not found. Build it (cargo build) or set ZEJTRON_BIN=/path/to/zejtron" >&2
	exit 1
fi

if command -v jq >/dev/null 2>&1; then
	JQ="jq"
else
	JQ=""
fi

TMP_OUT="$(mktemp)"
TMP_ERR="$(mktemp)"
trap 'rm -f "$TMP_OUT" "$TMP_ERR"' EXIT

# dump <file> <label>: print a captured stream, capped at MAX_LINES.
dump_stream() {
	local file="$1" label="$2"
	local total
	total="$(wc -l <"$file")"
	if [ "$MAX_LINES" -gt 0 ] && [ "$total" -gt "$MAX_LINES" ]; then
		echo "--- $label (first $MAX_LINES of $total lines) ---"
		head -n "$MAX_LINES" "$file"
		echo "--- $label truncated ($((total - MAX_LINES)) more lines) ---"
	else
		echo "--- $label ($total lines) ---"
		cat "$file"
	fi
}

# section <title>
section() {
	echo ""
	echo "================================================================================"
	echo "== $1"
	echo "================================================================================"
}

# probe <id> <expected> <command string>
# Runs the command through bash -c so env prefixes, pipes, and
# redirections work verbatim; captures the two streams apart and the
# exit code of the whole pipeline.
probe() {
	local id="$1" expected="$2" cmd="$3"
	: >"$TMP_OUT"
	: >"$TMP_ERR"
	bash -c "$cmd" >"$TMP_OUT" 2>"$TMP_ERR"
	local rc=$?
	echo ""
	echo "### [$id]"
	echo "# expected: $expected"
	echo "\$ $cmd"
	dump_stream "$TMP_OUT" "stdout"
	dump_stream "$TMP_ERR" "stderr"
	echo "--- exit: $rc ---"
}

JQ_NOTE="one line, jq-valid, exit 0"

echo "zejtron CLI/UX audit battery - night-dragon-fly-1"
echo "binary: $ZEJTRON_BIN"
echo "jq: ${JQ:-absent (JSON validity probes degrade to line counts)}"
echo "max lines per stream: $MAX_LINES"
echo "privileged probes: $WITH_ROOT"
echo "host: $(uname -sr)"

# ---------------------------------------------------------------------------
section "A. Root surface: bare, -h/--help, -V/--version, globals"
# ---------------------------------------------------------------------------

probe "A1 bare invocation" \
	"exit 0, stdout; byte-identical to A2 (the branded builder, cli/mod.rs help_command)" \
	"\"$ZEJTRON_BIN\""
probe "A2 root -h" \
	"exit 0, stdout: banner, about, usage line, 10 verbs each with an Example row, Options (-v/--verbose, --check-update, -h/--help, -V/--version), Pro mode section, Quick examples section" \
	"\"$ZEJTRON_BIN\" -h"
probe "A3 root --help" \
	"exit 0, stdout; byte-identical to A2" \
	"\"$ZEJTRON_BIN\" --help"
probe "A4 root -V" \
	"exit 0, stdout: the full version report (brand header, version, git hash, build info)" \
	"\"$ZEJTRON_BIN\" -V"
probe "A5 root --version" \
	"exit 0, stdout; byte-identical to A4" \
	"\"$ZEJTRON_BIN\" --version"
probe "A6 bare -v (verbose alone)" \
	"documents the parse result: verbose is global and dispatches nothing, so the bare help renders; exit 0" \
	"\"$ZEJTRON_BIN\" -v"
probe "A7 --check-update" \
	"network probe; exit 0 with the branded status report, or exit 1 'update check failed: ...' offline" \
	"\"$ZEJTRON_BIN\" --check-update"
probe "A8 root -h on a pipe" \
	"plain bytes, zero escape sequences (the capability ladder's Mono lane)" \
	"\"$ZEJTRON_BIN\" -h | cat -v"
probe "A9 NO_COLOR -h" \
	"plain bytes even on a color terminal" \
	"NO_COLOR=1 \"$ZEJTRON_BIN\" -h | cat -v"
probe "A10 CLICOLOR_FORCE -h on a pipe" \
	"ANSI escapes present (grey grammar rows, green verb tokens, purple headings)" \
	"CLICOLOR_FORCE=1 \"$ZEJTRON_BIN\" -h | cat -v | head -n 40"

# ---------------------------------------------------------------------------
section "B. Per-verb help surfaces (-h, --help, -V short-circuit, alias)"
# ---------------------------------------------------------------------------

for verb in path recent port proc holds touch why doctor net sig; do
	probe "B $verb -h" \
		"exit 0, stdout: usage line ('zejtron $verb ... or [options] e.g ...'), the verb's flags in the pinned row order (-V, -v, -h), Examples section" \
		"\"$ZEJTRON_BIN\" $verb -h"
done
probe "B sig alias --help" \
	"'zejtron signature' resolves to the sig help (alias, cli/mod.rs)" \
	"\"$ZEJTRON_BIN\" signature --help"
probe "B path -V short-circuit" \
	"exit 0, stdout: the version report, NOT a missing-operand usage error (the global -V fires before required positionals)" \
	"\"$ZEJTRON_BIN\" path -V"
probe "B proc -V short-circuit" \
	"same short-circuit law on a verb with a required-ish target group" \
	"\"$ZEJTRON_BIN\" proc -V"
probe "B holds -V short-circuit" \
	"same short-circuit law on a verb with a required positional" \
	"\"$ZEJTRON_BIN\" holds -V"
probe "B touch -V short-circuit" \
	"same short-circuit law" \
	"\"$ZEJTRON_BIN\" touch -V"
probe "B why -V short-circuit" \
	"same short-circuit law" \
	"\"$ZEJTRON_BIN\" why -V"
probe "B -v after verb (global flag order freedom)" \
	"parses wherever it sits; the render is unchanged, diagnostics ride stderr only" \
	"\"$ZEJTRON_BIN\" net -v 2>/dev/null"

# ---------------------------------------------------------------------------
section "C. Happy paths (read-only defaults, one probe per lane)"
# ---------------------------------------------------------------------------

probe "C path hit" \
	"exit 0, stdout: the resolution report for sh" \
	"\"$ZEJTRON_BIN\" path sh"
probe "C path miss" \
	"exit 1 (runtime), 'command not found in PATH:' block" \
	"\"$ZEJTRON_BIN\" path definitely-not-a-command-xyz"
probe "C recent default" \
	"exit 0, stdout: newest-first rows, default limit 20, default path ." \
	"\"$ZEJTRON_BIN\" recent ."
probe "C recent --limit 5" \
	"exit 0: at most 5 rows" \
	"\"$ZEJTRON_BIN\" recent --limit 5 ."
probe "C recent --since 1h" \
	"exit 0: only files newer than 1h" \
	"\"$ZEJTRON_BIN\" recent --since 1h ."
probe "C port default" \
	"exit 0, stdout: snapshot table + 60s event window, banner frame" \
	"\"$ZEJTRON_BIN\" port"
probe "C port --tcp --numeric" \
	"exit 0: numeric addresses, tcp only" \
	"\"$ZEJTRON_BIN\" port --tcp --numeric"
probe "C port 22" \
	"exit 0 (or the 'no owner' honest row when nothing listens): scoped to port 22" \
	"\"$ZEJTRON_BIN\" port 22"
probe "C port --listen" \
	"exit 0: listening/bound only" \
	"\"$ZEJTRON_BIN\" port --listen"
probe "C port --group" \
	"exit 0: repeated rendered rows collapsed" \
	"\"$ZEJTRON_BIN\" port --group"
probe "C port --no-pid" \
	"exit 0: owner lines without process ids" \
	"\"$ZEJTRON_BIN\" port --no-pid"
probe "C port --events-only" \
	"exit 0: event window only, no snapshot" \
	"\"$ZEJTRON_BIN\" port --events-only"
probe "C port --snapshot-only" \
	"exit 0: snapshot only, no window" \
	"\"$ZEJTRON_BIN\" port --snapshot-only"
probe "C proc --me" \
	"exit 0, stdout: the process tree of the current user" \
	"\"$ZEJTRON_BIN\" proc --me"
probe "C proc --find ssh" \
	"exit 0: families matching the substring (may be the honest empty state)" \
	"\"$ZEJTRON_BIN\" proc --find ssh"
probe "C proc --depth 2" \
	"exit 0: tree depth capped at 2" \
	"\"$ZEJTRON_BIN\" proc --me --depth 2"
probe "C proc --no-pid --no-color" \
	"exit 0: no pid labels, no ANSI even on a tty" \
	"\"$ZEJTRON_BIN\" proc --me --no-pid --no-color"
probe "C holds file target" \
	"exit 0: who holds /etc/resolv.conf" \
	"\"$ZEJTRON_BIN\" holds /etc/resolv.conf"
probe "C holds port target" \
	"exit 0: the target grammar accepts a bare port number" \
	"\"$ZEJTRON_BIN\" holds 22"
probe "C touch hit" \
	"exit 0: last-change report for /etc/hosts" \
	"\"$ZEJTRON_BIN\" touch /etc/hosts"
probe "C why file target" \
	"exit 0: the evidence report for /etc/passwd" \
	"\"$ZEJTRON_BIN\" why /etc/passwd"
probe "C why --trace" \
	"exit 0: the explainability ladder appended per row" \
	"\"$ZEJTRON_BIN\" why /etc/passwd --trace"
probe "C why --raw" \
	"exit 0: raw kernel events appended" \
	"\"$ZEJTRON_BIN\" why /etc/passwd --raw"
probe "C why --trace --raw (stacked)" \
	"exit 0: BOTH drill-downs append (print_json is the only lane that excludes them)" \
	"\"$ZEJTRON_BIN\" why /etc/passwd --trace --raw"
probe "C doctor readiness" \
	"exit 0: the readiness report (no eBPF attach without the flag)" \
	"\"$ZEJTRON_BIN\" doctor"
probe "C doctor --symptom ram" \
	"exit 0: the memory symptom report" \
	"\"$ZEJTRON_BIN\" doctor --symptom ram"
probe "C doctor --symptom slow" \
	"exit 0: the composite slow report" \
	"\"$ZEJTRON_BIN\" doctor --symptom slow"
probe "C doctor --symptom gpu" \
	"exit 0 or the honest no-gpu shape: gpu may be absent on this host" \
	"\"$ZEJTRON_BIN\" doctor --symptom gpu"
probe "C doctor --symptom ram --raw" \
	"exit 0: raw /proc reads appended under --symptom" \
	"\"$ZEJTRON_BIN\" doctor --symptom ram --raw"
probe "C net" \
	"exit 0: interfaces + routing report" \
	"\"$ZEJTRON_BIN\" net"
probe "C sig" \
	"exit 0: the embedded signature depth matrix" \
	"\"$ZEJTRON_BIN\" sig"

# ---------------------------------------------------------------------------
section "D. Parse-error lanes (exit 2, stderr, the one-tip contract)"
# ---------------------------------------------------------------------------

probe "D stat (near-miss table)" \
	"exit 2, tip: did you mean 'sig (signature)' or 'doctor (status)'?" \
	"\"$ZEJTRON_BIN\" stat"
probe "D status (near-miss table)" \
	"exit 2, same two-successor tip" \
	"\"$ZEJTRON_BIN\" status"
probe "D PORT uppercase (CI subcommand fallback)" \
	"exit 2, tip: a subcommand similar to 'port' exists" \
	"\"$ZEJTRON_BIN\" PORT"
probe "D WHOHOLDS uppercase (redirect is exact-match only)" \
	"exit 2; observe which tip lands: the redirect table misses uppercase, so the CI fallback or a bare error answers" \
	"\"$ZEJTRON_BIN\" WHOHOLDS"
probe "D whoholds (exact redirect)" \
	"exit 2, tip: a subcommand 'holds' exists (migration redirect)" \
	"\"$ZEJTRON_BIN\" whoholds"
probe "D lasttouch (exact redirect)" \
	"exit 2, tip: 'touch'" \
	"\"$ZEJTRON_BIN\" lasttouch"
probe "D whyopen (exact redirect)" \
	"exit 2, tip: 'why'" \
	"\"$ZEJTRON_BIN\" whyopen"
probe "D envpath (exact redirect)" \
	"exit 2, tip: 'path'" \
	"\"$ZEJTRON_BIN\" envpath"
probe "D help (muscle-memory redirect)" \
	"exit 2, tip: to see the reference, run 'zejtron --help'" \
	"\"$ZEJTRON_BIN\" help"
probe "D unknown verb zzzqqq" \
	"exit 2, generic unrecognized-subcommand error, honest tip-less or clap's own candidate" \
	"\"$ZEJTRON_BIN\" zzzqqq"
probe "D proc --ME uppercase (CI flag fallback)" \
	"exit 2, tip: a flag '--me' exists (the case-insensitive rescue clap lacks)" \
	"\"$ZEJTRON_BIN\" proc --ME"
probe "D --ME at root scope" \
	"exit 2: --me is proc-scoped, the root pool cannot name it; observe the honest tip-less shape" \
	"\"$ZEJTRON_BIN\" --ME"
probe "D --check-updated (retired alias)" \
	"exit 2, tip: '--check-update' (the top-level-authority rescue)" \
	"\"$ZEJTRON_BIN\" --check-updated"
probe "D port --tcpp typo" \
	"exit 2, tip: '--tcp'" \
	"\"$ZEJTRON_BIN\" port --tcpp"
probe "D holds --tcp (foreign flag)" \
	"exit 2: holds has no tcp; observe whether any tip lands (the pool is since/print-json/verbose/help/version)" \
	"\"$ZEJTRON_BIN\" holds --tcp"
probe "D net --since 5m (foreign flag)" \
	"exit 2: net has no since; observe the tip lane" \
	"\"$ZEJTRON_BIN\" net --since 5m"
probe "D port --listen --all conflict" \
	"exit 2, clap conflict render naming both flags" \
	"\"$ZEJTRON_BIN\" port --listen --all"
probe "D port --events-only --snapshot-only conflict" \
	"exit 2 (clap catches it before the runtime double guard in port.rs)" \
	"\"$ZEJTRON_BIN\" port --events-only --snapshot-only"
probe "D why --trace --print-json conflict" \
	"exit 2, conflict render (print_json excludes trace and raw)" \
	"\"$ZEJTRON_BIN\" why /etc/passwd --trace --print-json"
probe "D doctor --attach --detach conflict" \
	"exit 2, conflict render" \
	"\"$ZEJTRON_BIN\" doctor --attach --detach"
probe "D doctor --attach --print-json conflict" \
	"exit 2, conflict render" \
	"\"$ZEJTRON_BIN\" doctor --attach --print-json"
probe "D proc root --me (target group)" \
	"exit 2, 'cannot be used with' render (user_or_uid and me are exclusive)" \
	"\"$ZEJTRON_BIN\" proc root --me"
probe "D doctor --raw without --symptom" \
	"exit 1 (RUNTIME lane, not clap): '--raw requires --symptom' - observe whether this usage-shaped refusal belongs at exit 2 instead" \
	"\"$ZEJTRON_BIN\" doctor --raw"
probe "D recent --limit 1000001 (ceiling)" \
	"exit 2, the named range refusal with the range in the message" \
	"\"$ZEJTRON_BIN\" recent --limit 1000001 ."
probe "D recent --limit -1" \
	"exit 2, range refusal" \
	"\"$ZEJTRON_BIN\" recent --limit -1 ."
probe "D recent --limit abc" \
	"exit 2, invalid-value render" \
	"\"$ZEJTRON_BIN\" recent --limit abc ."
probe "D recent --limit overflow digits" \
	"exit 2, the i64 parse refusal (no silent wrap)" \
	"\"$ZEJTRON_BIN\" recent --limit 99999999999999999999 ."
probe "D proc --depth 0 (floor)" \
	"exit 2, range refusal (1-1024)" \
	"\"$ZEJTRON_BIN\" proc --me --depth 0"
probe "D proc --depth 1025 (ceiling)" \
	"exit 2, range refusal" \
	"\"$ZEJTRON_BIN\" proc --me --depth 1025"
probe "D proc --depth -5 (allow_hyphen_values)" \
	"exit 2: the hyphen value rides the parser; observed wording is 'invalid digit found in string' (the negative ask does not name the 1-1024 range the positive asks do)" \
	"\"$ZEJTRON_BIN\" proc --me --depth -5"
probe "D holds -- --tcp (escape hatch)" \
	"exit 1: '--tcp' becomes the TARGET operand and dies as 'no such file or directory', not as a flag error" \
	"\"$ZEJTRON_BIN\" holds -- --tcp"
probe "D path empty operand" \
	"exit 1 or 2: observe the empty-operand wording for path (port has a dedicated guard)" \
	"\"$ZEJTRON_BIN\" path \"\""
probe "D non-UTF-8 operand into holds" \
	"exit 2 with the branded clap render ('invalid UTF-8 was detected in one or more arguments'), NEVER exit 101/panic (the argv_lossy law)" \
	"\"$ZEJTRON_BIN\" holds \$'\\xff\\xfe'"

# ---------------------------------------------------------------------------
section "E. Runtime error lanes (exit 1, the 'error:' labeled block)"
# ---------------------------------------------------------------------------

probe "E port abc" \
	"exit 1, 'error: invalid port: abc'" \
	"\"$ZEJTRON_BIN\" port abc"
probe "E port 0" \
	"exit 1, invalid port (port 0 is refused)" \
	"\"$ZEJTRON_BIN\" port 0"
probe "E port 99999 (u16 overflow)" \
	"exit 1, invalid port" \
	"\"$ZEJTRON_BIN\" port 99999"
probe "E port empty operand" \
	"exit 1, 'the port is empty (e.g. zejtron port 22)'" \
	"\"$ZEJTRON_BIN\" port \"\""
probe "E holds missing file" \
	"exit 1, '<operand>: no such file or directory'" \
	"\"$ZEJTRON_BIN\" holds /nonexistent-path-xyz"
probe "E touch missing path" \
	"exit 1, 'path not found: /nonexistent-path-xyz'" \
	"\"$ZEJTRON_BIN\" touch /nonexistent-path-xyz"
probe "E proc unknown user" \
	"exit 1, 'unknown user: nouserxyz123'" \
	"\"$ZEJTRON_BIN\" proc nouserxyz123"
probe "E doctor --symptom xyz" \
	"exit 1, \"unknown symptom 'xyz' - the symptoms this version speaks: ram, cpu, disk, network, gpu, slow\" - observe: the code calls this a usage error while the house law says usage errors exit 2" \
	"\"$ZEJTRON_BIN\" doctor --symptom xyz"
probe "E port --since 3x (invalid duration)" \
	"exit 1, 'invalid duration: 3x (use e.g. 30s, 10m, 1h)'" \
	"\"$ZEJTRON_BIN\" port --since 3x"
probe "E recent --since 3x" \
	"exit 1, 'invalid duration: 3x (use e.g. 30s, 10m, 2h, 7d)' - note the two examples DIFFER from the window parser" \
	"\"$ZEJTRON_BIN\" recent --since 3x"
probe "E recent --since multibyte unit" \
	"exit 1, clean refusal (no panic, night-dragon-lts-1)" \
	"\"$ZEJTRON_BIN\" recent --since 5分"
probe "E recent --limit 0 (the honest cut)" \
	"exit 0: the render must name the limit-0 cut, never disguise it as 'no modified files found'" \
	"\"$ZEJTRON_BIN\" recent --limit 0 ."

# ---------------------------------------------------------------------------
section "F. JSON lanes (--print-json: one line, jq-valid, stream-clean)"
# ---------------------------------------------------------------------------

if [ -n "$JQ" ]; then
	JSON_CHECK='| '"$JQ"' -e . >/dev/null 2>&1 && echo "jq: VALID" || echo "jq: INVALID"'
else
	JSON_CHECK='|| echo "(jq absent - validity not checked)"'
fi

probe "F path --print-json" "$JQ_NOTE" "\"$ZEJTRON_BIN\" path sh --print-json | awk '{print \"lines=\"NR} END{if(NR==0)print \"lines=0\"}' ; \"$ZEJTRON_BIN\" path sh --print-json $JSON_CHECK"
probe "F recent --print-json" "$JQ_NOTE" "\"$ZEJTRON_BIN\" recent --limit 3 . --print-json | wc -l ; \"$ZEJTRON_BIN\" recent --limit 3 . --print-json $JSON_CHECK"
probe "F port --print-json" "$JQ_NOTE" "\"$ZEJTRON_BIN\" port --print-json | wc -l ; \"$ZEJTRON_BIN\" port --print-json $JSON_CHECK"
probe "F proc --print-json" "$JQ_NOTE" "\"$ZEJTRON_BIN\" proc --me --print-json | wc -l ; \"$ZEJTRON_BIN\" proc --me --print-json $JSON_CHECK"
probe "F holds --print-json" "$JQ_NOTE" "\"$ZEJTRON_BIN\" holds /etc/resolv.conf --print-json | wc -l ; \"$ZEJTRON_BIN\" holds /etc/resolv.conf --print-json $JSON_CHECK"
probe "F touch --print-json" "$JQ_NOTE" "\"$ZEJTRON_BIN\" touch /etc/hosts --print-json | wc -l ; \"$ZEJTRON_BIN\" touch /etc/hosts --print-json $JSON_CHECK"
probe "F why --print-json" "$JQ_NOTE" "\"$ZEJTRON_BIN\" why /etc/passwd --print-json | wc -l ; \"$ZEJTRON_BIN\" why /etc/passwd --print-json $JSON_CHECK"
probe "F doctor --print-json" "$JQ_NOTE" "\"$ZEJTRON_BIN\" doctor --print-json | wc -l ; \"$ZEJTRON_BIN\" doctor --print-json $JSON_CHECK"
probe "F doctor --symptom ram --print-json" "$JQ_NOTE" "\"$ZEJTRON_BIN\" doctor --symptom ram --print-json | wc -l ; \"$ZEJTRON_BIN\" doctor --symptom ram --print-json $JSON_CHECK"
probe "F net --print-json" "$JQ_NOTE" "\"$ZEJTRON_BIN\" net --print-json | wc -l ; \"$ZEJTRON_BIN\" net --print-json $JSON_CHECK"
probe "F sig --print-json" "$JQ_NOTE" "\"$ZEJTRON_BIN\" sig --print-json | wc -l ; \"$ZEJTRON_BIN\" sig --print-json $JSON_CHECK"
probe "F json key shapes" \
	"observe the top-level key naming per verb (snake_case consistency, schema stability)" \
	"\"$ZEJTRON_BIN\" why /etc/passwd --print-json | $JQ -c 'keys' 2>/dev/null || true; \"$ZEJTRON_BIN\" port --print-json | $JQ -c 'keys' 2>/dev/null || true; \"$ZEJTRON_BIN\" doctor --print-json | $JQ -c 'keys' 2>/dev/null || true"

# ---------------------------------------------------------------------------
section "G. Window clamp lanes (since: s/m/h/d accepted, [1s,1h] enforced)"
# ---------------------------------------------------------------------------

probe "G port --since 100h (over ceiling)" \
	"exit 0; STDERR carries 'warning: --since 100h exceeds the 1h maximum - clamped to 1h', stdout stays clean" \
	"\"$ZEJTRON_BIN\" port --since 100h --snapshot-only"
probe "G clamp note stream separation" \
	"stdout must be byte-clean (no warning) with stderr dropped" \
	"\"$ZEJTRON_BIN\" port --since 100h --snapshot-only 2>/dev/null | head -n 5"
probe "G clamp note alone on stderr" \
	"only the warning line lands here" \
	"\"$ZEJTRON_BIN\" port --since 100h --snapshot-only 2>&1 >/dev/null"
probe "G port --since 0s (under floor)" \
	"exit 0; stderr: 'warning: --since 0s below the 1s minimum - clamped to 1s'" \
	"\"$ZEJTRON_BIN\" port --since 0s --snapshot-only"
probe "G port --since 7d (the 'd' unit gap)" \
	"exit 0 AND CLAMPED: the parser accepts 'd' while the help and the refusal examples say s/m/h - the documented-grammar gap" \
	"\"$ZEJTRON_BIN\" port --since 7d --snapshot-only"
probe "G port --since 18446744073709551h (u64 saturation)" \
	"exit 0, clamped to 1h, no panic (the saturating law)" \
	"\"$ZEJTRON_BIN\" port --since 18446744073709551h --snapshot-only"
probe "G recent --since 100h (no clamp by design)" \
	"exit 0, NO warning line: recent is an age filter, the ask rides as-is" \
	"\"$ZEJTRON_BIN\" recent --since 100h . | head -n 5"
probe "G holds --since 500m (legal unit)" \
	"exit 0, clamped window (500m > 1h)" \
	"\"$ZEJTRON_BIN\" holds /etc/resolv.conf --since 500m"
probe "G clamp note + JSON together" \
	"the JSON lane stays pure: one JSON line on stdout, the warning on stderr" \
	"\"$ZEJTRON_BIN\" port --since 100h --print-json 2>/dev/null | wc -l"

# ---------------------------------------------------------------------------
section "H. Exit-code matrix and pipe citizenship"
# ---------------------------------------------------------------------------

probe "H exit: -h" "0" "\"$ZEJTRON_BIN\" -h >/dev/null 2>&1; echo rc=\$?"
probe "H exit: bare" "0" "\"$ZEJTRON_BIN\" >/dev/null 2>&1; echo rc=\$?"
probe "H exit: -V" "0" "\"$ZEJTRON_BIN\" -V >/dev/null 2>&1; echo rc=\$?"
probe "H exit: unknown verb" "2" "\"$ZEJTRON_BIN\" zzzqqq >/dev/null 2>&1; echo rc=\$?"
probe "H exit: unknown flag" "2" "\"$ZEJTRON_BIN\" --zzz >/dev/null 2>&1; echo rc=\$?"
probe "H exit: conflict" "2" "\"$ZEJTRON_BIN\" port --listen --all >/dev/null 2>&1; echo rc=\$?"
probe "H exit: invalid port" "1" "\"$ZEJTRON_BIN\" port abc >/dev/null 2>&1; echo rc=\$?"
probe "H exit: unknown symptom" "1 (audit question: usage-shaped but runtime-coded)" "\"$ZEJTRON_BIN\" doctor --symptom xyz >/dev/null 2>&1; echo rc=\$?"
probe "H exit: doctor --raw without symptom" "1 (audit question: usage-shaped but runtime-coded)" "\"$ZEJTRON_BIN\" doctor --raw >/dev/null 2>&1; echo rc=\$?"
probe "H SIGPIPE: json into an early-closing head" \
	"rc=0 when the render fits the pipe buffer (a one-line JSON does); 141 when a render exceeds it - the UNIX pipe law, never a Rust panic" \
	"\"$ZEJTRON_BIN\" proc --print-json 2>&1 | head -c 10 >/dev/null; echo \"left-pipe-rc=\${PIPESTATUS[0]}\""
probe "H SIGPIPE: help into head -1" \
	"no broken-pipe panic on stderr" \
	"\"$ZEJTRON_BIN\" -h 2>&1 | head -n 1"
probe "H verbose stays on stderr" \
	"stdout of -v lane unchanged; diagnostics (if any) suppressed by 2>/dev/null" \
	"\"$ZEJTRON_BIN\" net -v 2>/dev/null | head -n 5"

# ---------------------------------------------------------------------------
section "I. Color capability lanes on a DATA surface"
# ---------------------------------------------------------------------------

probe "I sig on a pipe" \
	"plain bytes, no escapes" \
	"\"$ZEJTRON_BIN\" sig | cat -v | head -n 30"
probe "I sig forced color on a pipe" \
	"escapes visible: purple banner, bold verdict tokens, tier palette" \
	"CLICOLOR_FORCE=1 \"$ZEJTRON_BIN\" sig | cat -v | head -n 30"
probe "I NO_COLOR doctor symptom" \
	"plain bytes on the symptom report" \
	"NO_COLOR=1 \"$ZEJTRON_BIN\" doctor --symptom ram | cat -v | head -n 30"
probe "I error lane color" \
	"the 'error:' label bold red on a forced pipe" \
	"CLICOLOR_FORCE=1 \"$ZEJTRON_BIN\" port abc 2>&1 >/dev/null | cat -v"

# ---------------------------------------------------------------------------
section "J. Privileged eBPF probes (ZEJTRON_BATTERY_WITH_ROOT=1 only)"
# ---------------------------------------------------------------------------

if [ "$WITH_ROOT" = "1" ]; then
	probe "J doctor --attach" \
		"exit 0: the privileged one-shot attaches, pins, reports; root required" \
		"\"$ZEJTRON_BIN\" doctor --attach"
	probe "J doctor --detach" \
		"exit 0: unpins everything, idempotent" \
		"\"$ZEJTRON_BIN\" doctor --detach"
	probe "J doctor --attach --print-json" \
		"exit 2 conflict or the JSON attach report - observe which lane owns attach+json (clap says conflict)" \
		"\"$ZEJTRON_BIN\" doctor --attach --print-json"
else
	echo ""
	echo "### [J] skipped: set ZEJTRON_BATTERY_WITH_ROOT=1 (and run as root) to include the eBPF attach/detach probes"
fi

echo ""
echo "================================================================================"
echo "== battery complete"
echo "================================================================================"
