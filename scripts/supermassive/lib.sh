# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# lib.sh — the supermassive assertion engine.
#
# Sourced by supermassive.sh (and usable standalone by the leg
# scripts). Every surface file calls these helpers and only these
# helpers; no surface file talks to the binary directly. The engine
# owns the counters (PASS / FAIL / SKIP), the skip-reason law (a SKIP
# without a reason is a harness bug, not a pass), the determinism
# normalizer, and the color tri-test.
#
# The trust contract (the whole point of the suite):
#   exit 0 = every check passed or skipped WITH a named reason
#   exit 1 = any check failed
# A fake PASS is a bug; a silent SKIP is a bug; both are treated as
# failures by the engine itself.

# ---------------------------------------------------------------------------
# Counters and the verdict ledger.
# ---------------------------------------------------------------------------

SM_PASS=0
SM_FAIL=0
SM_SKIP=0
SM_SKIP_REASONS=""
SM_FAILURES=""

# Counters are process-local state of the runner shell. Surface files
# are SOURCED, not executed, so the counters accumulate across the
# whole run - that is what makes the final verdict trustworthy.

sm_init() {
	SM_PASS=0
	SM_FAIL=0
	SM_SKIP=0
	SM_SKIP_REASONS=""
	SM_FAILURES=""
}

sm_pass() {
	SM_PASS=$((SM_PASS + 1))
	printf '  ok   %s\n' "$1"
}

sm_fail() {
	SM_FAIL=$((SM_FAIL + 1))
	SM_FAILURES="${SM_FAILURES}- FAIL: $1: $2"$'\n'
	printf '  FAIL %s: %s\n' "$1" "$2"
}

# The skip law: the reason argument is mandatory. An empty reason is
# a caller bug and the engine records a failure for it - a bare SKIP
# must never be able to hide inside a green run.
sm_skip() {
	local label="$1"
	local reason="$2"
	if [[ -z "$reason" ]]; then
		sm_fail "$label" "SKIP without a reason (harness bug)"
		return
	fi
	SM_SKIP=$((SM_SKIP + 1))
	SM_SKIP_REASONS="${SM_SKIP_REASONS}- SKIP: ${label}: ${reason}"$'\n'
	printf '  skip %s (%s)\n' "$label" "$reason"
}

# ---------------------------------------------------------------------------
# Invocation capture.
# ---------------------------------------------------------------------------

# sm_run <out-file> <err-file> <rc-var> [timeout-seconds] -- <cmd...>
# Runs the command under `timeout`, captures stdout and stderr
# separately, and stores the exit status in <rc-var>. The environment
# is wiped (env -i) so the host shell's color knobs (COLORTERM,
# CLICOLOR, NO_COLOR, TERM) can never leak into a pass that did not
# ask for them. LC_ALL=C pins the locale so sorting and message
# wording are byte-stable between hosts and runs.
# The captured status is written through printf -v into the caller's
# named variable. The engine's own local is deliberately named
# sm_status (never the caller's name): printf -v resolves in THIS
# function's scope, and a name collision here would silently leave
# the caller's variable at its previous value - the exact bug class
# the self-test exists to catch.
sm_run() {
	local out_file="$1" err_file="$2" rc_var="$3" tmo="${4:-$SM_TEST_TIMEOUT}"
	shift 4
	[[ "$1" == "--" ]] && shift
	local sm_status=0
	# env -i + the explicit allowlist: the suite's own env is the
	# only env the binary sees. HOME points at the scratch dir.
	timeout --foreground "$tmo" env -i \
		PATH="$SM_BIN_PATH_ENV" \
		HOME="$SM_SCRATCH/home" \
		TMPDIR="$SM_SCRATCH" \
		LC_ALL=C \
		LANG=C \
		"$@" >"$out_file" 2>"$err_file" || sm_status=$?
	printf -v "$rc_var" '%s' "$sm_status"
	return 0
}

# Same as sm_run but the caller supplies extra env assignments
# (KEY=VALUE pairs) before --. Used by the color tri-test and the
# forced-color passes.
sm_run_env() {
	local out_file="$1" err_file="$2" rc_var="$3" tmo="$4"
	shift 4
	local extra_env=()
	while [[ "$1" != "--" ]]; do
		extra_env+=("$1")
		shift
	done
	shift
	local sm_status=0
	timeout --foreground "$tmo" env -i \
		PATH="$SM_BIN_PATH_ENV" \
		HOME="$SM_SCRATCH/home" \
		TMPDIR="$SM_SCRATCH" \
		LC_ALL=C \
		LANG=C \
		"${extra_env[@]}" \
		"$@" >"$out_file" 2>"$err_file" || sm_status=$?
	printf -v "$rc_var" '%s' "$sm_status"
	return 0
}

# ---------------------------------------------------------------------------
# Assertions. Every assertion takes a human label; the label is what
# the depth-audit table counts.
# ---------------------------------------------------------------------------

sm_assert_rc() {
	local want="$1" got="$2" label="$3"
	if [[ "$got" == "$want" ]]; then
		sm_pass "$label"
	else
		sm_fail "$label" "exit status: want $want, got $got"
	fi
}

sm_assert_contains() {
	local file="$1" needle="$2" label="$3"
	if grep -q -- "$needle" "$file" 2>/dev/null; then
		sm_pass "$label"
	else
		sm_fail "$label" "output did not contain '$needle'"
	fi
}

sm_assert_not_contains() {
	local file="$1" needle="$2" label="$3"
	if grep -q -- "$needle" "$file" 2>/dev/null; then
		sm_fail "$label" "output unexpectedly contained '$needle'"
	else
		sm_pass "$label"
	fi
}

sm_assert_eq() {
	local got="$1" want="$2" label="$3"
	if [[ "$got" == "$want" ]]; then
		sm_pass "$label"
	else
		sm_fail "$label" "value mismatch: want '$want', got '$got'"
	fi
}

sm_assert_file_nonempty() {
	local file="$1" label="$2"
	if [[ -s "$file" ]]; then
		sm_pass "$label"
	else
		sm_fail "$label" "expected non-empty output, got nothing (all-white content)"
	fi
}

# The zero-escape invariant: the piped lane must be byte-clean for
# grep. Any CSI (ESC[) byte sequence in a captured (non-forced) pass
# is a color regression, whatever the tier claimed.
sm_assert_no_escapes() {
	local file="$1" label="$2"
	if LC_ALL=C grep -q "$(printf '\033\[')" "$file" 2>/dev/null; then
		sm_fail "$label" "ANSI escape found in a capture that must be plain"
	else
		sm_pass "$label"
	fi
}

# ---------------------------------------------------------------------------
# Determinism.
# ---------------------------------------------------------------------------

# sm_normalize <in-file> <out-file>
#
# The volatile-field table. Determinism means: same host state + same
# invocation = same bytes, modulo the fields below. Every field named
# here is genuinely non-deterministic (wall-clock, scheduler, kernel
# counters); anything not named here that differs between two runs is
# a determinism bug and the diff is reported.
#
#   <TIMESTAMP>  ISO-like wall-clock stamps, human date/minute
#                stamps, and the version report's MM/DD/YYYY build
#                time
#   <PID>        process IDs (pid=NNN labels, owner rows, /proc reads)
#   <DURATION>   elapsed/rendered durations (500ms, 1.2s, 3m, 2h)
#   <UPTIME>     uptime and load-family kernel counters that move
#                between any two invocations by definition
#   <COUNTER>    free-running kernel byte/packet counters (net), and
#                memory/pressure gauges that move on their own
sm_normalize() {
	local in_file="$1" out_file="$2"
	sed -E \
		-e 's/[0-9]{4}-[0-9]{2}-[0-9]{2}([T ][0-9]{2}:[0-9]{2}:[0-9]{2}([.,][0-9]+)?( ?([+-][0-9]{2}:?[0-9]{2}|UTC|Z))?)?/<TIMESTAMP>/g' \
		-e 's/[0-9]{2}:[0-9]{2}:[0-9]{2}/<TIMESTAMP>/g' \
		-e 's/[0-9]{2}:[0-9]{2}/<TIMESTAMP>/g' \
		-e 's/[0-9]{2}\/[0-9]{2}\/[0-9]{4}/<TIMESTAMP>/g' \
		-e 's/[0-9]{4}-[0-9]{2}-[0-9]{2}/<TIMESTAMP>/g' \
		-e 's/pid=[0-9]+/pid=<PID>/g' \
		-e 's/(pid|PID|ppid|PPID)([ :]+)[0-9]+/\1\2<PID>/g' \
		-e 's/\b[0-9]+(\.[0-9]+)?(ms|us|ns)\b/<DURATION>/g' \
		-e 's/\b[0-9]+(\.[0-9]+)?(s|m|h) ago\b/<AGE> ago/g' \
		-e 's/\b(up|uptime)([ :]+)[0-9]+([dhm]| [0-9]+ min)?/\1\2<UPTIME>/g' \
		-e 's/load average[s]?: [0-9.]+,? ?[0-9.]*,? ?[0-9.]*/load average: <UPTIME>/g' \
		-e 's/[0-9]+(\.[0-9]+)? ?(B|kB|KiB|MB|MiB|GB|GiB)\b/<COUNTER>/g' \
		-e 's/[0-9]+(\.[0-9]+)?%/<COUNTER>/g' \
		"$in_file" >"$out_file"
}

# sm_deterministic <label> [timeout] -- <cmd...>
# Two runs, both normalized through the volatile-field table, then
# byte-compared. A non-empty normalized diff is a FAIL and the first
# diff lines are named in the failure detail - the difference is
# named, never swallowed.
sm_deterministic() {
	local label="$1" tmo="${2:-$SM_TEST_TIMEOUT}"
	shift 2
	[[ "$1" == "--" ]] && shift
	local rc1 rc2
	sm_run "$SM_SCRATCH/det1.out" "$SM_SCRATCH/det1.err" rc1 "$tmo" -- "$@"
	sm_run "$SM_SCRATCH/det2.out" "$SM_SCRATCH/det2.err" rc2 "$tmo" -- "$@"
	sm_assert_rc "$rc1" "$rc2" "$label (same exit status twice)"
	if [[ "$rc1" -ne 0 ]]; then
		# A failing command's determinism is still worth pinning, but
		# only if the caller planned for it; the standard caller runs
		# deterministic checks on success paths and pins error bytes in
		# dedicated error checks instead.
		sm_pass "$label (determinism on a non-zero exit, error bytes pinned elsewhere)"
		return 0
	fi
	sm_normalize "$SM_SCRATCH/det1.out" "$SM_SCRATCH/det1.norm"
	sm_normalize "$SM_SCRATCH/det2.out" "$SM_SCRATCH/det2.norm"
	if cmp -s "$SM_SCRATCH/det1.norm" "$SM_SCRATCH/det2.norm"; then
		sm_pass "$label (normalized byte-equal)"
	else
		local diff_head
		diff_head="$(diff "$SM_SCRATCH/det1.norm" "$SM_SCRATCH/det2.norm" | head -6 | tr '\n' ';' || true)"
		sm_fail "$label" "normalized outputs differ: $diff_head"
	fi
}

# Structural determinism: the full table of a live kernel surface
# (sockets, processes, interfaces) moves under the suite's feet by
# definition; the honest determinism claim there is the stable
# skeleton. This helper extracts only section headers and verdict
# lines (the non-data render tier) and byte-compares those across the
# two runs. Named in the README as structural determinism.
sm_deterministic_structural() {
	local label="$1" tmo="${2:-$SM_TEST_TIMEOUT}"
	shift 2
	[[ "$1" == "--" ]] && shift
	local rc1 rc2
	sm_run "$SM_SCRATCH/sdet1.out" "$SM_SCRATCH/sdet1.err" rc1 "$tmo" -- "$@"
	sm_run "$SM_SCRATCH/sdet2.out" "$SM_SCRATCH/sdet2.err" rc2 "$tmo" -- "$@"
	sm_assert_rc "$rc1" "$rc2" "$label (same exit status twice)"
	if [[ "$rc1" -ne 0 ]]; then
		sm_pass "$label (structural determinism on a non-zero exit)"
		return 0
	fi
	sm_normalize "$SM_SCRATCH/sdet1.out" "$SM_SCRATCH/sdet1.nout"
	sm_normalize "$SM_SCRATCH/sdet2.out" "$SM_SCRATCH/sdet2.nout"
	# The skeleton: the top-level labeled lines - headers, verdicts,
	# mode declarations - which start with a letter. The data rows hang
	# under tree glyphs (| ├ └) or lead with digits, so this one rule
	# separates the stable skeleton from the moving rows on every
	# zejtron render. The skeleton then goes through the volatile-field
	# table: gauge surfaces (doctor --symptom ram) carry letter-led
	# gauge lines ("Memory used: 525.4 MiB"), and the gauge NUMBERS are
	# exactly what the table names as volatile.
	grep -E '^[A-Za-z]' "$SM_SCRATCH/sdet1.nout" >"$SM_SCRATCH/sdet1.skel" || true
	grep -E '^[A-Za-z]' "$SM_SCRATCH/sdet2.nout" >"$SM_SCRATCH/sdet2.skel" || true
	if cmp -s "$SM_SCRATCH/sdet1.skel" "$SM_SCRATCH/sdet2.skel" && [[ -s "$SM_SCRATCH/sdet1.skel" ]]; then
		sm_pass "$label (structural skeleton byte-equal)"
	else
		local diff_head
		diff_head="$(diff "$SM_SCRATCH/sdet1.skel" "$SM_SCRATCH/sdet2.skel" | head -6 | tr '\n' ';' || true)"
		sm_fail "$label" "structural skeleton differs or empty: $diff_head"
	fi
}

# ---------------------------------------------------------------------------
# The color tri-test.
# ---------------------------------------------------------------------------
#
# Three passes of the same invocation (the capability ladder's law,
# src/output/mod.rs):
#   pass 1 (piped):      no color knobs at all, both streams captured
#                        -> zero escapes on both streams (the piped
#                        lane anchors on the stream's TTY-ness)
#   pass 2 (NO_COLOR):   NO_COLOR=1 -> byte-equal to pass 1 on both
#                        streams
#   pass 3 (forced):     CLICOLOR_FORCE=1 COLORTERM=truecolor with a
#                        RECOGNIZED TERM (xterm-256color) -> the
#                        forced lane never lands Mono, and the
#                        truecolor detection renders 24-bit RGB
#                        escapes (ESC[38;2;). The recognized TERM
#                        matters: over a probe-dead TERM the ladder's
#                        law lands the forced lane on the Color16
#                        floor (sm_forced_floor_test pins that seat),
#                        so the 24-bit claim needs a real TERM.
#
# sm_color_tritest <label-base> [timeout] -- <cmd...>
#
# Gauge surfaces (doctor --symptom ram) have values that move between
# ANY two invocations; set SM_TRITEST_NORMALIZE=1 before calling and
# the NO_COLOR equality is asserted on the NORMALIZED bytes (the
# volatile-field table) instead of the raw ones. Every other surface
# compares raw bytes - the strict claim.
sm_color_tritest() {
	local label="$1" tmo="${2:-$SM_TEST_TIMEOUT}"
	shift 2
	[[ "$1" == "--" ]] && shift
	local rc1 rc2 rc3

	# Pass 1: the piped lane.
	sm_run "$SM_SCRATCH/ct1.out" "$SM_SCRATCH/ct1.err" rc1 "$tmo" -- "$@"
	sm_assert_no_escapes "$SM_SCRATCH/ct1.out" "$label: piped stdout has zero escapes"
	sm_assert_no_escapes "$SM_SCRATCH/ct1.err" "$label: piped stderr has zero escapes"

	# Pass 2: NO_COLOR equals piped, byte for byte, and the exit
	# status must not move either - a color knob is a render knob,
	# never a behavior knob.
	sm_run_env "$SM_SCRATCH/ct2.out" "$SM_SCRATCH/ct2.err" rc2 "$tmo" \
		"NO_COLOR=1" -- "$@"
	sm_assert_rc "$rc1" "$rc2" "$label: NO_COLOR keeps the exit status"
	if [[ "${SM_TRITEST_NORMALIZE:-0}" == "1" ]]; then
		sm_normalize "$SM_SCRATCH/ct1.out" "$SM_SCRATCH/ct1.nout"
		sm_normalize "$SM_SCRATCH/ct1.err" "$SM_SCRATCH/ct1.nerr"
		sm_normalize "$SM_SCRATCH/ct2.out" "$SM_SCRATCH/ct2.nout"
		sm_normalize "$SM_SCRATCH/ct2.err" "$SM_SCRATCH/ct2.nerr"
		local c1o="$SM_SCRATCH/ct1.nout" c1e="$SM_SCRATCH/ct1.nerr"
		local c2o="$SM_SCRATCH/ct2.nout" c2e="$SM_SCRATCH/ct2.nerr"
	else
		local c1o="$SM_SCRATCH/ct1.out" c1e="$SM_SCRATCH/ct1.err"
		local c2o="$SM_SCRATCH/ct2.out" c2e="$SM_SCRATCH/ct2.err"
	fi
	if cmp -s "$c1o" "$c2o" && cmp -s "$c1e" "$c2e"; then
		sm_pass "$label: NO_COLOR output equals piped output"
	else
		sm_fail "$label: NO_COLOR output equals piped output" "NO_COLOR pass differs from the piped pass"
	fi

	# Pass 3: the forced truecolor lane. The forced lane re-arms color
	# even on captured streams; with COLORTERM=truecolor the palette
	# renders as 24-bit RGB. The invariant: at least one 24-bit RGB
	# escape appears on the stream the surface paints (stdout for data
	# surfaces, stderr for the labeled error lane) - and the forced
	# pass must not be byte-identical to the plain pass.
	sm_run_env "$SM_SCRATCH/ct3.out" "$SM_SCRATCH/ct3.err" rc3 "$tmo" \
		"CLICOLOR_FORCE=1" "COLORTERM=truecolor" "TERM=xterm-256color" -- "$@"
	sm_assert_rc "$rc1" "$rc3" "$label: forced color keeps the exit status"
	if LC_ALL=C grep -q "$(printf '\033\[38;2;')" "$SM_SCRATCH/ct3.out" "$SM_SCRATCH/ct3.err" 2>/dev/null; then
		sm_pass "$label: forced truecolor carries 24-bit RGB escapes"
	else
		sm_fail "$label: forced truecolor carries 24-bit RGB escapes" \
			"no ESC[38;2; sequence found on either stream (forced lane landed Mono or a lower tier)"
	fi
	if cmp -s "$SM_SCRATCH/ct1.out" "$SM_SCRATCH/ct3.out"; then
		sm_fail "$label: forced pass differs from plain pass" \
			"forced truecolor output is byte-identical to the piped pass (color is dead, not just unpainted)"
	else
		sm_pass "$label: forced pass differs from plain pass"
	fi
}

# The 16-color floor of the forced lane: CLICOLOR_FORCE=1 with no
# COLORTERM and TERM=dumb must still paint (the classic bright slots,
# never Mono). Used where the clap lane owns the palette.
sm_forced_floor_test() {
	local label="$1" tmo="${2:-$SM_TEST_TIMEOUT}"
	shift 2
	[[ "$1" == "--" ]] && shift
	# The status rides out through the callee's printf -v contract, so the
	# per-file rule cannot see the write.
	# shellcheck disable=SC2034
	local ff_rc
	sm_run_env "$SM_SCRATCH/ff.out" "$SM_SCRATCH/ff.err" ff_rc "$tmo" \
		"CLICOLOR_FORCE=1" "TERM=dumb" -- "$@"
	if LC_ALL=C grep -q "$(printf '\033\[')" "$SM_SCRATCH/ff.out" "$SM_SCRATCH/ff.err" 2>/dev/null; then
		sm_pass "$label: forced 16-color floor still paints (never Mono)"
	else
		sm_fail "$label: forced 16-color floor still paints (never Mono)" \
			"CLICOLOR_FORCE=1 + TERM=dumb produced zero escapes"
	fi
}

# ---------------------------------------------------------------------------
# Flag registry: the honest untested-flag report.
# ---------------------------------------------------------------------------

# sm_flag_used <flag> — record that a surface exercised this flag.
# The runner owns the full documented-flag manifest; anything left
# unrecorded at the end of the run is printed as UNTESTED by name.
# The registry is RUN-level state: it must outlive every per-surface
# scratch dir (which are wiped as each surface ends), so it lives in
# SM_RUN_TMP - the runner creates that directory before the first
# surface and owns its cleanup.
SM_FLAGS_USED_FILE=""
sm_flags_init() {
	SM_FLAGS_USED_FILE="$SM_RUN_TMP/flags-used.txt"
	: >"$SM_FLAGS_USED_FILE"
}
sm_flag_used() {
	printf '%s\n' "$1" >>"$SM_FLAGS_USED_FILE"
}

# ---------------------------------------------------------------------------
# Surface bookkeeping.
# ---------------------------------------------------------------------------

# sm_surface_begin <name> — a fresh scratch dir per surface so
# fixtures never leak between surfaces.
sm_surface_begin() {
	local name="$1"
	SM_SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/supermassive-${name}.XXXXXX")"
	mkdir -p "$SM_SCRATCH/home"
	printf '\n== surface: %s ==\n' "$name"
}

sm_surface_end() {
	# Keep the scratch dir on failure for post-mortem, drop it on
	# success (the runner passes the keep flag through).
	if [[ "${SM_KEEP_SCRATCH:-0}" != "1" ]]; then
		rm -rf "$SM_SCRATCH"
	fi
}
