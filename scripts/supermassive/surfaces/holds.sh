# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_holds.sh — the `holds` surface.
#
# Depth: the success shape on a controlled fixture (the honest
# no-holder verdict and the Verdict section), the port-target form,
# the invalid-port error ladder, the invalid-duration error path,
# the missing-path error path, determinism against the fixture, the
# color tri-test, and the lane-honesty check (the eBPF support is
# unconditional by owner law - there is no dormant build - so the
# lane check pins the honest snapshot declaration and the
# no-fake-observed-rows rule instead).
#
# The window law (night-dragon-3): holds has no snapshot-only flag
# and the live collect sleeps the full window width (default 10s),
# so every lane that is not an error path rides --since 1s - the
# window's clamp floor, instant on the snapshot lane, a one-second
# bound on the live lane. The grammar under test is the flag's
# acceptance and the honest render, never a ten-second wait; the
# window grammar's own pins live in the unit tests.
# Exercised flags: --since, positional TARGET (path form and port form).

surface_holds() {
	local rc
	local file="$SM_SCRATCH/held file"
	printf 'held\n' >"$file"

	# Success path: a freshly created, unheld temp file. The
	# battery-pinned verdict: the honest no-holder line. The window
	# law: --since 1s (the clamp floor) bounds the live lane.
	sm_run "$SM_SCRATCH/ok.out" "$SM_SCRATCH/ok.err" rc 5 -- \
		"$SM_DEFAULT_BIN" holds "$file" --since 1s
	sm_assert_rc 0 "$rc" "holds <unheld file> exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/ok.out" "holds renders content"
	sm_assert_contains "$SM_SCRATCH/ok.out" "Evidence report:" "holds opens with the evidence header"
	sm_assert_contains "$SM_SCRATCH/ok.out" "Verdict:" "holds renders the Verdict section"
	sm_assert_contains "$SM_SCRATCH/ok.out" "The evidence supports:" \
		"holds names the no-holder verdict"

	# The port form: a valid port number is accepted regardless of
	# whether anything listens on it (the report is honest either way).
	sm_run "$SM_SCRATCH/port.out" "$SM_SCRATCH/port.err" rc 5 -- \
		"$SM_DEFAULT_BIN" holds 53 --since 1s
	sm_assert_rc 0 "$rc" "holds 53 (port form) exits 0"

	# Error ladder: invalid port numbers, runtime failures (exit 1).
	local bad
	for bad in 0 65536; do
		sm_run "$SM_SCRATCH/bad.out" "$SM_SCRATCH/bad.err" rc 5 -- "$SM_DEFAULT_BIN" holds "$bad"
		sm_assert_rc 1 "$rc" "holds $bad exits 1"
		if grep -q "invalid port" "$SM_SCRATCH/bad.out" "$SM_SCRATCH/bad.err" 2>/dev/null; then
			sm_pass "holds $bad names the invalid port"
		else
			sm_fail "holds $bad names the invalid port" "neither stream mentioned 'invalid port'"
		fi
	done

	# Error path: a filesystem target that does not exist. The verified
	# contract: exit 1, the OS error wording (holds passes the OS error
	# through for filesystem targets).
	sm_run "$SM_SCRATCH/miss.out" "$SM_SCRATCH/miss.err" rc 5 -- \
		"$SM_DEFAULT_BIN" holds "$SM_SCRATCH/no-such-file"
	sm_assert_rc 1 "$rc" "holds <missing> exits 1"
	sm_assert_contains "$SM_SCRATCH/miss.err" "no such file or directory" \
		"holds <missing> names the OS error on stderr"

	# --since grammar and its invalid-duration refusal. The width is
	# the clamp floor (the window law) - the flag's contract is
	# acceptance and render, not a wait.
	sm_run "$SM_SCRATCH/since.out" "$SM_SCRATCH/since.err" rc 5 -- \
		"$SM_DEFAULT_BIN" holds "$file" --since 1s
	sm_assert_rc 0 "$rc" "holds --since 1s exits 0"
	sm_flag_used "holds --since"

	sm_run "$SM_SCRATCH/baddur.out" "$SM_SCRATCH/baddur.err" rc 5 -- \
		"$SM_DEFAULT_BIN" holds "$file" --since nope
	sm_assert_rc 1 "$rc" "holds --since nope exits 1"
	if grep -q "invalid duration" "$SM_SCRATCH/baddur.out" "$SM_SCRATCH/baddur.err" 2>/dev/null; then
		sm_pass "holds --since nope names the invalid duration"
	else
		sm_fail "holds --since nope names the invalid duration" \
			"neither stream mentioned 'invalid duration'"
	fi

	# Determinism against the fixture (event-window stamps are
	# normalized by the engine). The window law: --since 1s.
	sm_deterministic "holds determinism (fixture)" 5 -- \
		"$SM_DEFAULT_BIN" holds "$file" --since 1s

	# The color tri-test.
	# Gauge knob: the event window may cover the fixture
	# creation, so the NO_COLOR equality rides the volatile-field table.
	# The window law: --since 1s.
	SM_TRITEST_NORMALIZE=1 sm_color_tritest "holds" 5 -- \
		"$SM_DEFAULT_BIN" holds "$file" --since 1s

	# Lane honesty: there is NO dormant build (owner law, Cargo.toml -
	# the eBPF support is unconditional), so the honest check is the
	# lane declaration itself: the Mode line names the lane that ran,
	# and while the snapshot lane is active the render must NOT fake
	# kernel-observed rows (the ladder's [observed] tag belongs to the
	# probe lane only).
	sm_run "$SM_SCRATCH/lane.out" "$SM_SCRATCH/lane.err" rc 5 -- \
		"$SM_DEFAULT_BIN" holds "$file" --since 1s
	sm_assert_rc 0 "$rc" "lane honesty: holds renders its mode"
	sm_assert_contains "$SM_SCRATCH/lane.out" "Mode:" "lane honesty: holds declares its lane"
	if grep -q "Mode: snapshot" "$SM_SCRATCH/lane.out"; then
		sm_assert_not_contains "$SM_SCRATCH/lane.out" "\\[observed\\]" \
			"lane honesty: snapshot mode renders no fake [observed] rows"
	else
		sm_pass "lane honesty: snapshot mode renders no fake [observed] rows (probe lane active)"
	fi
}
