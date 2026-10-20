# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_why.sh — the `why` surface.
#
# Depth: the evidence-report success shape (the battery-pinned
# verdict), the drill-down flags --trace and --raw, the invalid-port
# error ladder, the missing-path error path, the --since grammar,
# determinism on the pinned fixture (the repo README), the color
# tri-test, and the dormant build variant.
# Exercised flags: --trace, --raw, --since, positional TARGET.

surface_why() {
	local rc
	# The fixture is the repo README: present on every host that has
	# the tree, stable across the run (nothing rewrites it).
	local file="$SUITE_README"

	# Success path: the battery-pinned verdict line.
	sm_run "$SM_SCRATCH/ok.out" "$SM_SCRATCH/ok.err" rc 5 -- "$SM_DEFAULT_BIN" why "$file"
	sm_assert_rc 0 "$rc" "why <readme> exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/ok.out" "why renders content"
	sm_assert_contains "$SM_SCRATCH/ok.out" "The evidence supports:" "why names the evidence verdict"

	# --trace appends the explainability ladder.
	sm_run "$SM_SCRATCH/trace.out" "$SM_SCRATCH/trace.err" rc 5 -- \
		"$SM_DEFAULT_BIN" why "$file" --trace
	sm_assert_rc 0 "$rc" "why --trace exits 0"
	if grep -qi "trace\|how zejtron knows" "$SM_SCRATCH/trace.out"; then
		sm_pass "why --trace renders the ladder section"
	else
		sm_fail "why --trace renders the ladder section" "no trace section in the render"
	fi
	if [[ "$(wc -l <"$SM_SCRATCH/trace.out")" -ge "$(wc -l <"$SM_SCRATCH/ok.out")" ]]; then
		sm_pass "why --trace renders at least the base report"
	else
		sm_fail "why --trace renders at least the base report" "trace render is shorter than the base"
	fi
	sm_flag_used "why --trace"

	# --raw appends the drained kernel events.
	sm_run "$SM_SCRATCH/raw.out" "$SM_SCRATCH/raw.err" rc 5 -- \
		"$SM_DEFAULT_BIN" why "$file" --raw
	sm_assert_rc 0 "$rc" "why --raw exits 0"
	if [[ "$(wc -l <"$SM_SCRATCH/raw.out")" -ge "$(wc -l <"$SM_SCRATCH/ok.out")" ]]; then
		sm_pass "why --raw renders at least the base report"
	else
		sm_fail "why --raw renders at least the base report" "raw render is shorter than the base"
	fi
	sm_flag_used "why --raw"

	# Error ladder: invalid port numbers (runtime failures, exit 1).
	local bad
	for bad in 0 65536; do
		sm_run "$SM_SCRATCH/bad.out" "$SM_SCRATCH/bad.err" rc 5 -- "$SM_DEFAULT_BIN" why "$bad"
		sm_assert_rc 1 "$rc" "why $bad exits 1"
		if grep -q "invalid port" "$SM_SCRATCH/bad.out" "$SM_SCRATCH/bad.err" 2>/dev/null; then
			sm_pass "why $bad names the invalid port"
		else
			sm_fail "why $bad names the invalid port" "neither stream mentioned 'invalid port'"
		fi
	done

	# Error path: missing filesystem target (battery-pinned).
	sm_run "$SM_SCRATCH/miss.out" "$SM_SCRATCH/miss.err" rc 5 -- \
		"$SM_DEFAULT_BIN" why "$SM_SCRATCH/no-such-target"
	sm_assert_rc 1 "$rc" "why <missing> exits 1"
	if grep -q "path not found" "$SM_SCRATCH/miss.out" "$SM_SCRATCH/miss.err" 2>/dev/null; then
		sm_pass "why <missing> names the missing path"
	else
		sm_fail "why <missing> names the missing path" "neither stream mentioned 'path not found'"
	fi

	# --since grammar.
	sm_run "$SM_SCRATCH/since.out" "$SM_SCRATCH/since.err" rc 5 -- \
		"$SM_DEFAULT_BIN" why "$file" --since 1m
	sm_assert_rc 0 "$rc" "why --since 1m exits 0"
	sm_flag_used "why --since"

	# Determinism on the pinned fixture.
	sm_deterministic "why determinism (readme fixture)" 5 -- "$SM_DEFAULT_BIN" why "$file"

	# The color tri-test.
	# The tri-test rides the normalized bytes: the render carries the
	# evidence file's access time, and reading the file IS the act
	# that moves it - the tool's own two passes land a second apart
	# on hosts without relatime throttling. The volatile-field table
	# owns that stamp; the strict raw claim cannot hold for it.
	SM_TRITEST_NORMALIZE=1 sm_color_tritest "why" 5 -- "$SM_DEFAULT_BIN" why "$file"

	# Lane honesty: no dormant build exists (owner law); the lane
	# declaration and the no-fake-observed-rows rule are the check.
	sm_run "$SM_SCRATCH/lane.out" "$SM_SCRATCH/lane.err" rc 5 -- "$SM_DEFAULT_BIN" why "$file"
	sm_assert_rc 0 "$rc" "lane honesty: why renders its mode"
	sm_assert_contains "$SM_SCRATCH/lane.out" "Mode:" "lane honesty: why declares its lane"
	if grep -q "Mode: snapshot" "$SM_SCRATCH/lane.out"; then
		sm_assert_not_contains "$SM_SCRATCH/lane.out" "\\[observed\\]" \
			"lane honesty: snapshot mode renders no fake [observed] rows"
	else
		sm_pass "lane honesty: snapshot mode renders no fake [observed] rows (tap lane active)"
	fi
}
