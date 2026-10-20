# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_touch.sh — the `touch` surface.
#
# Depth: the success shape for both fixture kinds (file and
# directory - the battery-pinned type rows), the missing-path error
# path, the invalid-duration error path, the --since flag, fixture
# determinism, the color tri-test, and the dormant build variant
# (touch rides the fallback ladder).
# Exercised flags: --since, positional PATH.

surface_touch() {
	local rc
	local file="$SM_SCRATCH/touched file"
	local dir="$SM_SCRATCH/touched dir"
	printf 'content\n' >"$file"
	mkdir -p "$dir"

	# Success path, file form: the battery-pinned type row.
	sm_run "$SM_SCRATCH/file.out" "$SM_SCRATCH/file.err" rc 5 -- "$SM_DEFAULT_BIN" touch "$file"
	sm_assert_rc 0 "$rc" "touch <file> exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/file.out" "touch <file> renders content"
	sm_assert_contains "$SM_SCRATCH/file.out" "type file" "touch <file> names the file type"

	# Success path, directory form.
	sm_run "$SM_SCRATCH/dir.out" "$SM_SCRATCH/dir.err" rc 5 -- "$SM_DEFAULT_BIN" touch "$dir"
	sm_assert_rc 0 "$rc" "touch <dir> exits 0"
	sm_assert_contains "$SM_SCRATCH/dir.out" "type directory" "touch <dir> names the directory type"

	# Error path: a path that does not exist (battery-pinned).
	sm_run "$SM_SCRATCH/miss.out" "$SM_SCRATCH/miss.err" rc 5 -- \
		"$SM_DEFAULT_BIN" touch "$SM_SCRATCH/no-such-path"
	sm_assert_rc 1 "$rc" "touch <missing> exits 1"
	if grep -q "path not found" "$SM_SCRATCH/miss.out" "$SM_SCRATCH/miss.err" 2>/dev/null; then
		sm_pass "touch <missing> names the missing path"
	else
		sm_fail "touch <missing> names the missing path" "neither stream mentioned 'path not found'"
	fi

	# --since grammar and its invalid-duration refusal.
	sm_run "$SM_SCRATCH/since.out" "$SM_SCRATCH/since.err" rc 5 -- \
		"$SM_DEFAULT_BIN" touch "$file" --since 1m
	sm_assert_rc 0 "$rc" "touch --since 1m exits 0"
	sm_flag_used "touch --since"

	sm_run "$SM_SCRATCH/baddur.out" "$SM_SCRATCH/baddur.err" rc 5 -- \
		"$SM_DEFAULT_BIN" touch "$file" --since nope
	sm_assert_rc 1 "$rc" "touch --since nope exits 1"
	if grep -q "invalid duration" "$SM_SCRATCH/baddur.out" "$SM_SCRATCH/baddur.err" 2>/dev/null; then
		sm_pass "touch --since nope names the invalid duration"
	else
		sm_fail "touch --since nope names the invalid duration" \
			"neither stream mentioned 'invalid duration'"
	fi

	# Determinism: the fixture's mtimes are frozen for the whole
	# surface (nothing touches them), so the report is byte-stable
	# modulo the volatile-field table.
	sm_deterministic "touch determinism (fixture)" 5 -- "$SM_DEFAULT_BIN" touch "$file"

	# The color tri-test.
	# Gauge knob: the event window may cover the fixture
	# creation, so the NO_COLOR equality rides the volatile-field table.
	SM_TRITEST_NORMALIZE=1 sm_color_tritest "touch" 5 -- "$SM_DEFAULT_BIN" touch "$file"

	# Lane honesty: no dormant build exists (owner law); the lane
	# declaration and the no-fake-observed-rows rule are the check.
	sm_run "$SM_SCRATCH/lane.out" "$SM_SCRATCH/lane.err" rc 5 -- "$SM_DEFAULT_BIN" touch "$file"
	sm_assert_rc 0 "$rc" "lane honesty: touch renders its mode"
	sm_assert_contains "$SM_SCRATCH/lane.out" "Mode:" "lane honesty: touch declares its lane"
	if grep -q "Mode: snapshot" "$SM_SCRATCH/lane.out"; then
		sm_assert_not_contains "$SM_SCRATCH/lane.out" "\\[observed\\]" \
			"lane honesty: snapshot mode renders no fake [observed] rows"
	else
		sm_pass "lane honesty: snapshot mode renders no fake [observed] rows (tap lane active)"
	fi
}
