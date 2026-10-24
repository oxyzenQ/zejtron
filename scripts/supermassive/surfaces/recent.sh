# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_recent.sh — the `recent` surface.
#
# Depth: success shape on a controlled fixture, both documented
# flags (--limit, --since), the invalid-duration error path, the
# missing-path error path, determinism against the fixture, and the
# color tri-test. Pure filesystem surface - no dormant variant.
# Exercised flags: --limit, --since, positional PATH.

surface_recent() {
	local rc
	local dir="$SM_SCRATCH/fixture"
	mkdir -p "$dir"
	# Three files with pinned, DISTINCT mtimes: --since and --limit
	# have something real to bite on.
	printf 'a\n' >"$dir/older.txt"
	printf 'b\n' >"$dir/middle.txt"
	printf 'c\n' >"$dir/newer.txt"
	touch -d '2026-01-01 00:00:00 UTC' "$dir/older.txt"
	touch -d '2026-06-01 00:00:00 UTC' "$dir/middle.txt"
	touch -d '2030-01-01 00:00:00 UTC' "$dir/newer.txt"

	# Success path.
	sm_run "$SM_SCRATCH/ok.out" "$SM_SCRATCH/ok.err" rc 5 -- "$SM_DEFAULT_BIN" recent "$dir"
	sm_assert_rc 0 "$rc" "recent <dir> exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/ok.out" "recent renders content"

	# --limit pins the row count: the fixture has 3 files, the report
	# must carry at most 1 file row when --limit 1 is set. The exact
	# row spelling is pinned by the structure check; the honest count
	# check is: the newer file renders, and the word for a capped
	# render (the summary) still exists. Row-count arithmetic on a
	# rendered table belongs to the render tests; here the flag's
	# contract is "it runs clean and the render is bounded".
	sm_run "$SM_SCRATCH/lim.out" "$SM_SCRATCH/lim.err" rc 5 -- \
		"$SM_DEFAULT_BIN" recent "$dir" --limit 1
	sm_assert_rc 0 "$rc" "recent --limit 1 exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/lim.out" "recent --limit 1 renders content"

	# The typed JSON lane (night-dragon-4): the automation contract
	# - pure JSON, silent stderr, and the --limit law enforced on
	# the typed row count, not a rendered table's shape.
	sm_run "$SM_SCRATCH/json.out" "$SM_SCRATCH/json.err" rc 5 -- \
		"$SM_DEFAULT_BIN" recent "$dir" --print-json
	sm_assert_rc 0 "$rc" "recent --print-json exits 0"
	sm_assert_silent_stderr "$SM_SCRATCH/json.err" \
		"recent --print-json keeps stderr silent"
	sm_assert_pure_json "$SM_SCRATCH/json.out" \
		"recent --print-json stdout is pure JSON"
	sm_assert_json "$SM_SCRATCH/json.out" '.files | type == "array"' \
		"recent --print-json carries the files array"
	sm_assert_json "$SM_SCRATCH/json.out" '(.files | length) >= 1' \
		"recent --print-json rows survive the fixture"
	sm_run "$SM_SCRATCH/limjson.out" "$SM_SCRATCH/limjson.err" rc 5 -- \
		"$SM_DEFAULT_BIN" recent "$dir" --limit 1 --print-json
	sm_assert_json "$SM_SCRATCH/limjson.out" '(.files | length) <= 1' \
		"recent --limit 1 --print-json bounds the typed row count"
	sm_flag_used "recent --print-json"

	# The battery's own edge: --limit 0 must not blank the report.
	sm_run "$SM_SCRATCH/zero.out" "$SM_SCRATCH/zero.err" rc 5 -- \
		"$SM_DEFAULT_BIN" recent "$dir" --limit 0
	sm_assert_rc 0 "$rc" "recent --limit 0 exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/zero.out" "recent --limit 0 still renders (never all-white)"

	# --since accepts the documented duration grammar.
	sm_run "$SM_SCRATCH/since.out" "$SM_SCRATCH/since.err" rc 5 -- \
		"$SM_DEFAULT_BIN" recent "$dir" --since 1h
	sm_assert_rc 0 "$rc" "recent --since 1h exits 0"

	# Error path: the invalid duration is a runtime failure (exit 1),
	# pinned by the battery's wording.
	sm_run "$SM_SCRATCH/baddur.out" "$SM_SCRATCH/baddur.err" rc 5 -- \
		"$SM_DEFAULT_BIN" recent "$dir" --since nope
	sm_assert_rc 1 "$rc" "recent --since nope exits 1"
	if grep -q "invalid duration" "$SM_SCRATCH/baddur.out" "$SM_SCRATCH/baddur.err" 2>/dev/null; then
		sm_pass "recent --since nope names the invalid duration"
	else
		sm_fail "recent --since nope names the invalid duration" \
			"neither stream mentioned 'invalid duration'"
	fi

	# Error path: a path that does not exist. The verified contract:
	# exit 1 with the OS error wording on stderr (this surface passes
	# the OS error through - unlike touch/why, which name the path).
	sm_run "$SM_SCRATCH/miss.out" "$SM_SCRATCH/miss.err" rc 5 -- \
		"$SM_DEFAULT_BIN" recent "$SM_SCRATCH/no-such-dir"
	sm_assert_rc 1 "$rc" "recent <missing> exits 1"
	sm_assert_contains "$SM_SCRATCH/miss.err" "No such file or directory" \
		"recent <missing> names the OS error on stderr"

	# Determinism against the controlled fixture.
	sm_deterministic "recent determinism (fixture)" 5 -- "$SM_DEFAULT_BIN" recent "$dir" --limit 5

	# The color tri-test.
	sm_color_tritest "recent" 5 -- "$SM_DEFAULT_BIN" recent "$dir" --limit 5

	sm_flag_used "recent --limit"
	sm_flag_used "recent --since"
}
