# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_doctor_disk.sh — the `doctor --symptom disk` surface
# (night-improve-48: the delta symptoms land as their own surface
# rows, the doctor-ram precedent).
#
# Same delta-lane shape as the cpu surface: every run burns its own
# 1.0s sampling window, so the per-call budget names the sleep. The
# surface pins the success shape, the iowait gauge header, the
# --raw drill-down, structural determinism, and the color tri-test.
# Exercised flags: --symptom disk, --raw.

surface_doctor_disk() {
	local rc

	# Success path: the symptom report with a verdict.
	sm_run "$SM_SCRATCH/disk.out" "$SM_SCRATCH/disk.err" rc 10 -- \
		"$SM_DEFAULT_BIN" doctor --symptom disk
	sm_assert_rc 0 "$rc" "doctor --symptom disk exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/disk.out" "doctor --symptom disk renders content"

	# The typed JSON lane (night-dragon-4): the symptom report's
	# automation contract - pure JSON, silent stderr, the typed
	# disk shape.
	sm_run "$SM_SCRATCH/json.out" "$SM_SCRATCH/json.err" rc 10 -- \
		"$SM_DEFAULT_BIN" doctor --symptom disk --print-json
	sm_assert_rc 0 "$rc" "doctor --symptom disk --print-json exits 0"
	sm_assert_silent_stderr "$SM_SCRATCH/json.err" \
		"doctor disk --print-json keeps stderr silent"
	sm_assert_pure_json "$SM_SCRATCH/json.out" \
		"doctor disk --print-json stdout is pure JSON"
	sm_assert_json "$SM_SCRATCH/json.out" \
		'.mode == "symptom" and .symptom == "disk"' \
		"doctor disk --print-json names the disk symptom"
	sm_assert_json "$SM_SCRATCH/json.out" 'has("iowait_pct")' \
		"doctor disk --print-json carries the iowait gauge"
	sm_flag_used "doctor --print-json"

	# The lane's contracts: the delta mode line, the iowait gauge
	# header, the Unaccounted block, and the verdict.
	sm_assert_contains "$SM_SCRATCH/disk.out" "Mode: snapshot delta" \
		"doctor --symptom disk declares the delta mode"
	sm_assert_contains "$SM_SCRATCH/disk.out" "I/O wait (window 1.0s):" \
		"doctor --symptom disk renders the iowait gauge header"
	sm_assert_contains "$SM_SCRATCH/disk.out" "Unaccounted:" \
		"doctor --symptom disk renders the Unaccounted block"
	sm_assert_contains "$SM_SCRATCH/disk.out" "Verdict:" \
		"doctor --symptom disk renders the verdict"

	# --raw appends the raw /proc reads (the documented drill-down).
	sm_run "$SM_SCRATCH/diskraw.out" "$SM_SCRATCH/diskraw.err" rc 10 -- \
		"$SM_DEFAULT_BIN" doctor --symptom disk --raw
	sm_assert_rc 0 "$rc" "doctor --symptom disk --raw exits 0"
	if [[ "$(wc -l <"$SM_SCRATCH/diskraw.out")" -ge "$(wc -l <"$SM_SCRATCH/disk.out")" ]]; then
		sm_pass "doctor --symptom disk --raw renders at least the base report"
	else
		sm_fail "doctor --symptom disk --raw renders at least the base report" \
			"raw render is shorter than the base"
	fi

	# Determinism: the iowait tick gauges move on their own; the
	# volatile table masks them, and the skeleton is the claim.
	sm_deterministic_structural "doctor --symptom disk determinism (structural)" 10 -- \
		"$SM_DEFAULT_BIN" doctor --symptom disk

	# The color tri-test, structural: the top I/O table's row order
	# follows the moving byte gauges.
	SM_TRITEST_STRUCTURAL=1 sm_color_tritest "doctor --symptom disk" 10 -- \
		"$SM_DEFAULT_BIN" doctor --symptom disk

	sm_flag_used "doctor --symptom"
}
