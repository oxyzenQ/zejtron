# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_doctor_cpu.sh — the `doctor --symptom cpu` surface
# (night-improve-48: the delta symptoms land as their own surface
# rows, the doctor-ram precedent).
#
# The delta lane is the gauge surface with a clock in it: every run
# burns its own 1.0s sampling window (the wait IS the measurement -
# the per-call budget names the sleep), so the surface pins the
# success shape, the --raw drill-down, the lane's mode-line and
# Unaccounted/Verdict furniture, structural determinism (the tick
# gauges move; the volatile table masks them), and the color
# tri-test. Exercised flags: --symptom cpu, --raw.

surface_doctor_cpu() {
	local rc

	# Success path: the symptom report with a verdict. The 10s
	# budget carries the lane's own 1.0s sampling window plus the
	# two pid walks around it.
	sm_run "$SM_SCRATCH/cpu.out" "$SM_SCRATCH/cpu.err" rc 10 -- \
		"$SM_DEFAULT_BIN" doctor --symptom cpu
	sm_assert_rc 0 "$rc" "doctor --symptom cpu exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/cpu.out" "doctor --symptom cpu renders content"

	# The typed JSON lane (night-dragon-4): the symptom report's
	# automation contract - pure JSON, silent stderr, the typed
	# cpu shape.
	sm_run "$SM_SCRATCH/json.out" "$SM_SCRATCH/json.err" rc 10 -- \
		"$SM_DEFAULT_BIN" doctor --symptom cpu --print-json
	sm_assert_rc 0 "$rc" "doctor --symptom cpu --print-json exits 0"
	sm_assert_silent_stderr "$SM_SCRATCH/json.err" \
		"doctor cpu --print-json keeps stderr silent"
	sm_assert_pure_json "$SM_SCRATCH/json.out" \
		"doctor cpu --print-json stdout is pure JSON"
	sm_assert_json "$SM_SCRATCH/json.out" \
		'.mode == "symptom" and .symptom == "cpu"' \
		"doctor cpu --print-json names the cpu symptom"
	sm_assert_json "$SM_SCRATCH/json.out" \
		'.ncpu > 0 and has("loadavg_1min")' \
		"doctor cpu --print-json carries the typed cpu gauges"
	sm_flag_used "doctor --print-json"

	# The lane's contracts: the delta mode line (both lane states
	# carry the "snapshot delta" shape), the ranked table header,
	# the Unaccounted block, and the two-line verdict family.
	sm_assert_contains "$SM_SCRATCH/cpu.out" "Mode: snapshot delta" \
		"doctor --symptom cpu declares the delta mode"
	sm_assert_contains "$SM_SCRATCH/cpu.out" "Top CPU consumers (window 1.0s):" \
		"doctor --symptom cpu renders the ranked table header"
	sm_assert_contains "$SM_SCRATCH/cpu.out" "Unaccounted:" \
		"doctor --symptom cpu renders the Unaccounted block"
	sm_assert_contains "$SM_SCRATCH/cpu.out" "Verdict:" \
		"doctor --symptom cpu renders the verdict"

	# --raw appends the raw /proc reads (the documented drill-down).
	sm_run "$SM_SCRATCH/cpuraw.out" "$SM_SCRATCH/cpuraw.err" rc 10 -- \
		"$SM_DEFAULT_BIN" doctor --symptom cpu --raw
	sm_assert_rc 0 "$rc" "doctor --symptom cpu --raw exits 0"
	if [[ "$(wc -l <"$SM_SCRATCH/cpuraw.out")" -ge "$(wc -l <"$SM_SCRATCH/cpu.out")" ]]; then
		sm_pass "doctor --symptom cpu --raw renders at least the base report"
	else
		sm_fail "doctor --symptom cpu --raw renders at least the base report" \
			"raw render is shorter than the base"
	fi

	# Determinism: the tick gauges and the load gauge move on their
	# own; the volatile table masks them, and the skeleton (headers,
	# mode line, verdict furniture) is the honest claim.
	sm_deterministic_structural "doctor --symptom cpu determinism (structural)" 10 -- \
		"$SM_DEFAULT_BIN" doctor --symptom cpu

	# The color tri-test. The cpu report is a rank-sampled gauge
	# surface: the top-consumer table's ROW ORDER follows the moving
	# tick gauges, so the NO_COLOR equality rides the stable skeleton
	# (SM_TRITEST_STRUCTURAL=1) - the tri-test answers the color
	# question, never the data question.
	SM_TRITEST_STRUCTURAL=1 sm_color_tritest "doctor --symptom cpu" 10 -- \
		"$SM_DEFAULT_BIN" doctor --symptom cpu

	sm_flag_used "doctor --symptom"
}
