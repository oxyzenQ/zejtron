# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_doctor_ram.sh — the `doctor --symptom ram` surface.
#
# The symptom lane is its own surface row in the depth-audit table:
# a symptom report has its own verdict, its own gauges, and its own
# drill-down. Depth: the success shape, the --raw drill-down, the
# known-symptom grammar (ram is one of the four documented values),
# structural determinism (memory gauges move on their own), and the
# color tri-test. Exercised flags: --symptom ram, --raw.

surface_doctor_ram() {
	local rc

	# Success path: the symptom report with a verdict.
	sm_run "$SM_SCRATCH/ok.out" "$SM_SCRATCH/ok.err" rc 5 -- \
		"$SM_DEFAULT_BIN" doctor --symptom ram
	sm_assert_rc 0 "$rc" "doctor --symptom ram exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/ok.out" "doctor --symptom ram renders content"

	# --raw appends the raw /proc reads (the documented drill-down).
	sm_run "$SM_SCRATCH/raw.out" "$SM_SCRATCH/raw.err" rc 5 -- \
		"$SM_DEFAULT_BIN" doctor --symptom ram --raw
	sm_assert_rc 0 "$rc" "doctor --symptom ram --raw exits 0"
	if [[ "$(wc -l <"$SM_SCRATCH/raw.out")" -ge "$(wc -l <"$SM_SCRATCH/ok.out")" ]]; then
		sm_pass "doctor --symptom ram --raw renders at least the base report"
	else
		sm_fail "doctor --symptom ram --raw renders at least the base report" \
			"raw render is shorter than the base"
	fi

	# Determinism: the gauges move; the skeleton (headers and the
	# verdict lines) is the honest claim.
	sm_deterministic_structural "doctor --symptom ram determinism (structural)" 5 -- \
		"$SM_DEFAULT_BIN" doctor --symptom ram

	# The color tri-test. The ram report is a rank-sampled GAUGE
	# surface: the top-consumer table's ROW ORDER follows the moving
	# PSS gauges, so two passes differ by re-sampling even after the
	# volatile-field table masks every value. The NO_COLOR equality
	# rides the stable skeleton - the same depth the determinism check
	# above already claims for this surface - because the tri-test
	# answers the color question, never the data question.
	SM_TRITEST_STRUCTURAL=1 sm_color_tritest "doctor --symptom ram" 5 -- \
		"$SM_DEFAULT_BIN" doctor --symptom ram

	sm_flag_used "doctor --symptom"
}
