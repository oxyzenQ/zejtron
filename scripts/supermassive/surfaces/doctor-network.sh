# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_doctor_network.sh — the `doctor --symptom network`
# surface (night-improve-48: the delta symptoms land as their own
# surface rows, the doctor-ram precedent).
#
# Same delta-lane shape: every run burns its own 1.0s sampling
# window, so the per-call budget names the sleep. The surface pins
# the success shape, the interface table and the socket-state census
# headers, the --raw drill-down, structural determinism, and the
# color tri-test. Exercised flags: --symptom network, --raw.

surface_doctor_network() {
	local rc

	# Success path: the symptom report with a verdict.
	sm_run "$SM_SCRATCH/net.out" "$SM_SCRATCH/net.err" rc 10 -- \
		"$SM_DEFAULT_BIN" doctor --symptom network
	sm_assert_rc 0 "$rc" "doctor --symptom network exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/net.out" "doctor --symptom network renders content"

	# The lane's contracts: the delta mode line, the interface table
	# header, the socket-state census header, the Unaccounted block,
	# and the verdict.
	sm_assert_contains "$SM_SCRATCH/net.out" "Mode: snapshot delta" \
		"doctor --symptom network declares the delta mode"
	sm_assert_contains "$SM_SCRATCH/net.out" "Interfaces (window 1.0s):" \
		"doctor --symptom network renders the interface table header"
	sm_assert_contains "$SM_SCRATCH/net.out" "Socket states:" \
		"doctor --symptom network renders the socket-state census header"
	sm_assert_contains "$SM_SCRATCH/net.out" "Unaccounted:" \
		"doctor --symptom network renders the Unaccounted block"
	sm_assert_contains "$SM_SCRATCH/net.out" "Verdict:" \
		"doctor --symptom network renders the verdict"

	# --raw appends the raw /proc reads (the documented drill-down).
	sm_run "$SM_SCRATCH/netraw.out" "$SM_SCRATCH/netraw.err" rc 10 -- \
		"$SM_DEFAULT_BIN" doctor --symptom network --raw
	sm_assert_rc 0 "$rc" "doctor --symptom network --raw exits 0"
	if [[ "$(wc -l <"$SM_SCRATCH/netraw.out")" -ge "$(wc -l <"$SM_SCRATCH/net.out")" ]]; then
		sm_pass "doctor --symptom network --raw renders at least the base report"
	else
		sm_fail "doctor --symptom network --raw renders at least the base report" \
			"raw render is shorter than the base"
	fi

	# Determinism: the byte/packet gauges move on their own; the
	# volatile table masks them, and the skeleton is the claim.
	sm_deterministic_structural "doctor --symptom network determinism (structural)" 10 -- \
		"$SM_DEFAULT_BIN" doctor --symptom network

	# The color tri-test, structural: the interface table's row order
	# follows the moving byte gauges.
	SM_TRITEST_STRUCTURAL=1 sm_color_tritest "doctor --symptom network" 10 -- \
		"$SM_DEFAULT_BIN" doctor --symptom network

	sm_flag_used "doctor --symptom"
}
