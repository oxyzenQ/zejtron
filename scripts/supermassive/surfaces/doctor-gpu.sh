# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_doctor_gpu.sh — the `doctor --symptom gpu` surface
# (night-improve-48: the snapshot symptom lands as its own surface
# row, the doctor-ram precedent).
#
# The one symptom that takes NO delta: the question is who holds
# the device open, and /proc/<pid>/fd answers it at the instant of
# the command - no sampling window, no sleep, so the standard 5s
# per-call budget holds. The surface pins the success shape, the
# snapshot mode line, the --raw drill-down (a no-op on the honest
# empty scene - the base render is the floor), structural
# determinism, and the color tri-test. Exercised flags:
# --symptom gpu, --raw.

surface_doctor_gpu() {
	local rc

	# Success path: the symptom report with a verdict. On a host
	# with no GPU (the CI containers, the micro-VMs) the honest
	# empty scene renders - the contract is the report, never the
	# hardware.
	sm_run "$SM_SCRATCH/gpu.out" "$SM_SCRATCH/gpu.err" rc 5 -- \
		"$SM_DEFAULT_BIN" doctor --symptom gpu
	sm_assert_rc 0 "$rc" "doctor --symptom gpu exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/gpu.out" "doctor --symptom gpu renders content"

	# The lane's contracts: the snapshot mode line (both lane states
	# carry the "Mode: snapshot" shape), the holders header, the
	# Unaccounted block, and the verdict.
	sm_assert_contains "$SM_SCRATCH/gpu.out" "Mode: snapshot" \
		"doctor --symptom gpu declares the snapshot mode"
	sm_assert_contains "$SM_SCRATCH/gpu.out" "GPU device holders:" \
		"doctor --symptom gpu renders the holders header"
	sm_assert_contains "$SM_SCRATCH/gpu.out" "Unaccounted:" \
		"doctor --symptom gpu renders the Unaccounted block"
	sm_assert_contains "$SM_SCRATCH/gpu.out" "Verdict:" \
		"doctor --symptom gpu renders the verdict"

	# --raw appends the raw device links (the documented
	# drill-down). On the empty scene the drill-down is a no-op, so
	# the contract is the exit status and the floor: raw is never
	# SHORTER than the base.
	sm_run "$SM_SCRATCH/gpuraw.out" "$SM_SCRATCH/gpuraw.err" rc 5 -- \
		"$SM_DEFAULT_BIN" doctor --symptom gpu --raw
	sm_assert_rc 0 "$rc" "doctor --symptom gpu --raw exits 0"
	if [[ "$(wc -l <"$SM_SCRATCH/gpuraw.out")" -ge "$(wc -l <"$SM_SCRATCH/gpu.out")" ]]; then
		sm_pass "doctor --symptom gpu --raw renders at least the base report"
	else
		sm_fail "doctor --symptom gpu --raw renders at least the base report" \
			"raw render is shorter than the base"
	fi

	# Determinism: the holder set and the VRAM gauges move with the
	# host's own GPU users; the skeleton is the claim.
	sm_deterministic_structural "doctor --symptom gpu determinism (structural)" 5 -- \
		"$SM_DEFAULT_BIN" doctor --symptom gpu

	# The color tri-test, structural: the holder list is live data
	# (a process can open or close the device between any two
	# passes), so the NO_COLOR equality rides the stable skeleton.
	SM_TRITEST_STRUCTURAL=1 sm_color_tritest "doctor --symptom gpu" 5 -- \
		"$SM_DEFAULT_BIN" doctor --symptom gpu

	sm_flag_used "doctor --symptom"
}
