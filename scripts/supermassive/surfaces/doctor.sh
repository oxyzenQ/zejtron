# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_doctor.sh — the `doctor` surface (readiness lane).
#
# Depth: the readiness success shape, the privileged lifecycle flags
# (--attach refuses with exit 1 + "attach refused" on any host that
# cannot attach; --detach is idempotent with exit 0), the
# unknown-symptom refusal that teaches the documented grammar, the
# --raw orphaned-flag refusal, structural determinism (memory gauges
# move), the color tri-test, and the lane-honesty checks (the [eBPF]
# section's Feature/Lane declaration - there is no dormant build by
# owner law).
# Exercised flags: --attach, --detach, --raw (the --symptom flag and
# its values are the doctor-ram surface's estate).

surface_doctor() {
	local rc

	# Success path: the readiness report.
	sm_run "$SM_SCRATCH/ok.out" "$SM_SCRATCH/ok.err" rc 5 -- "$SM_DEFAULT_BIN" doctor
	sm_assert_rc 0 "$rc" "doctor exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/ok.out" "doctor renders content"

	# --attach is the privileged one-shot. The verified universal
	# contract: on a host that cannot attach, the refusal is exit 1
	# with "attach refused" on stderr - the REASON is host-dependent
	# (the kernel floor, BTF, or the missing capabilities - whichever
	# preflight fires first) and the label names that honestly instead
	# of guessing one.
	sm_run "$SM_SCRATCH/att.out" "$SM_SCRATCH/att.err" rc 5 -- "$SM_DEFAULT_BIN" doctor --attach
	sm_assert_rc 1 "$rc" "doctor --attach refuses honestly on an unprivileged host (exit 1)"
	sm_flag_used "doctor --attach"
	sm_assert_contains "$SM_SCRATCH/att.err" "attach refused" \
		"doctor --attach refusal names the reason"

	# --detach is documented idempotent ("unpin everything,
	# idempotent"): with no tap ever attached in this suite, the
	# verified contract is exit 0 and the honest nothing-to-detach
	# line.
	sm_run "$SM_SCRATCH/det.out" "$SM_SCRATCH/det.err" rc 5 -- "$SM_DEFAULT_BIN" doctor --detach
	sm_assert_rc 0 "$rc" "doctor --detach is idempotent (exit 0)"
	sm_flag_used "doctor --detach"
	sm_assert_file_nonempty "$SM_SCRATCH/det.out" "doctor --detach renders its status"

	# Unknown symptom: a runtime refusal (exit 1) that names the
	# symptom grammar - the four documented values must be in the
	# refusal, so the error itself teaches the surface.
	sm_run "$SM_SCRATCH/sym.out" "$SM_SCRATCH/sym.err" rc 5 -- \
		"$SM_DEFAULT_BIN" doctor --symptom definitely-not-a-symptom
	sm_assert_rc 1 "$rc" "doctor --symptom <unknown> exits 1"
	sm_assert_contains "$SM_SCRATCH/sym.err" "unknown symptom" \
		"doctor --symptom <unknown> names the refusal"
	sm_assert_contains "$SM_SCRATCH/sym.err" "ram, slow, disk, network" \
		"doctor --symptom <unknown> teaches the documented grammar"

	# --raw without --symptom: the verified contract is a refusal
	# (exit 1) - the drill-down is scoped to the symptom lane and the
	# readiness lane refuses the orphaned flag.
	sm_run "$SM_SCRATCH/rawflag.out" "$SM_SCRATCH/rawflag.err" rc 5 -- "$SM_DEFAULT_BIN" doctor --raw
	sm_assert_rc 1 "$rc" "doctor --raw without --symptom is refused (exit 1)"
	sm_assert_file_nonempty "$SM_SCRATCH/rawflag.err" "doctor --raw refusal explains itself on stderr"
	sm_flag_used "doctor --raw"

	# Determinism: gauges move; the skeleton is the claim.
	sm_deterministic_structural "doctor determinism (structural)" 5 -- "$SM_DEFAULT_BIN" doctor

	# The color tri-test.
	sm_color_tritest "doctor" 5 -- "$SM_DEFAULT_BIN" doctor

	# Lane honesty: there is NO dormant build (owner law, Cargo.toml -
	# the eBPF support is unconditional), so the honest check is the
	# [eBPF] section's declaration: the Feature line and the Lane line
	# must render on every host, whatever state they report.
	sm_assert_contains "$SM_SCRATCH/ok.out" "[eBPF]" "lane honesty: doctor renders the [eBPF] section"
	sm_assert_contains "$SM_SCRATCH/ok.out" "Feature:" "lane honesty: doctor declares the feature state"
	sm_assert_contains "$SM_SCRATCH/ok.out" "Lane:" "lane honesty: doctor declares the active lane"
}
