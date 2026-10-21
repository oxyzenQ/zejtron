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
# owner law), plus the kernel-floor specs (night-improve-43): the
# section's full row estate, the four-name Probes contract, and the
# 5.15 floor agreement held from both sides of the line.
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

	# The row estate (night-improve-43): eight rows is the section's
	# contract (format_section's law in src/commands/doctor/ebpf.rs),
	# and the floor decision rides the kernel-facing rows. The values
	# are host facts; the KEYS are the binary's contract - every row
	# key must render on every host, whatever state the value reports.
	sm_assert_contains "$SM_SCRATCH/ok.out" "Kernel:" "row estate: the Kernel row renders"
	sm_assert_contains "$SM_SCRATCH/ok.out" "BTF:" "row estate: the BTF row renders"
	sm_assert_contains "$SM_SCRATCH/ok.out" "Lockdown:" "row estate: the Lockdown row renders"
	sm_assert_contains "$SM_SCRATCH/ok.out" "Caps:" "row estate: the Caps row renders"
	sm_assert_contains "$SM_SCRATCH/ok.out" "Probes:" "row estate: the Probes row renders"
	sm_assert_contains "$SM_SCRATCH/ok.out" "Pins:" "row estate: the Pins row renders"

	# The Probes row is the binary's contract, not host state (the
	# tap object carries all four programs whatever the host allows):
	# the four names, in planting order, on every host.
	sm_assert_contains "$SM_SCRATCH/ok.out" \
		"sched_process_exec, inet_sock_set_state, vfs_open, vfs_write" \
		"probes contract: the four tap names render in order"

	# The kernel floor agreement (night-improve-43): the eBPF lane's
	# documented floor is 5.15 (KERNEL_FLOOR in src/ebpf/mod.rs, the
	# README's "kernel >= 5.15"), and the suite holds the binary to
	# the floor from BOTH sides of the line. The harness reads the
	# same file the binary reads (/proc/sys/kernel/osrelease),
	# computes the floor direction itself, and demands the render
	# agree: at or above the floor the Lane row must never carry a
	# false floor refusal; below the floor (or an unparsable release,
	# the binary's refuse-what-it-cannot-verify law) the refusal must
	# fire BY NAME - "below the 5.15 floor" pins the number too. No
	# stock GitHub runner ships a below-floor kernel today (the
	# ubuntu-22.04 image rides a 6.8 HWE kernel), but this suite runs
	# wherever a maintainer runs it, and on an old-kernel host this
	# is the check that pins the honest refusal end to end.
	local osrelease rel_major rel_minor at_or_above
	osrelease="$(cat /proc/sys/kernel/osrelease 2>/dev/null || true)"
	if [[ -z "$osrelease" ]]; then
		sm_skip "kernel floor agreement" \
			"/proc/sys/kernel/osrelease unreadable - the harness cannot compute the floor direction"
	else
		if [[ "$osrelease" =~ ^([0-9]+)\.([0-9]+) ]]; then
			rel_major="${BASH_REMATCH[1]}"
			rel_minor="${BASH_REMATCH[2]}"
			if ((rel_major > 5)) || { ((rel_major == 5)) && ((rel_minor >= 15)); }; then
				at_or_above=1
			else
				at_or_above=0
			fi
		else
			# The binary's law: an unparsable release is NOT a pass
			# (kernel_meets_floor refuses what it cannot verify), so
			# the harness mirrors the same direction.
			at_or_above=0
		fi
		# The Kernel row and the harness read the same file; the two
		# reads must agree - the row carries the host's own release.
		sm_assert_contains "$SM_SCRATCH/ok.out" "$osrelease" \
			"kernel row agreement: the Kernel row carries the host's own release"
		if ((at_or_above)); then
			sm_assert_not_contains "$SM_SCRATCH/ok.out" "below the 5.15 floor" \
				"kernel floor agreement: at/above the floor, the Lane row never carries a false floor refusal"
		else
			sm_assert_contains "$SM_SCRATCH/ok.out" "below the 5.15 floor" \
				"kernel floor agreement: below the floor, the Lane row names the 5.15 floor"
			sm_assert_contains "$SM_SCRATCH/att.err" "below the 5.15 floor" \
				"kernel floor agreement: below the floor, doctor --attach names the floor in its refusal"
		fi
	fi
}
