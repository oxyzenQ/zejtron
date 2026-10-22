# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_doctor.sh — the `doctor` surface (readiness lane).
#
# Depth: the readiness success shape, the privileged lifecycle flags
# pinned from BOTH directions (night-improve-43's kernel-floor lane
# made the privileged direction reachable: root + BTF + the real
# 5.15.0 floor kernel inside the KVM micro-VM), the
# unknown-symptom refusal that teaches the documented grammar, the
# --raw orphaned-flag refusal, structural determinism (memory gauges
# move), the color tri-test, and the lane-honesty checks (the [eBPF]
# section's Feature/Lane declaration - there is no dormant build by
# owner law), plus the kernel-floor specs (night-improve-43): the
# section's full row estate, the six-name Probes contract, and the
# 5.15 floor agreement held from both sides of the line.
# Exercised flags: --attach, --detach, --raw (the --symptom flag
# and its values are the five symptom surfaces' estate: doctor-ram
# and night-improve-48's doctor-cpu, doctor-disk, doctor-network,
# doctor-gpu).

surface_doctor() {
	local rc
	local osrelease rel_major rel_minor at_or_above capeff can_attach

	# Success path: the readiness report.
	sm_run "$SM_SCRATCH/ok.out" "$SM_SCRATCH/ok.err" rc 5 -- "$SM_DEFAULT_BIN" doctor
	sm_assert_rc 0 "$rc" "doctor exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/ok.out" "doctor renders content"

	# The floor direction, computed once up front: the attach
	# lifecycle below and the floor agreement at the end both hold
	# the binary to the same direction, read from the same file
	# the binary reads (/proc/sys/kernel/osrelease). An unparsable
	# or unreadable release is NOT a pass - the binary's
	# refuse-what-it-cannot-verify law, mirrored here.
	osrelease="$(cat /proc/sys/kernel/osrelease 2>/dev/null || true)"
	at_or_above=0
	if [[ "$osrelease" =~ ^([0-9]+)\.([0-9]+) ]]; then
		rel_major="${BASH_REMATCH[1]}"
		rel_minor="${BASH_REMATCH[2]}"
		if ((rel_major > 5)) || { ((rel_major == 5)) && ((rel_minor >= 15)); }; then
			at_or_above=1
		fi
	fi
	# The capability half of the attach preflight: the binary's
	# lane_verdict reads CAP_BPF + CAP_PERFMON in the EFFECTIVE
	# set (bits 39 and 38), and the harness reads the same words
	# from /proc/self/status - no guessing from euid (a dropped-
	# caps root would guess wrong in both directions).
	capeff="$(awk '/^CapEff/ {print $2}' /proc/self/status 2>/dev/null || true)"
	can_attach=0
	if [[ -n "$capeff" && -r /sys/kernel/btf/vmlinux ]] && ((at_or_above)); then
		if (((16#$capeff >> 38) & 1)) && (((16#$capeff >> 39) & 1)); then
			can_attach=1
		fi
	fi

	# --attach is the privileged one-shot, pinned from both
	# directions. On a host that cannot attach, the verified
	# universal contract: the refusal is exit 1 with "attach
	# refused" on stderr - the REASON is host-dependent (the
	# kernel floor, BTF, or the missing capabilities - whichever
	# preflight fires first) and the label names that honestly
	# instead of guessing one. On a host the harness PROVES
	# capable (floor met + BTF readable + the two capabilities in
	# the effective set), the attach may legitimately still refuse
	# (lockdown active is the real-world case) or succeed - and a
	# SUCCESS carries its own contract: the tap names itself, the
	# pin directory names itself, the BTF-verified offsets claim
	# pins itself, the second attach is the honest idempotent
	# nothing-to-do, and the detach that follows is the REAL
	# unpin (15 pins removed, the pin directory gone). A success
	# on a host the harness reads as incapable is a loud failure:
	# the binary attached where its own preflight must refuse.
	# The 20s per-call budget is the leg's documented slow class
	# (the same vocabulary --check-update rides): the one-shot
	# loads five BPF programs and pins fifteen objects.
	sm_run "$SM_SCRATCH/att.out" "$SM_SCRATCH/att.err" rc 20 -- "$SM_DEFAULT_BIN" doctor --attach
	sm_flag_used "doctor --attach"
	if [[ "$rc" -eq 0 ]]; then
		if ((can_attach)); then
			sm_assert_contains "$SM_SCRATCH/att.out" "tap attached" \
				"doctor --attach succeeds on a capable host and names the tap"
			sm_assert_contains "$SM_SCRATCH/att.out" "/sys/fs/bpf/zejtron" \
				"doctor --attach names the pin directory"
			sm_assert_contains "$SM_SCRATCH/att.out" "offsets verified from this host's BTF" \
				"doctor --attach pins the BTF-verified offsets claim"
			sm_run "$SM_SCRATCH/att2.out" "$SM_SCRATCH/att2.err" rc 20 -- "$SM_DEFAULT_BIN" doctor --attach
			sm_assert_rc 0 "$rc" "doctor --attach is idempotent on a live tap (exit 0)"
			sm_assert_contains "$SM_SCRATCH/att2.out" "tap is already attached - nothing to do" \
				"doctor --attach idempotence names the live tap"
			sm_run "$SM_SCRATCH/det.out" "$SM_SCRATCH/det.err" rc 20 -- "$SM_DEFAULT_BIN" doctor --detach
			sm_assert_rc 0 "$rc" "doctor --detach unpins the live tap (exit 0)"
			sm_assert_contains "$SM_SCRATCH/det.out" "tap detached: unpinned" \
				"doctor --detach reports the real unpin"
			if [[ -e /sys/fs/bpf/zejtron ]]; then
				sm_fail "doctor --detach removes the pin directory" \
					"/sys/fs/bpf/zejtron still exists after detach"
			else
				sm_pass "doctor --detach removes the pin directory"
			fi
		else
			sm_fail "doctor --attach success direction" \
				"attach exited 0 on a host the harness reads as incapable (release: ${osrelease:-unreadable}, BTF, caps) - the binary attached where its own preflight must refuse"
		fi
		# Either way the surface ends clean: the idempotent
		# nothing-to-detach on an unattached host.
		sm_run "$SM_SCRATCH/det2.out" "$SM_SCRATCH/det2.err" rc 20 -- "$SM_DEFAULT_BIN" doctor --detach
		sm_assert_rc 0 "$rc" "doctor --detach is idempotent (exit 0)"
		sm_assert_contains "$SM_SCRATCH/det2.out" "nothing to detach - no pins present" \
			"doctor --detach idempotence names the clean state"
	else
		sm_assert_rc 1 "$rc" "doctor --attach refuses honestly on a host that cannot attach (exit 1)"
		sm_assert_contains "$SM_SCRATCH/att.err" "attach refused" \
			"doctor --attach refusal names the reason"
		# --detach is documented idempotent ("unpin everything,
		# idempotent"): with no tap ever attached in this suite
		# run, the verified contract is exit 0 and the honest
		# nothing-to-detach line.
		sm_run "$SM_SCRATCH/det.out" "$SM_SCRATCH/det.err" rc 20 -- "$SM_DEFAULT_BIN" doctor --detach
		sm_assert_rc 0 "$rc" "doctor --detach is idempotent (exit 0)"
		sm_assert_file_nonempty "$SM_SCRATCH/det.out" "doctor --detach renders its status"
		sm_assert_contains "$SM_SCRATCH/det.out" "nothing to detach - no pins present" \
			"doctor --detach names the clean state"
	fi
	sm_flag_used "doctor --detach"

	# Unknown symptom: a runtime refusal (exit 1) that names the
	# symptom grammar - the six documented values must be in the
	# refusal, so the error itself teaches the surface.
	sm_run "$SM_SCRATCH/sym.out" "$SM_SCRATCH/sym.err" rc 5 -- \
		"$SM_DEFAULT_BIN" doctor --symptom definitely-not-a-symptom
	sm_assert_rc 1 "$rc" "doctor --symptom <unknown> exits 1"
	sm_assert_contains "$SM_SCRATCH/sym.err" "unknown symptom" \
		"doctor --symptom <unknown> names the refusal"
	sm_assert_contains "$SM_SCRATCH/sym.err" "ram, cpu, disk, network, gpu, slow" \
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
	# tap object carries all six programs whatever the host allows):
	# the six names, in planting order, on every host.
	sm_assert_contains "$SM_SCRATCH/ok.out" \
		"sched_process_exec, inet_sock_set_state, vfs_open, raw_syscalls/sys_enter, vfs_writev, sched_process_exit" \
		"probes contract: the six tap names render in order"

	# The kernel floor agreement (night-improve-43): the eBPF lane's
	# documented floor is 5.15 (KERNEL_FLOOR in src/ebpf/mod.rs, the
	# README's "kernel >= 5.15"), and the suite holds the binary to
	# the floor from BOTH sides of the line, computed once above.
	# At or above the floor the Lane row must never carry a false
	# floor refusal; below the floor (or an unparsable release, the
	# binary's refuse-what-it-cannot-verify law) the refusal must
	# fire BY NAME - "below the 5.15 floor" pins the number too. No
	# stock GitHub runner ships a below-floor kernel today (the
	# ubuntu images ride 6.x HWE kernels) and none ships the floor
	# itself either - the kernel-floor micro-VM lane
	# (.github/workflows/supermassive-kernel-floor.yml, the local
	# twin scripts/sandbox/zejtron-sandbox.sh) boots the REAL jammy
	# GA 5.15.0 kernel and runs this suite inside it, so the
	# at-floor direction is pinned LIVE, on the exact oldest kernel
	# zejtron promises to run on.
	if [[ -z "$osrelease" ]]; then
		sm_skip "kernel floor agreement" \
			"/proc/sys/kernel/osrelease unreadable - the harness cannot compute the floor direction"
	else
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
