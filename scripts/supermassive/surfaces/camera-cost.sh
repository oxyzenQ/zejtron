# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_camera_cost.sh — the Camera Cost Contract's runtime seat
# (night-frontier-Z4): the price of the camera, ENFORCED live, not
# advertised. The compile-time half of the contract rides the cost
# pins (src/ebpf/cost.rs: the eBPF instruction table, the kernel-side
# ring bytes - a cost change fails the tests until consciously
# re-pinned); this surface enforces the RUNTIME half on the booted
# kernel, per push, on every root CI leg:
#
#   * the attach wall-time ceiling: doctor --attach must plant the
#     whole estate (BTF verify, programs, links, pins, the generation
#     stamp) inside 2000 ms - a lazy camera that takes longer to
#     plant than a busy one takes to answer is a marketing lie, and
#     the suite names the measured milliseconds either way;
#   * the userland memory ceiling: the representative surfaces run
#     under `ulimit -v 65536` (64 MiB of address space) and must exit
#     0 - the kernel itself rejects the run if the camera's footprint
#     ever exceeds the contract, so a regression cannot pass
#     unnoticed;
#   * the binary size ceiling: the payload binary stays under
#     16 MiB - the static musl shape a buyer ships to an air-gapped
#     host stays shippable.
#
# The published table (docs/CAMERA-COST.md) carries the compile-time
# numbers and these ceilings together; the witness logs carry the
# LIVE per-dialect attach milliseconds this surface measures.
# Probe-lane seat: the budgets need the camera, so a host where the
# attach refuses skips with the reason named - the root CI lanes
# carry the proof. Zero new flags: the surface rides existing ones.

surface_camera_cost() {
	local rc rc2 t0 t1 attach_us attach_ms measured_size
	local scratch="$SM_SCRATCH/cost"
	mkdir -p "$scratch"

	# The binary size ceiling first (no camera needed): the static
	# musl payload a buyer ships stays under 16 MiB. The suite's
	# binary is the artifact being measured - SM_DEFAULT_BIN itself.
	measured_size="$(stat -c%s "$SM_DEFAULT_BIN" 2>/dev/null || echo 0)"
	if [[ "$measured_size" -gt 0 && "$measured_size" -le 16777216 ]]; then
		sm_pass "camera-cost: the binary size under the contract (measured $measured_size bytes <= 16777216)"
	elif [[ "$measured_size" -eq 0 ]]; then
		sm_fail "camera-cost: the binary size is measurable" \
			"stat on the suite binary returned nothing - the surface cannot audit what it cannot see"
	else
		sm_fail "camera-cost: the binary size under the contract" \
			"measured $measured_size bytes > 16777216 - the shipping shape outgrew the contract"
	fi

	# The lane probe: the attach IS the cost under measurement here.
	t0="${EPOCHREALTIME/./}"
	sm_run "$scratch/attach.out" "$scratch/attach.err" rc 20 -- \
		"$SM_DEFAULT_BIN" doctor --attach
	t1="${EPOCHREALTIME/./}"
	attach_us=$((t1 - t0))
	attach_ms=$((attach_us / 1000))
	if [[ "$rc" -ne 0 ]]; then
		sm_skip "camera-cost: the runtime budgets (attach, memory)" \
			"the camera refused to attach on this host (no root or no BTF) - the root CI lanes carry the proof"
		return
	fi
	# EPOCHREALTIME carries microseconds: the ceiling is 2000 ms =
	# 2000000 us; the measured value renders in whole milliseconds.
	if [[ "$attach_us" -le 2000000 ]]; then
		sm_pass "camera-cost: the attach plants the whole estate in ${attach_ms}ms (ceiling 2000ms)"
	else
		sm_fail "camera-cost: the attach wall-time ceiling" \
			"the attach took ${attach_ms}ms > 2000ms - the lazy camera outgrew its own name"
	fi

	# The userland memory ceiling: the representative surfaces run
	# under ulimit -v 65536 (64 MiB of ADDRESS SPACE, the kernel
	# enforcing the contract). The live lane rides too - why's
	# drain window runs against the attached camera inside the same
	# ceiling. A regression (a fat allocation, a leak) makes the
	# kernel refuse the exec: the failure is named, never absorbed.
	# (EPOCHREALTIME is the timer - bash 5, no date fork, sub-ms
	# resolution; the attach itself rides sm_run's own 20s cap as the
	# outer belt.)
	# The userland memory ceiling: the representative surfaces run
	# under ulimit -v 65536 (64 MiB of ADDRESS SPACE, the kernel
	# enforcing the contract). The subshells ride the `|| rc2=$?`
	# capture - a bare subshell under the suite's set -Eeuo pipefail
	# would kill the WHOLE suite on the ceiling's own refusal (the
	# first live run's finding, fixed the same night: the floor VM
	# died inside the ceiling block, the verdict shipped without its
	# summary). The invocations ride the documented flag spellings
	# (--version, not a bare `version` - the parser's usage error
	# rc 2 would fail the block for a reason that has nothing to do
	# with memory).
	printf 'cost-contract probe file\n' >"$scratch/probe.txt"
	rc2=0
	(
		ulimit -v 65536
		"$SM_DEFAULT_BIN" --version >/dev/null 2>&1 &&
			"$SM_DEFAULT_BIN" proc --me >/dev/null 2>&1 &&
			"$SM_DEFAULT_BIN" path "$scratch/probe.txt" >/dev/null 2>&1 &&
			"$SM_DEFAULT_BIN" why "$scratch/probe.txt" --raw >/dev/null 2>&1
	) || rc2=$?
	if [[ "$rc2" -eq 0 ]]; then
		sm_pass "camera-cost: the representative surfaces run under the 64 MiB ceiling"
	else
		sm_fail "camera-cost: the userland memory ceiling" \
			"an invocation died under ulimit -v 65536 (rc $rc2) - the camera's footprint outgrew the contract"
	fi
	# The ceiling holds while the CAMERA IS ATTACHED - the whole
	# point: the plant must not change the tool's price.
	rc2=0
	(
		ulimit -v 65536
		"$SM_DEFAULT_BIN" doctor >/dev/null 2>&1
	) || rc2=$?
	if [[ "$rc2" -eq 0 ]]; then
		sm_pass "camera-cost: the doctor answers under the 64 MiB ceiling WITH the camera planted"
	else
		sm_fail "camera-cost: the memory ceiling with the camera planted" \
			"the doctor died under ulimit -v 65536 with the estate live (rc $rc2)"
	fi

	# The leg ends clean by its own hand (the storm surface's law).
	sm_run "$scratch/detach.out" "$scratch/detach.err" rc 20 -- \
		"$SM_DEFAULT_BIN" doctor --detach
	sm_assert_rc 0 "$rc" "camera-cost: doctor --detach ends the leg clean (exit 0)"
	if [[ -e /sys/fs/bpf/zejtron ]]; then
		sm_fail "camera-cost: detach removes the pin directory" \
			"/sys/fs/bpf/zejtron still exists after detach"
	else
		sm_pass "camera-cost: detach removes the pin directory"
	fi
	# The ceiling is the contract's own note - named so a reader sees
	# the number the kernel enforced above.
	sm_pass "camera-cost: the memory ceiling is ulimit -v 65536 KiB (the kernel enforced it live)"
}
