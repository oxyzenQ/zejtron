#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool.
#
# kernel-matrix.sh (night-frontier-4, the owner's approved tooth: the
# kernel matrix as a LOCAL harness first) — drive the kernel-floor
# sandbox across the whole witness ladder, one micro-VM boot per
# kernel, and print the matrix: which kernel generation zejtron is
# proven on, which one refuses, which one drifted.
#
# WHY THIS EXISTS: the ladder ALREADY runs in CI per push
# (.github/workflows/supermassive-kernel-witnesses.yml: focal 5.4.0
# below the floor, jammy 5.15.0 at it, noble 6.8.0 above it, cachyos
# as the moving-latest witness - the line that caught the 6.18
# anonymous union wrapping struct file's f_path live). What the
# estate lacked is the LOCAL seat: the CI lane boots only on a push,
# on a hosted runner, and its verdict lives in the Actions tab - an
# operator debugging a kernel-specific refusal has no one-command
# way to run the same ladder on the box in front of them. This
# harness is that seat: the same witnesses, the same sandbox code
# path, one command, one table - the drift alarm the operator can
# ring BEFORE pushing, not after the CI tab turns red. One
# implementation, two seats, so the local instrument cannot drift
# from what CI proves (the floor lane's own law).
#
# LOCAL ONLY, BY DESIGN (the owner's gate: local first, CI later):
# no CI workflow joins this commit - the witnesses lane already
# burns the ladder per push inside its 5-minute budgets, and a
# duplicate lane would double the burn for the same verdict. The
# harness earns new CI only if it catches a drift the CI ladder's
# shapes miss (a new witness preset, a new envelope); any future
# lane must still respect the estate's 10-minute run budget.
#
# THE KERNEL SOURCES ARE THE SUITE TABLE'S: 5.15/6.8 GA come from
# the Ubuntu archive's frozen GA pockets; the newest line comes from
# the cachyos repo index. A mainline kernel the archive does not
# carry (a 6.1 or 6.6 LTS build, say) rides the sandbox's arbitrary
# lane the same way it always has: `zejtron-sandbox.sh --kernel
# /path/to/vmlinuz` - the matrix points are the resolvable
# witnesses, the arbitrary lane is the operator's own extension.
#
# Usage:
#   scripts/sandbox/kernel-matrix.sh                 # the full ladder
#   scripts/sandbox/kernel-matrix.sh --suite noble   # one witness
#   scripts/sandbox/kernel-matrix.sh --list          # print the ladder, run nothing
#
# Options:
#   --suite NAME        one witness to run (repeatable, replaces the
#                       ladder; a name the sandbox's --kernel accepts)
#   --binary PATH       the zejtron payload binary (the sandbox's own
#                       probe picks the newest repo build otherwise)
#   --timeout SECONDS   the outer VM budget PER WITNESS (default: the
#                       sandbox's own 1800)
#   --stop              stop at the first failed witness (default:
#                       run the whole ladder, report every row)
#   --list              print the ladder and exit
#   -h | --help         this help
#
# Requirements: the sandbox's own (qemu-system-x86_64, python3, git;
# /dev/kvm optional - TCG boots work and report, slower).

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX="${SCRIPT_DIR}/zejtron-sandbox.sh"
MATRIX_CACHE="${ZEJTRON_MATRIX_CACHE:-${HOME}/.cache/zejtron-sandbox/matrix}"

# The witness ladder, below-floor to moving-latest: each name is a
# suite the packer's SUITE_TABLE resolves and the sandbox's --kernel
# accepts. The order IS the report order (oldest kernel first).
DEFAULT_SUITES="focal jammy noble cachyos"

SUITES=""
BINARY=""
TIMEOUT=""
STOP=0

note() { echo "[matrix] $*"; }
die() {
	echo "[matrix] FAIL: $*" >&2
	exit 1
}

usage() {
	sed -n 's/^# //p' "${BASH_SOURCE[0]}" |
		sed -n '/^Usage:/,/^Requirements:/p' |
		sed '/^Requirements:/d' |
		sed '/^$/d'
	exit "${1:-0}"
}

while [ $# -gt 0 ]; do
	case "$1" in
	--suite)
		SUITES="${SUITES:+${SUITES} }${2:?}"
		shift 2
		;;
	--binary)
		BINARY="${2:?}"
		shift 2
		;;
	--timeout)
		TIMEOUT="${2:?}"
		shift 2
		;;
	--stop)
		STOP=1
		shift
		;;
	--list)
		echo "the witness ladder (oldest first):"
		for suite in ${DEFAULT_SUITES}; do
			echo "  ${suite}"
		done
		exit 0
		;;
	-h | --help) usage 0 ;;
	*)
		echo "unknown flag: $1" >&2
		usage 2
		;;
	esac
done

[ -n "${SUITES}" ] || SUITES="${DEFAULT_SUITES}"
[ -x "${SANDBOX}" ] || die "the sandbox entrypoint is missing or not executable: ${SANDBOX}"
command -v qemu-system-x86_64 >/dev/null 2>&1 ||
	die "qemu-system-x86_64 not found - the matrix boots VMs (install qemu-system-x86)"
mkdir -p "${MATRIX_CACHE}"

note "witness ladder: ${SUITES}"

ROWS=()
FAILED=0
RAN=0
STARTED_AT="$(date +%s)"

for suite in ${SUITES}; do
	note "booting the ${suite} witness (log: ${MATRIX_CACHE}/${suite}/vm.log)"
	log_dir="${MATRIX_CACHE}/${suite}"
	mkdir -p "${log_dir}"
	suite_start="${SECONDS}"

	# The sandbox owns everything: the kernel resolution, the
	# packer, the boot, the suite, the sentinels. The env-scoped
	# cache keeps each witness's kernel, initramfs, and boot log
	# separate (a witness's cached vmlinuz is its own - the
	# cachyos witness re-resolves inside its own cache).
	run_env=(env "ZEJTRON_SANDBOX_CACHE=${log_dir}")
	timeout_args=()
	[ -n "${TIMEOUT}" ] && timeout_args=(--timeout "${TIMEOUT}")
	binary_args=()
	[ -n "${BINARY}" ] && binary_args=(--binary "${BINARY}")

	# No set -e here on purpose: a failing witness must not end the
	# ladder - the sentinel line is the verdict, the whole ladder
	# reports, and the driver's own exit is the aggregate.
	"${run_env[@]}" bash "${SANDBOX}" --battery --kernel "${suite}" \
		"${timeout_args[@]}" "${binary_args[@]}" --keep \
		>"${log_dir}/run.out" 2>&1
	elapsed="${SECONDS}"
	elapsed=$((elapsed - suite_start))
	RAN=$((RAN + 1))

	log="${log_dir}/vm.log"
	verdict="NO-VERDICT (the boot died before the sentinels - see run.out)"
	grep -q '^SANDBOX-VERDICT:' "${log}" 2>/dev/null &&
		verdict="$(grep '^SANDBOX-VERDICT:' "${log}" | tail -1 | sed 's/^SANDBOX-VERDICT: //')"
	kernel_row="$(grep -m1 'kernel floor (release\|kernel direction (release' "${log}" 2>/dev/null |
		sed 's/^SANDBOX-RESULT: kernel [a-z]* (release //; s/ — .*//; s/)$//')"
	[ -n "${kernel_row}" ] || kernel_row="unreported"
	btf="unreported"
	grep -q 'BTF (/sys/kernel/btf/vmlinux readable' "${log}" 2>/dev/null && btf="readable"
	grep -q 'BTF (/sys/kernel/btf/vmlinux unreadable' "${log}" 2>/dev/null && btf="absent"

	if [ "${verdict}" = "PASS" ]; then
		mark="PASS"
	else
		mark="FAIL"
		FAILED=$((FAILED + 1))
	fi
	ROWS+=("  ${suite}  |  ${kernel_row}  |  BTF ${btf}  |  ${mark}  |  ${elapsed}s  |  ${verdict}")
	note "witness ${suite}: ${mark} (${elapsed}s)"

	# The per-witness verdict IS the payload's own exit code under
	# the report lane; the sandbox propagates it, and a nonzero rc
	# with a PASS sentinel is the qemu exit-shape artifact the
	# init's guest_exit documents (the isa-debug-exit path exits
	# status 1 by design). The sentinel is the verdict; the rc is
	# the boot's shape.
	if [ "${STOP}" = "1" ] && [ "${mark}" = "FAIL" ]; then
		note "--stop: the ladder ends at the first failed witness"
		break
	fi
done

WALL=$((SECONDS - STARTED_AT))
echo ""
echo "kernel matrix (the witness ladder, oldest first):"
printf '  suite  |  kernel  |  BTF  |  verdict  |  wall  |  sentinel\n'
printf '%s\n' "${ROWS[@]}"
echo ""
if [ "${FAILED}" -eq 0 ]; then
	note "matrix green: ${RAN} witness(es), 0 failures, ${WALL}s total - every rung of the ladder proves zejtron"
	exit 0
fi
note "matrix RED: ${FAILED}/${RAN} witness(es) failed, ${WALL}s total - the failed witness names the drift (logs: ${MATRIX_CACHE}/<suite>/vm.log)"
exit 1
