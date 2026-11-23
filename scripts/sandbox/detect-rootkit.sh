#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial
# OS: Linux only - the detonation runs on a real kernel, root, in the
# project's own micro-VM.
#
# scripts/sandbox/detect-rootkit.sh - the night-frontier-Z11 phase c
# detonation proof (D8). Runs INSIDE the kernel-floor micro-VM (the
# jammy GA 5.15.0 kernel, root), after the supermassive low leg, and
# proves the Z11 detections against a REAL stealth mechanism instead
# of a mock:
#
#   leg a  negative control    a visible writer's window carries no
#                              hidden-pid and no silent-deletion entry
#                              - the detector does not cry wolf;
#   leg b  the pidhide hide    the fixture's fexit program hides the
#                              marker's dirent from getdents64; the
#                              camera still records the marker's write
#                              (hiding from the listing does not hide
#                              from the kprobe); the direct /proc pid
#                              lookup still resolves; the listing does
#                              not name it - `why` must render the
#                              "hidden pids" Unaccounted entry;
#   leg c  the log's story     a synthetic audit record names a
#                              deletion the camera's window never saw -
#                              `why` must render the "silent deletions"
#                              Unaccounted entry (the two lanes'
#                              disagreement, named);
#   leg d  the id plane        the attached estate's pins all sit in
#                              the kernel's own id enumeration - the
#                              doctor must render the "verified" ID
#                              Plane row and the JSON must agree;
#   leg e  the honesty row     a reader without CAP_SYS_ADMIN must
#                              get the named absence, never a guess.
#
# The verdict contract: one SANDBOX-RESULT line per leg (the verdict
# step in the workflow greps them), the overall SANDBOX-VERDICT: PASS
# line only when every leg passed. A leg that cannot even run (a
# fixture the kernel refused) FAILS the run loudly - the proof's
# value is that it cannot pass quietly.
#
# Usage (inside the micro-VM, as root):
#   bash /opt/zejtron/scripts/sandbox/detect-rootkit.sh

set -u

SANDBOX=/opt/zejtron/.sandbox
BIN=${ZEJTRON_BIN:-/opt/zejtron/zejtron}
LOADER=${PIDHIDE_LOADER:-${SANDBOX}/pidhide-loader}
OBJECT=${PIDHIDE_OBJECT:-${SANDBOX}/pidhide-ebpf}
WORK=${SANDBOX}/detonation

mkdir -p "${WORK}"
cd "${WORK}" || exit 1

legs_passed=0
legs_failed=0

pass_leg() {
	legs_passed=$((legs_passed + 1))
	echo "SANDBOX-RESULT: z11 leg $1 - PASS"
}

fail_leg() {
	legs_failed=$((legs_failed + 1))
	echo "SANDBOX-RESULT: z11 leg $1 - FAIL ($2)"
}

# The category probe the jq checks ride: 0 when the JSON's top-level
# unaccounted block carries the named category, 1 when it does not.
has_unaccounted_category() {
	jq -e --arg wanted "$2" \
		'[(.unaccounted // [])[] | .category] | index($wanted) != null' \
		"$1" >/dev/null 2>&1
}

lacks_unaccounted_category() {
	jq -e --arg wanted "$2" \
		'[(.unaccounted // [])[] | .category] | index($wanted) == null' \
		"$1" >/dev/null 2>&1
}

echo "── z11 detonation: attach (root, the lane the legs ride) ──"
if ! "${BIN}" doctor --attach; then
	fail_leg a-attach "the attach itself refused on the floor kernel"
	fail_leg b-pidhide "skipped (no camera)"
	fail_leg c-silent-deletion "skipped (no camera)"
	fail_leg d-id-plane "skipped (no camera)"
	fail_leg e-honesty "skipped (no camera)"
	echo "SANDBOX-VERDICT: FAIL"
	exit 1
fi

# ── leg a: the negative control ──────────────────────────────────────
echo "── z11 detonation: leg a (negative control, visible writer) ──"
(
	i=0
	while [ "$i" -lt 200 ]; do
		printf 'x\n' >>"${WORK}/leg-a-file" 2>/dev/null || break
		sleep 0.05
		i=$((i + 1))
	done
) &
leg_a_writer=$!
sleep 1
if "${BIN}" why "${WORK}/leg-a-file" --since 5s --print-json >leg-a.json 2>leg-a.err; then
	if lacks_unaccounted_category leg-a.json "hidden pids" &&
		lacks_unaccounted_category leg-a.json "silent deletions"; then
		pass_leg a-negative-control
	else
		fail_leg a-negative-control "the visible window raised a stealth entry (crying wolf)"
	fi
else
	fail_leg a-negative-control "the why run itself failed: $(cat leg-a.err)"
fi
wait "${leg_a_writer}" || true

# ── leg b: the pidhide hide ──────────────────────────────────────────
echo "── z11 detonation: leg b (pidhide, the real stealth mechanism) ──"
if [ ! -x "${LOADER}" ] || [ ! -f "${OBJECT}" ]; then
	fail_leg b-pidhide "the fixture artifacts are missing from the rootfs"
else
	"${LOADER}" "${OBJECT}" 12 >leg-b.loader 2>&1 &
	loader_pid=$!
	# The loader's sentinel line names the marker pid it hid.
	marker_pid=""
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		marker_pid=$(sed -n 's/^PIDHIDE-PLANTED marker=//p' leg-b.loader | head -1)
		[ -n "${marker_pid}" ] && break
		sleep 1
	done
	sleep 2
	# The hide's direct proof: the marker is alive but the listing
	# does not name it, while the direct lookup still resolves.
	listing_hidden=1
	if [ -n "${marker_pid}" ] && kill -0 "${marker_pid}" 2>/dev/null; then
		if [ -d "/proc/${marker_pid}" ]; then
			# The listing membership: walk the namespace's own readdir
			# (the glob expansion IS the directory listing) and look
			# for the marker's entry - the same read the detector
			# reconciles against the direct lookup.
			found_in_listing=0
			for entry in /proc/*; do
				[ "${entry}" = "/proc/${marker_pid}" ] && found_in_listing=1
			done
			[ "${found_in_listing}" -eq 1 ] && listing_hidden=0
		else
			listing_hidden=0
		fi
		direct_lookup=1
		test -d "/proc/${marker_pid}" || direct_lookup=0
	else
		listing_hidden=0
		direct_lookup=0
	fi
	if "${BIN}" why "${SANDBOX}/marker-file" --since 8s --print-json >leg-b.json 2>leg-b.err; then
		if has_unaccounted_category leg-b.json "hidden pids" &&
			[ "${listing_hidden}" -eq 1 ] && [ "${direct_lookup}" -eq 1 ]; then
			pass_leg b-pidhide
		else
			fail_leg b-pidhide \
				"listing_hidden=${listing_hidden} direct_lookup=${direct_lookup} entry=missing (see leg-b.json leg-b.loader)"
		fi
	else
		fail_leg b-pidhide "the why run itself failed: $(cat leg-b.err)"
	fi
	wait "${loader_pid}" || true
fi

# ── leg c: the log's story (the synthetic audit trail) ───────────────
echo "── z11 detonation: leg c (silent deletion, the lanes' disagreement) ──"
printf 'x\n' >"${WORK}/leg-c-file"
leg_c_inode=$(stat -c '%i' "${WORK}/leg-c-file")
leg_c_now=$(date +%s)
mkdir -p /var/log/audit
{
	echo "type=SYSCALL msg=audit(${leg_c_now}.000:1): arch=c000003e syscall=87 success=yes exit=0 a0=0 comm=\"fixture\" pid=1"
	echo "type=PATH msg=audit(${leg_c_now}.000:1): name=\"${WORK}/leg-c-file\" inode=${leg_c_inode} dev=fd:03"
} >audit.log
if "${BIN}" why "${WORK}/leg-c-file" --since 30s --print-json >leg-c.json 2>leg-c.err; then
	if has_unaccounted_category leg-c.json "silent deletions"; then
		pass_leg c-silent-deletion
	else
		fail_leg c-silent-deletion "the log's deletion story raised no entry (see leg-c.json)"
	fi
else
	fail_leg c-silent-deletion "the why run itself failed: $(cat leg-c.err)"
fi
rm -f audit.log

# ── leg d: the id plane, verified ────────────────────────────────────
echo "── z11 detonation: leg d (the ID plane, attached estate) ──"
if "${BIN}" doctor --print-json >leg-d.json 2>leg-d.err; then
	if jq -e '.ebpf.id_plane_state == "verified"' leg-d.json >/dev/null 2>&1 &&
		"${BIN}" doctor | grep -q 'ID Plane:.*verified'; then
		pass_leg d-id-plane
	else
		fail_leg d-id-plane "the attached estate did not verify against the id plane (see leg-d.json)"
	fi
else
	fail_leg d-id-plane "the doctor run itself failed: $(cat leg-d.err)"
fi

# ── leg e: the honesty row (the reader without the capability) ───────
echo "── z11 detonation: leg e (the honesty row, no CAP_SYS_ADMIN) ──"
if setpriv --reuid=65534 --regid=65534 --clear-groups "${BIN}" doctor >leg-e.txt 2>&1 &&
	grep -q 'ID Plane:.*unavailable (requires CAP_SYS_ADMIN' leg-e.txt; then
	pass_leg e-honesty
else
	fail_leg e-honesty "the unprivileged reader did not print the named absence (see leg-e.txt)"
fi

"${BIN}" doctor --detach || true

if [ "${legs_failed}" -eq 0 ]; then
	echo "SANDBOX-VERDICT: PASS (legs passed: ${legs_passed})"
	exit 0
fi
echo "SANDBOX-VERDICT: FAIL (passed: ${legs_passed}, failed: ${legs_failed})"
exit 1
