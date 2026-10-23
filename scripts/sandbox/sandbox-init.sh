#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool.
#
# The zejtron kernel-floor sandbox init (night-improve-43) — PID 1
# inside the micro-VM booted by scripts/sandbox/zejtron-sandbox.sh
# (local) and .github/workflows/supermassive-kernel-floor.yml (CI).
# Modeled on the sibling's CI init (zelynic's supermassive-init.sh):
# no systemd, this script owns every mount, it must NEVER exit
# without ending the VM, and the exit rides qemu's isa-debug-exit
# port device — reboot(2) poweroff silently no-ops in a direct-boot
# guest. The differences are the point: this init runs whatever
# payload the entrypoint packed into /opt/zejtron/.sandbox/payload.sh
# and relays the exit code through the SANDBOX-VERDICT sentinel line.
#
# Two lanes, one init. The FLOOR lane (the default, and the only
# lane the CI twin runs): the kernel that booted must BE the jammy
# GA floor kernel (5.15.0-*, the exact documented minimum — a wrong
# kernel booted under the floor lane's name fails HERE, before any
# payload spends its budget), BTF must be readable (the floor kernel
# ships it; the probe lane's offsets verification reads it), and the
# binary must run and answer the doctor's bpf syscall probe on THIS
# kernel: bring-up is a GATE - any failed probe ends the VM before
# the payload. The ARBITRARY lane (the entrypoint's --kernel PATH,
# a marker packed at .sandbox/lane): the same probes REPORT instead
# of gate - the floor guard becomes the floor DIRECTION row (at/above
# or below the 5.15 floor, the same number the suite's own capability
# computation reads), because the point of the arbitrary lane is
# proving zejtron on a kernel of the operator's choice, and the
# payload's exit code is the verdict there.
#
# Contract: SANDBOX-RESULT lines for the bring-up probes plus one
# final SANDBOX-VERDICT line (PASS, or FAIL with the payload's exit
# code), all on the serial console — the entrypoint greps these
# sentinels; the VM cannot relay exit codes through qemu, the
# sentinel lines ARE the relay.

set -u
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export TERM="${TERM:-dumb}"

FAILURES=0
LANE="floor"

note() {
	echo "SANDBOX-RESULT: $1 — $2"
	# The floor lane gates on bring-up; the arbitrary lane only
	# reports - there the payload's exit code is the verdict.
	if [ "$2" != "PASS" ] && [ "$LANE" = "floor" ]; then
		FAILURES=$((FAILURES + 1))
	fi
}

guest_exit() {
	# The deterministic VM exit, belts in order. (1) The console
	# drain: the sentinel lines are the contract, and qemu's
	# isa-debug-exit device ends the process the moment one byte
	# lands on port 0xf4 - serial bytes still in flight (the tail of
	# the SANDBOX-RESULT line, the SANDBOX-VERDICT line itself) die
	# with it, proven live on the cachyos witness: a green 389/0
	# suite whose PASS sentinel never reached vm.log. One quiet
	# second lets the UART FIFO and the host-side pipe run dry before
	# the exit byte is written. (2) qemu's isa-debug-exit device:
	# /dev/port is the root-writable port-I/O window (seek = the
	# port number), and the written value 0 makes qemu exit with
	# status 1 - an rc the entrypoint's boot step accepts as the
	# guest's deliberate exit. (3) The sysrq poweroff: enabling sysrq
	# first is LOAD-BEARING (the jammy kernel's default mask hides
	# the poweroff bit, and a bare `echo o` silently no-ops - proven
	# live on the floor kernel: with sysrq enabled, the write reaches
	# ACPI S5 and the kernel prints "reboot: Power down"; qemu exits
	# 0, a natural poweroff, also accepted). (4) The sleep loop
	# (never spin the host's budget - the outer timeout owns the last
	# resort).
	echo 1 >/proc/sys/kernel/sysrq 2>/dev/null || true
	sync 2>/dev/null || true
	sleep 1 2>/dev/null || true
	printf '\x00' | dd of=/dev/port bs=1 seek=244 count=1 2>/dev/null || true
	echo o >/proc/sysrq-trigger 2>/dev/null || true
	while true; do sleep 60; done
}

Z=/opt/zejtron
if ! cd "$Z"; then
	# A PID 1 must never plain-exit (the guest would panic-wedge):
	# exit through the port device with the verdict already naming
	# the failure.
	echo "SANDBOX-VERDICT: FAIL (cannot cd $Z — initrd assembly bug)"
	guest_exit
fi

# ── the kernel surfaces, before anything that needs them ──────────
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs dev /dev
exec >/dev/console 2>&1
echo "SANDBOX: init on $(uname -r)"

# The lane (the entrypoint packs it at .sandbox/lane): floor = the
# strict identity contract; arbitrary = the report mode. A garbage
# lane file is an assembly bug - fail loudly, never guess.
if [ -r "$Z/.sandbox/lane" ]; then
	LANE="$(cat "$Z/.sandbox/lane" 2>/dev/null)"
fi
LANE="${LANE:-floor}"
case "$LANE" in
floor | arbitrary) ;;
*)
	echo "SANDBOX-VERDICT: FAIL (unknown lane: $LANE — assembly bug)"
	guest_exit
	;;
esac
if [ "$LANE" = "arbitrary" ]; then
	echo "SANDBOX: arbitrary lane — the identity rows below are reports; the payload is the verdict"
fi

# Everything the zejtron battery needs (PID 1 owns it all): tmpfs
# scratch (the suite's run dirs), bpffs (the probe lane's pin surface,
# /sys/fs/bpf/zejtron), devpts (the pty-shaped color probes),
# loopback (the traffic the probe lane can observe), and the tracing
# substrate a real distro host mounts for its tracing tools:
# debugfs plus tracefs at /sys/kernel/tracing - the probe lane's
# tracepoint attach reads <tracefs>/events (aya probes
# /sys/kernel/tracing then /sys/kernel/debug/tracing), and the
# jammy GA kernel creates the /sys/kernel/tracing directory but
# mounts nothing there until somebody does (systemd's automount on
# a real host - this init, here). Without it the attach fails past
# its own preflight with "tracefs not found", exactly the gap the
# first floor-kernel run caught.
if mount -t tmpfs tmp /tmp &&
	mount -t tmpfs run /run &&
	mkdir -p /sys/fs/bpf /dev/pts /sys/kernel/debug /sys/kernel/tracing &&
	mount -t bpf bpf /sys/fs/bpf &&
	mount -t devpts devpts /dev/pts &&
	mount -t debugfs debugfs /sys/kernel/debug &&
	mount -t tracefs tracefs /sys/kernel/tracing &&
	ip link set lo up; then
	note "kernel surfaces (proc, sysfs, devtmpfs, tmpfs, bpffs, devpts, debugfs, tracefs, loopback)" PASS
else
	note "kernel surfaces" FAIL
fi

# The lane's own floor guard. Floor lane: the kernel that booted
# must BE the documented floor kernel — 5.15.0-*, the jammy GA
# release; a newer kernel riding the floor lane's name (a resolver
# regression, a cached wrong vmlinuz) fails HERE, loudly, before the
# payload. Arbitrary lane: the same release is REPORTED with its
# floor direction instead — the suite's capability computation
# composes that direction with BTF and the effective capabilities,
# so the row states the floor dimension only.
if [ "$LANE" = "floor" ]; then
	case "$(uname -r)" in
	5.15.0-*)
		note "kernel floor (release $(uname -r) is the jammy GA 5.15.0 floor kernel)" PASS
		;;
	*)
		note "kernel floor (release $(uname -r) is NOT the 5.15.0 floor kernel — wrong kernel booted)" FAIL
		;;
	esac
else
	KREL="$(uname -r)"
	KMAJ="${KREL%%.*}"
	KREST="${KREL#*.}"
	KMIN="${KREST%%[-.]*}"
	case "${KMAJ}${KMIN}" in
	'' | *[!0-9]*)
		note "kernel direction (release $KREL is unparsable — the suite's own osrelease computation owns the direction)" PASS
		;;
	*)
		if [ "$KMAJ" -gt 5 ] || { [ "$KMAJ" -eq 5 ] && [ "$KMIN" -ge 15 ]; }; then
			note "kernel direction (release $KREL is at/above the 5.15 floor)" PASS
		else
			note "kernel direction (release $KREL is BELOW the 5.15 floor)" PASS
		fi
		;;
	esac
fi

# The BTF substrate: the floor kernel ships /sys/kernel/btf/vmlinux
# (CONFIG_DEBUG_INFO_BTF=y, jammy GA), and the probe lane's offsets
# verification reads it at attach time — on the floor lane its
# absence would mean the image or the kernel is not what the lane
# documents; on the arbitrary lane it is a reported property of the
# operator's chosen kernel.
if [ -r /sys/kernel/btf/vmlinux ]; then
	note "BTF (/sys/kernel/btf/vmlinux readable — the offsets substrate)" PASS
else
	note "BTF (/sys/kernel/btf/vmlinux unreadable — no offsets substrate on this kernel)" FAIL
fi

# The tracing substrate (the lane contract the first floor-kernel
# run taught): the tracepoint attach reads <tracefs>/events, and a
# bare /sys/kernel/tracing directory without a mount fails it. The
# mount battery above owns the mount; this probe pins the RESULT -
# the events tree for the probe's own tracepoints must be readable.
if [ -r /sys/kernel/tracing/events/sched/sched_process_exec/id ]; then
	note "tracefs (the sched_process_exec tracepoint id is readable)" PASS
else
	note "tracefs (the sched_process_exec tracepoint id is unreadable)" FAIL
fi

# The lean prelude: the binary runs and the doctor answers on this
# kernel, before any payload spends its budget.
if ./zejtron -V >/dev/null 2>&1; then
	note "zejtron -V (the binary runs on this kernel)" PASS
else
	note "zejtron -V (the binary runs on this kernel)" FAIL
fi
if ./zejtron doctor >/dev/null 2>&1; then
	note "doctor (the bpf syscall answers on this kernel)" PASS
else
	note "doctor (the bpf syscall answers on this kernel)" FAIL
fi

# ── the payload ────────────────────────────────────────────────────
# Whatever the entrypoint packed: --battery runs the supermassive
# low leg (the full suite, root, on the booted kernel), --shell drops
# into an interactive root bash on this console, --run executes an
# arbitrary root-requiring script. The payload's exit code IS the
# verdict; bring-up FAILURES above fail the run too on the floor
# lane (a guest that cannot host the lane has no payload verdict
# worth reporting) - on the arbitrary lane the payload is the
# verdict, bring-up only reported.
PAYLOAD="$Z/.sandbox/payload.sh"
if [ "$FAILURES" -ne 0 ]; then
	echo "SANDBOX-VERDICT: FAIL (bring-up probes failed — payload never ran)"
	guest_exit
fi
if [ -x "$PAYLOAD" ]; then
	echo "SANDBOX: running the packed payload..."
	bash "$PAYLOAD"
	rc=$?
else
	echo "SANDBOX: no payload packed — the root shell is the console."
	bash
	rc=$?
fi
if [ "$rc" -eq 0 ]; then
	echo "SANDBOX-VERDICT: PASS"
else
	echo "SANDBOX-VERDICT: FAIL (payload exit $rc)"
fi
guest_exit
