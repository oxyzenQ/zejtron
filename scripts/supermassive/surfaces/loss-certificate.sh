# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_loss_certificate.sh — the Loss-under-Load certificate
# (night-frontier-Z3): the drop census's proof seat.
#
# The hole (night-frontier-Z1's drop truth, one layer up): the
# drop_census map COUNTS the file ring's reserve failures, and the
# why surface NAMES them in Unaccounted - but nothing ever proved the
# census HONEST under a real overload. A census that quietly
# undercounts is worse than none: it launders silent loss behind a
# green number. Sysdig, Datadog, and Tetragon drop silently; zejtron
# claims its loss is counted - so the claim gets a proof leg, not a
# hope.
#
# The physics: the file_events ring is a bounded 256 KiB RingBuf
# (~6553 forty-byte FileEvent records). The leg generates an event
# storm far past that capacity INSIDE one tracked window, with the
# ground truth counted OUTSIDE the camera - the generator is the
# counter: a pure-bash write loop over one pre-opened descriptor,
# its completed-write total landing in a sidecar the camera never
# sees (the count file's inode is never tracked; a write the filter
# drops costs no census). Then the conservation identity, all four
# directions:
#
#   delivered (the --raw records the ring actually held)
#   + drops   (the census's own count of the reserve failures)
#   == ground truth (the generator's completed writes)
#
# delivered > truth  = the camera invented records (fabrication);
# delivered + drops < truth  = events lost uncounted (the silent
# loss the census exists to name); overload reached with drops == 0
# = the census lied. Only exact equality - with a REAL overload
# behind it - issues the certificate:
#
#   the camera never loses silently under overload: its loss is
#   counted, and the count is provable against an external truth.
#
# Zero new flags: the leg rides the existing surfaces only (doctor
# --attach/--detach, why --since --raw). Probe-lane seat: the storm
# needs the camera, so a host where the attach refuses (no root, no
# BTF) skips with the reason named - the root CI lanes (the floor
# lane strict, the witnesses report mode) carry the proof.

surface_loss_certificate() {
	local rc storm_dir hot count_file why_rc storm_count delivered drops
	local window_pid storm_target storm_deadline total
	storm_dir="$SM_SCRATCH/loss-cert"
	hot="$storm_dir/hot.bin"
	count_file="$storm_dir/storm.count"

	mkdir -p "$storm_dir"

	# The hygiene guard: the certificate's conservation arithmetic
	# is only valid over ONE attach session - a pin estate that
	# survived a prior surface would carry a foreign drop history.
	# Every surface ends clean by its own hand; a pre-existing estate
	# here is a suite bug, named loudly, never absorbed.
	if [[ -e /sys/fs/bpf/zejtron ]]; then
		sm_fail "loss-certificate: the pin estate is clean before the leg" \
			"/sys/fs/bpf/zejtron pre-exists (a prior surface leaked its attach - the census would count foreign drops)"
		return
	fi
	sm_pass "loss-certificate: the pin estate is clean before the leg"

	# The lane probe: the attach attempt itself (the storm surface's
	# precedent). No camera, no certificate - the skip names why.
	sm_run "$SM_SCRATCH/lc-attach.out" "$SM_SCRATCH/lc-attach.err" rc 20 -- \
		"$SM_DEFAULT_BIN" doctor --attach
	if [[ "$rc" -ne 0 ]]; then
		sm_skip "loss-certificate: the probe lane (attach, storm, conservation)" \
			"the camera refused to attach on this host (no root or no BTF) - the root CI lanes carry the proof"
		return
	fi
	sm_pass "loss-certificate: the camera attaches (the probe lane runs)"

	: >"$hot"
	# The one open, BEFORE the window: the descriptor's open(2) rides
	# outside the tracked window (the inode is not yet tracked - the
	# kernel filter drops it silently, no record, no census), so the
	# ground truth counts WRITES ONLY, one syscall per printf.
	exec 3>>"$hot"

	# The window + the storm, concurrent. The why surface holds the
	# track for the whole --since window (track_file, sleep, untrack,
	# one drain); the storm writes fd 3 inside it. The runner's
	# env discipline rides here too (env -i, LC_ALL=C) - the why's
	# output must be byte-stable for the parse, and the run's rc
	# lands in a file because a background subshell cannot printf -v
	# into the caller's variable.
	(
		timeout --foreground 30 env -i \
			PATH="$SM_BIN_PATH_ENV" \
			HOME="$SM_SCRATCH/home" \
			TMPDIR="$SM_SCRATCH" \
			LC_ALL=C \
			LANG=C \
			"$SM_DEFAULT_BIN" why "$hot" --since 6s --raw \
			>"$SM_SCRATCH/lc-why.out" 2>"$SM_SCRATCH/lc-why.err"
		echo "$?" >"$SM_SCRATCH/lc-why.rc"
	) &
	window_pid=$!

	# The settle: the why's track_file lands near-instantly after
	# exec, but the storm must never precede the window - a write
	# before the track is a write the ground truth counts and the
	# camera never saw (a conservation break by construction).
	sleep 1.5

	# The storm: exactly one write(2) per iteration, pure builtins
	# (no fork, no open - the fd rides from the pre-window open), a
	# deadline one second inside the window's close so every counted
	# write completes while the inode is still tracked. The counter
	# is the generator's own loop variable - the ground truth lives
	# OUTSIDE the camera by construction. The target rides a named
	# test seam (SM_LOSS_CERT_TARGET, the selftest's hermetic seat);
	# unset it means 40000, far past the ring's 6553-record capacity.
	local storm_target="${SM_LOSS_CERT_TARGET:-40000}"
	[[ "$storm_target" -ge 1 ]] 2>/dev/null || storm_target=40000
	local storm_deadline=$((SECONDS + 3))
	storm_count=0
	while ((storm_count < storm_target && SECONDS < storm_deadline)); do
		printf 'zejtron-loss-cert-%06d\n' "$storm_count" >&3
		storm_count=$((storm_count + 1))
	done
	printf '%s\n' "$storm_count" >"$count_file"

	# The window closes: untrack, drain, render. Then the parse.
	wait "$window_pid"
	why_rc="$(cat "$SM_SCRATCH/lc-why.rc" 2>/dev/null || echo 99)"
	sm_assert_rc 0 "$why_rc" \
		"loss-certificate: the why window drains and renders (exit 0)"

	# delivered: the --raw section's op=write records - the kernel's
	# own records as drained, uncapped (the identity filter only).
	delivered="$(grep -c 'op=write' "$SM_SCRATCH/lc-why.out" 2>/dev/null || true)"
	delivered="${delivered:-0}"
	# drops: the Unaccounted block's ring-drops entry - the census's
	# own count, rendered by the surface ("N ring drops (...)"). A
	# degraded render (the census unreadable) yields no entry: the
	# parse degrades to 0 and the conservation math names the rest.
	drops="$(grep -E 'ring drops' "$SM_SCRATCH/lc-why.out" 2>/dev/null |
		head -n 1 | sed -E 's/^ *([0-9]+) ring drops.*/\1/' || true)"
	drops="${drops:-0}"

	# The certificate: the conservation identity, direction by
	# direction, with the numbers on every line.
	total=$((delivered + drops))
	if [[ "$delivered" -gt "$storm_count" ]]; then
		sm_fail "loss-certificate: delivered <= ground truth" \
			"the camera rendered $delivered records for $storm_count generated writes - fabrication"
	elif [[ "$total" -ne "$storm_count" ]]; then
		sm_fail "loss-certificate: delivered + drops == ground truth" \
			"delivered $delivered + drops $drops = $total, ground truth $storm_count - events lost uncounted (the silent-loss direction)"
	elif [[ "$drops" -eq 0 && "$storm_count" -gt 8192 ]]; then
		# 8192 > the 256 KiB ring's whole capacity (6553 records):
		# a storm past this bound with zero counted drops means the
		# census did not count a real overload - the lying-census
		# direction, named.
		sm_fail "loss-certificate: the census counts a real overload" \
			"$storm_count writes flooded a 6553-record ring yet drop_census reads 0 - the census missed the overload"
	elif [[ "$drops" -eq 0 ]]; then
		sm_skip "loss-certificate: delivered + drops == ground truth (certificate)" \
			"no overload reached ($storm_count writes inside the window, none past the ring's capacity) - the host was too slow to overflow it"
	else
		# The certificate ISSUES: exact conservation over a real
		# overload. The numbers ARE the certificate - say them.
		sm_pass "loss-certificate: the certificate (delivered $delivered + drops $drops == ground truth $storm_count; the loss is counted and proven)"
	fi

	# The leg ends clean by its own hand (the storm surface's law):
	# the detach unpins the camera, the pin directory is gone.
	sm_run "$SM_SCRATCH/lc-detach.out" "$SM_SCRATCH/lc-detach.err" rc 20 -- \
		"$SM_DEFAULT_BIN" doctor --detach
	sm_assert_rc 0 "$rc" "loss-certificate: doctor --detach ends the leg clean (exit 0)"
	if [[ -e /sys/fs/bpf/zejtron ]]; then
		sm_fail "loss-certificate: detach removes the pin directory" \
			"/sys/fs/bpf/zejtron still exists after detach"
	else
		sm_pass "loss-certificate: detach removes the pin directory"
	fi

	# Descriptor hygiene: the storm's fd dies with the surface.
	exec 3>&-
}
