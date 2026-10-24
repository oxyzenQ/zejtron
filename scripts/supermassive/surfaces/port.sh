# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_port.sh — the `port` surface.
#
# Depth: the success shape, every documented flag (--tcp --udp
# --listen --all --numeric --group --no-pid --since --events-only
# --snapshot-only), the invalid-port error ladder (0 / 65536 / abc),
# the clap conflict error (--listen --all), structural determinism
# (the socket table moves under the suite by definition), and the
# color tri-test. Pure procfs - no dormant variant.
#
# The window law (night-dragon-3): the port default window is SIXTY
# seconds (the Lazy Camera's collect width) and the live collect
# sleeps the full width, so every lane that is not explicitly the
# event-window test rides --snapshot-only, and the window test rides
# the 1s clamp floor. The tri-test rides the structural gauge: the
# socket table is live kernel state and moves between ANY two
# invocations - the tri-test answers the color question, never the
# data question.
# Exercised flags: all ten documented port flags.

surface_port() {
	local rc

	# Success path: the wide snapshot.
	sm_run "$SM_SCRATCH/ok.out" "$SM_SCRATCH/ok.err" rc 5 -- "$SM_DEFAULT_BIN" port --snapshot-only
	sm_assert_rc 0 "$rc" "port --snapshot-only exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/ok.out" "port renders content"

	# Flag ladder: every documented flag runs clean, one invocation
	# each (the flag-specific contract is rc 0 + rendered content;
	# the render shape is pinned by the snapshot check above).
	# Every lane rides --snapshot-only (the window law): without it
	# the default 60s collect would burn the whole per-test timeout
	# and die as exit 124 - the night-dragon-3 post-mortem's seven
	# dead lanes, fixed at the invocation, not the timeout.
	local flag
	local -a flag_args
	for flag in --tcp --udp --listen --all --numeric --group --no-pid --snapshot-only; do
		flag_args=("$flag")
		[[ "$flag" != "--snapshot-only" ]] && flag_args+=("--snapshot-only")
		sm_run "$SM_SCRATCH/f.out" "$SM_SCRATCH/f.err" rc 5 -- \
			"$SM_DEFAULT_BIN" port "${flag_args[@]}"
		sm_assert_rc 0 "$rc" "port $flag exits 0"
		sm_assert_file_nonempty "$SM_SCRATCH/f.out" "port $flag renders content"
		sm_flag_used "port $flag"
	done

	# --events-only and --since are the event-window family. The
	# verified honest contract: the window renders with its width and
	# states its capture ability plainly (unavailable or observed -
	# never a fake event table). The width is the 1s clamp floor: the
	# contract under test is the window grammar and the honest
	# header, not a sixty-second wait (the window law, night-dragon-3;
	# the window grammar's own pins live in the unit tests).
	sm_run "$SM_SCRATCH/ev.out" "$SM_SCRATCH/ev.err" rc 5 -- \
		"$SM_DEFAULT_BIN" port --events-only --since 1s
	sm_assert_rc 0 "$rc" "port --events-only --since 1s exits 0"
	sm_assert_contains "$SM_SCRATCH/ev.out" "Changes in the last" \
		"port --events-only renders the honest window header"
	sm_flag_used "port --events-only"
	sm_flag_used "port --since"

	# A combined ladder: the flags compose.
	sm_run "$SM_SCRATCH/comb.out" "$SM_SCRATCH/comb.err" rc 5 -- \
		"$SM_DEFAULT_BIN" port --tcp --numeric --no-pid --group --snapshot-only
	sm_assert_rc 0 "$rc" "port --tcp --numeric --no-pid --group --snapshot-only composes"

	# Error ladder: invalid port numbers are runtime failures (exit 1)
	# with the battery-pinned wording.
	local bad
	for bad in 0 65536 abc; do
		sm_run "$SM_SCRATCH/bad.out" "$SM_SCRATCH/bad.err" rc 5 -- "$SM_DEFAULT_BIN" port "$bad"
		sm_assert_rc 1 "$rc" "port $bad exits 1"
		if grep -q "invalid port" "$SM_SCRATCH/bad.out" "$SM_SCRATCH/bad.err" 2>/dev/null; then
			sm_pass "port $bad names the invalid port"
		else
			sm_fail "port $bad names the invalid port" "neither stream mentioned 'invalid port'"
		fi
	done

	# Clap conflict: --listen and --all are declared exclusive, so
	# this is a usage error - exit 2, battery-pinned wording.
	sm_run "$SM_SCRATCH/conf.out" "$SM_SCRATCH/conf.err" rc 5 -- \
		"$SM_DEFAULT_BIN" port --listen --all
	sm_assert_rc 2 "$rc" "port --listen --all is a usage error (exit 2)"
	if grep -q "cannot be used" "$SM_SCRATCH/conf.out" "$SM_SCRATCH/conf.err" 2>/dev/null; then
		sm_pass "port --listen --all names the conflict"
	else
		sm_fail "port --listen --all names the conflict" "neither stream mentioned 'cannot be used'"
	fi

	# Determinism: the socket table is live kernel state, so the
	# honest determinism claim is the stable skeleton (headers and
	# verdict lines), not the moving rows.
	sm_deterministic_structural "port determinism (structural)" 5 -- \
		"$SM_DEFAULT_BIN" port --snapshot-only --numeric

	# The color tri-test, on the stable skeleton: the socket table
	# moves between ANY two invocations (the same depth the
	# structural determinism check claims above), so the raw
	# byte-equality would test the host's churn, not the palette.
	SM_TRITEST_STRUCTURAL=1 sm_color_tritest "port" 5 -- \
		"$SM_DEFAULT_BIN" port --snapshot-only
}
