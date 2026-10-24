# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_net.sh — the `net` surface.
#
# Depth: the success shape (the loopback interface exists on every
# Linux host - the one interface the suite may pin unconditionally),
# the no-argument grammar refusal, structural determinism (byte and
# packet counters move on their own), and the color tri-test. Pure
# procfs/sysfs - no dormant variant. Exercised flags: none (net
# takes no options - the refusal of an extra argument is itself a
# tested contract).

surface_net() {
	local rc

	# Success path.
	sm_run "$SM_SCRATCH/ok.out" "$SM_SCRATCH/ok.err" rc 5 -- "$SM_DEFAULT_BIN" net
	sm_assert_rc 0 "$rc" "net exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/ok.out" "net renders content"
	sm_assert_contains "$SM_SCRATCH/ok.out" "lo" "net names the loopback interface"

	# The typed JSON lane (night-dragon-4): the automation contract
	# - pure JSON, silent stderr, the typed interface rows.
	sm_run "$SM_SCRATCH/json.out" "$SM_SCRATCH/json.err" rc 5 -- \
		"$SM_DEFAULT_BIN" net --print-json
	sm_assert_rc 0 "$rc" "net --print-json exits 0"
	sm_assert_silent_stderr "$SM_SCRATCH/json.err" \
		"net --print-json keeps stderr silent"
	sm_assert_pure_json "$SM_SCRATCH/json.out" \
		"net --print-json stdout is pure JSON"
	sm_assert_json "$SM_SCRATCH/json.out" '.interfaces | type == "array"' \
		"net --print-json carries the interfaces array"
	sm_assert_json "$SM_SCRATCH/json.out" 'any(.interfaces[]; .name == "lo")' \
		"net --print-json names the loopback row"
	sm_flag_used "net --print-json"

	# Grammar refusal: net takes no positional argument, so an extra
	# word is a usage error - exit 2.
	sm_run "$SM_SCRATCH/extra.out" "$SM_SCRATCH/extra.err" rc 5 -- "$SM_DEFAULT_BIN" net extra-arg
	sm_assert_rc 2 "$rc" "net <extra-arg> is a usage error (exit 2)"
	sm_assert_file_nonempty "$SM_SCRATCH/extra.err" "net usage error prints to stderr"

	# Determinism: the counters move under the suite; the stable
	# skeleton is the honest claim.
	sm_deterministic_structural "net determinism (structural)" 5 -- "$SM_DEFAULT_BIN" net

	# The color tri-test. Net is a GAUGE surface (rx/tx counters move
	# between any two invocations), so the NO_COLOR equality is
	# asserted on the normalized bytes.
	SM_TRITEST_NORMALIZE=1 sm_color_tritest "net" 5 -- "$SM_DEFAULT_BIN" net
}
