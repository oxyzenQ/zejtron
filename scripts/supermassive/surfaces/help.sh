# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_help.sh — the `-h` / `--help` surface.
#
# The help surface is the one surface every user sees first; its
# depth here: -h renders the usage, --help is byte-equal to -h, the
# bare invocation renders the same help (main's bare-`zejtron`
# branch), the Pro mode section (the complete flag estate) is
# present, the unknown-flag refusal (exit 2), the typo-suggestion
# path, the forced 16-color floor (the clap lane's own palette), the
# color tri-test, and the --check-update flag (the one networked
# flag - asserted structurally, never faked).
# Exercised flags: -h, --help, --check-update.

surface_help() {
	local rc

	# -h renders the usage on stdout, exit 0.
	sm_run "$SM_SCRATCH/h.out" "$SM_SCRATCH/h.err" rc 5 -- "$SM_DEFAULT_BIN" -h
	sm_assert_rc 0 "$rc" "-h exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/h.out" "-h renders content"
	sm_assert_contains "$SM_SCRATCH/h.out" "Usage:" "-h renders the usage line"

	# --help is byte-equal to -h (one help authority, night-improve-15).
	sm_run "$SM_SCRATCH/help.out" "$SM_SCRATCH/help.err" rc 5 -- "$SM_DEFAULT_BIN" --help
	sm_assert_rc 0 "$rc" "--help exits 0"
	if cmp -s "$SM_SCRATCH/h.out" "$SM_SCRATCH/help.out"; then
		sm_pass "--help is byte-equal to -h"
	else
		sm_fail "--help is byte-equal to -h" "the two help spellings differ"
	fi

	# The bare invocation renders the same help (exit 0).
	sm_run "$SM_SCRATCH/bare.out" "$SM_SCRATCH/bare.err" rc 5 -- "$SM_DEFAULT_BIN"
	sm_assert_rc 0 "$rc" "bare zejtron exits 0"
	sm_assert_contains "$SM_SCRATCH/bare.out" "Usage:" "bare zejtron renders the usage line"

	# The Pro mode section: the after_help carries the complete flag
	# estate; its presence is the render's depth claim.
	if grep -q "Pro mode" "$SM_SCRATCH/h.out"; then
		sm_pass "-h carries the Pro mode section"
	else
		sm_fail "-h carries the Pro mode section" "no Pro mode section in the help render"
	fi

	# Unknown flag refusal: exit 2 on stderr.
	sm_run "$SM_SCRATCH/unknown.out" "$SM_SCRATCH/unknown.err" rc 5 -- \
		"$SM_DEFAULT_BIN" --definitely-not-a-flag
	sm_assert_rc 2 "$rc" "unknown flag is a usage error (exit 2)"
	sm_assert_file_nonempty "$SM_SCRATCH/unknown.err" "unknown-flag error prints to stderr"

	# Typo path: a near-miss subcommand gets clap's suggestion lane.
	sm_run "$SM_SCRATCH/typo.out" "$SM_SCRATCH/typo.err" rc 5 -- "$SM_DEFAULT_BIN" pat
	sm_assert_rc 2 "$rc" "typo subcommand is a usage error (exit 2)"
	if grep -qi "similar\|did you mean" "$SM_SCRATCH/typo.out" "$SM_SCRATCH/typo.err" 2>/dev/null; then
		sm_pass "typo subcommand gets the suggestion lane"
	else
		sm_fail "typo subcommand gets the suggestion lane" \
			"no suggestion wording on either stream"
	fi

	# The color tri-test (the clap lane obeys the same capability
	# ladder) plus the 16-color forced floor.
	sm_color_tritest "help" 5 -- "$SM_DEFAULT_BIN" -h
	sm_forced_floor_test "help" 5 -- "$SM_DEFAULT_BIN" -h

	# --check-update: the one networked flag. The honest structural
	# assertion - success renders on stdout; failure carries the
	# labeled error wording from main's gate. Never faked: whichever
	# way the network falls, the STRUCTURE is pinned. The per-test
	# ceiling exceeds the in-binary 15s curl cap.
	sm_run "$SM_SCRATCH/upd.out" "$SM_SCRATCH/upd.err" rc 20 -- "$SM_DEFAULT_BIN" --check-update
	if [[ "$rc" -eq 0 ]]; then
		sm_pass "--check-update exits 0"
		sm_assert_file_nonempty "$SM_SCRATCH/upd.out" "--check-update renders the upstream status"
	elif grep -q "update check failed" "$SM_SCRATCH/upd.out" "$SM_SCRATCH/upd.err" 2>/dev/null; then
		sm_pass "--check-update failure carries the labeled error (networked surface)"
	else
		sm_fail "--check-update structural contract" \
			"exit $rc with neither a render nor the labeled failure"
	fi
	sm_flag_used "-h"
	sm_flag_used "--help"
	sm_flag_used "--check-update"

	# The update check's other documented spelling: the alias.
	sm_run "$SM_SCRATCH/alias.out" "$SM_SCRATCH/alias.err" rc 20 -- "$SM_DEFAULT_BIN" --check-updated
	if [[ "$rc" -eq 0 ]] || grep -q "update check failed" "$SM_SCRATCH/alias.out" "$SM_SCRATCH/alias.err" 2>/dev/null; then
		sm_pass "--check-updated (alias) obeys the same contract"
	else
		sm_fail "--check-updated (alias) obeys the same contract" "exit $rc, neither render nor labeled failure"
	fi
}
