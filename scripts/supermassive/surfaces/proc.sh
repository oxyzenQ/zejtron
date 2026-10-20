# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_proc.sh — the `proc` surface.
#
# Depth: the success shape, every documented flag (--me --depth
# --find --no-pid --no-color plus the positional USER_OR_UID), the
# removed-flag refusal path (night-improve-34: --live/--watch/--since
# are unknown arguments now), structural determinism (the process
# tree is live state), and the color tri-test. Pure procfs - no
# dormant variant.
# Exercised flags: --me, --depth, --find, --no-pid, --no-color,
# positional USER_OR_UID.

surface_proc() {
	local rc

	# Success path: the caller's own process family.
	sm_run "$SM_SCRATCH/ok.out" "$SM_SCRATCH/ok.err" rc 5 -- "$SM_DEFAULT_BIN" proc --me
	sm_assert_rc 0 "$rc" "proc --me exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/ok.out" "proc renders content"

	# --depth bounds the render.
	sm_run "$SM_SCRATCH/depth.out" "$SM_SCRATCH/depth.err" rc 5 -- \
		"$SM_DEFAULT_BIN" proc --me --depth 1
	sm_assert_rc 0 "$rc" "proc --me --depth 1 exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/depth.out" "proc --depth 1 renders content"
	sm_flag_used "proc --depth"

	# --find narrows to a family that must exist: the suite itself
	# runs under bash, so the bash family is a stable target.
	sm_run "$SM_SCRATCH/find.out" "$SM_SCRATCH/find.err" rc 5 -- \
		"$SM_DEFAULT_BIN" proc --me --find sh --depth 2
	sm_assert_rc 0 "$rc" "proc --me --find sh exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/find.out" "proc --find renders content"
	sm_flag_used "proc --find"

	# --no-pid hides the pid labels. The honest check: the label
	# spelling that the plain render carries must be gone.
	sm_run "$SM_SCRATCH/nopid.out" "$SM_SCRATCH/nopid.err" rc 5 -- \
		"$SM_DEFAULT_BIN" proc --me --no-pid --depth 1
	sm_assert_rc 0 "$rc" "proc --me --no-pid exits 0"
	if grep -q "pid=" "$SM_SCRATCH/ok.out"; then
		sm_assert_not_contains "$SM_SCRATCH/nopid.out" "pid=" "proc --no-pid removes the pid= labels"
	else
		# The plain render carries no pid= spelling on this host; the
		# honest equivalent is: --no-pid output is byte-equal to the
		# plain run (nothing to remove, nothing changed).
		if cmp -s "$SM_SCRATCH/ok.out" "$SM_SCRATCH/nopid.out"; then
			sm_pass "proc --no-pid removes the pid= labels (none rendered on this host)"
		else
			sm_fail "proc --no-pid removes the pid= labels" \
				"plain render has no pid= but --no-pid output still differs"
		fi
	fi
	sm_flag_used "proc --no-pid"

	# --no-color is the documented per-verb opt-out: its output must
	# be byte-equal to the plain piped run (which is already plain).
	sm_run "$SM_SCRATCH/nocolor.out" "$SM_SCRATCH/nocolor.err" rc 5 -- \
		"$SM_DEFAULT_BIN" proc --me --no-color --depth 1
	sm_assert_rc 0 "$rc" "proc --no-color exits 0"
	if cmp -s "$SM_SCRATCH/depth.out" "$SM_SCRATCH/nocolor.out"; then
		sm_pass "proc --no-color matches the plain piped render byte for byte"
	else
		sm_fail "proc --no-color matches the plain piped render byte for byte" \
			"--no-color output differs from the piped render"
	fi
	sm_flag_used "proc --no-color"

	# Positional USER_OR_UID: root always exists, uid 0 is root.
	sm_run "$SM_SCRATCH/root.out" "$SM_SCRATCH/root.err" rc 5 -- "$SM_DEFAULT_BIN" proc root
	sm_assert_rc 0 "$rc" "proc root exits 0"
	sm_run "$SM_SCRATCH/uid.out" "$SM_SCRATCH/uid.err" rc 5 -- "$SM_DEFAULT_BIN" proc 0
	sm_assert_rc 0 "$rc" "proc 0 (uid positional) exits 0"

	# The removed-flag refusal path (night-improve-34): the lifecycle
	# flags are gone entirely - clap refuses them as unknown arguments,
	# exit 2, battery-pinned wording.
	local dead
	for dead in --live --watch; do
		sm_run "$SM_SCRATCH/dead.out" "$SM_SCRATCH/dead.err" rc 5 -- "$SM_DEFAULT_BIN" proc "$dead"
		sm_assert_rc 2 "$rc" "proc $dead is refused (exit 2)"
		if grep -q "unexpected argument '$dead'" "$SM_SCRATCH/dead.out" "$SM_SCRATCH/dead.err" 2>/dev/null; then
			sm_pass "proc $dead names the unknown argument"
		else
			sm_fail "proc $dead names the unknown argument" \
				"neither stream mentioned 'unexpected argument'"
		fi
	done

	# Determinism: the process tree moves under the suite; the stable
	# skeleton is the honest claim.
	sm_deterministic_structural "proc determinism (structural)" 5 -- \
		"$SM_DEFAULT_BIN" proc --me --depth 1

	# The color tri-test.
	sm_color_tritest "proc" 5 -- "$SM_DEFAULT_BIN" proc --me --depth 1

	sm_flag_used "proc --me"
}
