# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_path.sh — the `path` surface.
#
# Depth: success shape (the active resolution and the duplicates
# section both render), the runtime error path (a command that is not
# on PATH), the clap error path (a missing argument), determinism,
# and the color tri-test. Pure PATH surgery - no eBPF lane, so no
# dormant variant exists to check (documented in the README).
# Exercised flags: the positional COMMAND (no options on this verb).

surface_path() {
	local rc

	# Success path: the binary the battery already trusts (path sh).
	# Budget 20, not the 5s sibling guard: the path report walks the
	# whole PATH estate (and the process table behind the duplicates
	# section), and on a contended runner the first, cold invocation
	# measured past the 5s guard (the e2e best leg landed exit 124
	# while the warm determinism and tri-test runs seconds later
	# passed). The budget is a hang guard, never a perf contract.
	sm_run "$SM_SCRATCH/ok.out" "$SM_SCRATCH/ok.err" rc 20 -- "$SM_DEFAULT_BIN" path sh
	sm_assert_rc 0 "$rc" "path sh exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/ok.out" "path sh renders content"
	sm_assert_contains "$SM_SCRATCH/ok.out" "active:" "path sh names the active resolution"
	sm_assert_contains "$SM_SCRATCH/ok.out" "duplicates:" "path sh names the duplicates section"

	# Runtime error path: a command that cannot exist on PATH. The
	# honest contract (verified against the binary): this is a REPORT,
	# not a failure - exit 0, the miss named on stdout, so scripts can
	# tell a miss from a crash.
	sm_run "$SM_SCRATCH/miss.out" "$SM_SCRATCH/miss.err" rc 20 -- \
		"$SM_DEFAULT_BIN" path "definitely-not-a-command-3f9a"
	sm_assert_rc 0 "$rc" "path <missing> reports honestly with exit 0"
	sm_assert_contains "$SM_SCRATCH/miss.out" "command not found in PATH" \
		"path <missing> names the miss on stdout"

	# Clap error path: the verb without its argument is a usage
	# error, so the contract is exit 2.
	sm_run "$SM_SCRATCH/noarg.out" "$SM_SCRATCH/noarg.err" rc 5 -- "$SM_DEFAULT_BIN" path
	sm_assert_rc 2 "$rc" "path without an argument is a usage error (exit 2)"
	sm_assert_file_nonempty "$SM_SCRATCH/noarg.err" "path usage error prints to stderr"

	# Determinism: PATH state is stable within a run; the report must
	# be byte-stable modulo the volatile-field table.
	sm_deterministic "path sh determinism" 20 -- "$SM_DEFAULT_BIN" path sh

	# The color tri-test on the success invocation (the same 20s
	# budget as above: three full path reports under one guard).
	sm_color_tritest "path sh" 20 -- "$SM_DEFAULT_BIN" path sh

	sm_flag_used "path <command>"
}
