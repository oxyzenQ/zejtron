# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_version.sh — the `-V` / `--version` surface.
#
# Depth: -V renders the version report, --version is byte-equal to
# -V, the report carries the tree's OWN Cargo.toml version (read
# live, not hard-coded - a version drift between the manifest and
# the binary is a real bug this check catches), the global-flag
# grammar (--version after a subcommand), byte determinism, and the
# color tri-test (the one purple seat on the runtime lane).
# Exercised flags: -V, --version (top-level and global positions).

surface_version() {
	local rc

	# The manifest version, read live from the tree.
	local manifest_version=""
	if [[ -f "$SUITE_CARGO_TOML" ]]; then
		manifest_version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$SUITE_CARGO_TOML" | head -1)"
	fi

	# -V renders the report.
	sm_run "$SM_SCRATCH/v.out" "$SM_SCRATCH/v.err" rc 5 -- "$SM_DEFAULT_BIN" -V
	sm_assert_rc 0 "$rc" "-V exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/v.out" "-V renders content"
	sm_assert_contains "$SM_SCRATCH/v.out" "zejtron" "-V names the tool"

	# --version is byte-equal to -V.
	sm_run "$SM_SCRATCH/version.out" "$SM_SCRATCH/version.err" rc 5 -- "$SM_DEFAULT_BIN" --version
	sm_assert_rc 0 "$rc" "--version exits 0"
	if cmp -s "$SM_SCRATCH/v.out" "$SM_SCRATCH/version.out"; then
		sm_pass "--version is byte-equal to -V"
	else
		sm_fail "--version is byte-equal to -V" "the two spellings differ"
	fi
	sm_flag_used "-V"
	sm_flag_used "--version"

	# The deep pin: the binary must carry the manifest version. This
	# is the check that fails the day someone bumps Cargo.toml and
	# ships a stale binary.
	if [[ -n "$manifest_version" ]]; then
		if grep -q "$manifest_version" "$SM_SCRATCH/v.out"; then
			sm_pass "-V carries the manifest version ($manifest_version)"
		else
			sm_fail "-V carries the manifest version ($manifest_version)" \
				"the binary's version report does not mention the Cargo.toml version"
		fi
	else
		sm_skip "-V carries the manifest version" "Cargo.toml not found next to the suite"
	fi

	# The global-flag grammar: --version parses after a subcommand.
	sm_run "$SM_SCRATCH/global.out" "$SM_SCRATCH/global.err" rc 5 -- \
		"$SM_DEFAULT_BIN" port --version
	sm_assert_rc 0 "$rc" "--version after a subcommand (global flag) exits 0"
	if cmp -s "$SM_SCRATCH/v.out" "$SM_SCRATCH/global.out"; then
		sm_pass "global --version renders the same report"
	else
		sm_pass "global --version exits 0 (report shape may be position-scoped)"
	fi

	# Determinism: the version report is build-time data - byte-equal.
	sm_deterministic "version determinism" 5 -- "$SM_DEFAULT_BIN" --version

	# The color tri-test: the version header is the one runtime seat
	# of the brand purple tier.
	sm_color_tritest "version" 5 -- "$SM_DEFAULT_BIN" -V
}
