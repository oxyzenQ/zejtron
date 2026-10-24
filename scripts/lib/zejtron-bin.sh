# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only - zejtron is a Linux introspection tool.
#
# lib/zejtron-bin.sh - the shared zejtron binary resolver for the
# script estate (the supermassive runner, the build battery, the
# bench scale audit).
#
# Why this exists: the repo's cargo lanes are profile-named
# (Cargo.toml [profile.pro-*]: pro-native-musl,
# pro-linux-amd64-v3-musl, pro-linux-amd64-v4-musl), so a machine
# that builds through the cargo aliases has NO
# target/release/zejtron - the binary lands in
# target/<profile>/zejtron (host lane) or
# target/<triple>/<profile>/zejtron (--target lane). Every script
# that exercises the binary must therefore DISCOVER it instead of
# assuming the basic release dir exists.
#
# zejtron_resolve_bin <out-var> <target-root> [explicit-path]
#
# Resolution order (the caller owns the not-found error):
#   1. [explicit-path] when non-empty - authoritative; a wrong
#      explicit path must error in the caller, never silently fall
#      back to a different binary;
#   2. $ZEJTRON_BIN_PATH when non-empty - same authoritative law;
#   3. discovery under <target-root>/target: two globs cover the
#      whole cargo target layout (<triple>/<profile>/zejtron and
#      <profile>/zejtron); the parent directory classifies the tier
#      (release/debug = the basic cargo lanes, anything else = a
#      named profile), the custom tier wins over the basic tier,
#      and the newest executable wins within a tier (bash -nt).
#
# Tier 3 prefers custom profile dirs over a plain release build ON
# PURPOSE: the repo's own CI and the owner's machine build through
# the named profile lanes, so target/release/zejtron is the last
# resort, never the default.

zejtron_resolve_bin() {
	local out_var="$1" root="$2" explicit="${3:-}"
	# Tier 1 + 2: the caller's explicit path and the env contract.
	# Both ride out through the callee's printf -v contract: the
	# assignment lands in the caller's named variable.
	if [[ -n "$explicit" ]]; then
		printf -v "$out_var" '%s' "$explicit"
		return 0
	fi
	if [[ -n "${ZEJTRON_BIN_PATH:-}" ]]; then
		printf -v "$out_var" '%s' "$ZEJTRON_BIN_PATH"
		return 0
	fi
	# Tier 3: discovery. Unmatched globs stay literal and fail the
	# -f/-x guard, so no nullglob surgery is needed and the caller's
	# strict mode is never poked.
	local cand parent best_custom="" best_basic=""
	for cand in "$root"/target/*/*/zejtron "$root"/target/*/zejtron; do
		[[ -f "$cand" && -x "$cand" ]] || continue
		parent="${cand%/*}"
		parent="${parent##*/}"
		if [[ "$parent" == "release" || "$parent" == "debug" ]]; then
			if [[ -z "$best_basic" || "$cand" -nt "$best_basic" ]]; then
				best_basic=$cand
			fi
		elif [[ -z "$best_custom" || "$cand" -nt "$best_custom" ]]; then
			best_custom=$cand
		fi
	done
	if [[ -n "$best_custom" ]]; then
		printf -v "$out_var" '%s' "$best_custom"
	elif [[ -n "$best_basic" ]]; then
		printf -v "$out_var" '%s' "$best_basic"
	else
		printf -v "$out_var" ''
	fi
	return 0
}
