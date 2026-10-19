#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool.

set -Eeuo pipefail

check_command() {
	local command="$1"
	local label="${2:-$1}"
	if ! command -v "$command" >/dev/null 2>&1; then
		echo "error: required command not found: $label" >&2
		if [[ "$label" == "codespell" ]]; then
			echo "hint: install codespell or run SKIP_CODESPELL=1 ./scripts/build.sh" >&2
		fi
		exit 1
	fi
}

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

# Two modes:
#   check-all (default) - the full commit gate: toolchain checks, fmt,
#     clippy, cargo check, tests, release build, then the CLI battery.
#   battery - the CLI runtime battery only, no compile: the binary must
#     already exist. The supermassive CI lane calls this per matrix leg
#     (ZEJTRON_BIN_PATH pointing at the leg's freshly built binary),
#     so every build shape the repo ships gets the same runtime
#     contract, not just the host shape.
#   miri - undefined-behavior verification of the pure-Rust module
#     families (scripts/lib/miri.sh owns the runner: the audited
#     scope, the stamp file contract, the banner). Needs the nightly
#     toolchain with the miri component; --no-install is CI's
#     contract. Sub-flags: --filter <pat>, --no-install, --full.
#   quiet (-q|--quiet, check-all and battery modes) - essentials
#     only: the per-command `+ cmd` chatter is suppressed and every
#     verdict-bearing line (errors, tolerated smokes, the final
#     verdict) always emits. The CI shape - the fast lane names the
#     exact invocation in its job title, so a reader can copy the
#     name straight into a terminal and get the same gate locally.
MODE="check-all"
QUIET=0
case "${1:---check-all}" in
--check-all | check-all) MODE="check-all" ;;
--battery | battery) MODE="battery" ;;
--miri | miri) MODE="miri" ;;
*)
	echo "usage: ./scripts/build.sh [--check-all|--battery|--miri] [-q|--quiet]" >&2
	exit 2
	;;
esac
if [[ "$MODE" != "miri" ]]; then
	if [[ "$#" -gt 0 ]]; then
		shift
	fi
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--quiet | -q) QUIET=1 ;;
		*)
			echo "usage: ./scripts/build.sh [--check-all|--battery|--miri] [-q|--quiet]" >&2
			exit 2
			;;
		esac
		shift
	done
fi

# miri sub-flags (parsed before anything else runs).
MIRI_FILTER=""
MIRI_NO_INSTALL=0
MIRI_FULL=0
# The miri flags are consumed by scripts/lib/miri.sh after the
# source below - the single-file lint view cannot see that, so the
# unused-variable verdict is disabled for this parse block.
# shellcheck disable=SC2034
if [[ "$MODE" == "miri" ]]; then
	shift
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--filter)
			MIRI_FILTER="$2"
			shift 2
			;;
		--no-install)
			MIRI_NO_INSTALL=1
			shift
			;;
		--full)
			MIRI_FULL=1
			shift
			;;
		*)
			echo "usage: ./scripts/build.sh miri [--filter <pat>|--no-install|--full]" >&2
			exit 2
			;;
		esac
	done
fi

# The binary the battery exercises. Override for cross-shape legs
# (e.g. ZEJTRON_BIN_PATH=target/x86_64-unknown-linux-musl/release/zejtron).
ZEJTRON_BIN="${ZEJTRON_BIN_PATH:-target/release/zejtron}"

if [[ "$MODE" == "battery" ]]; then
	if [[ ! -x "$ZEJTRON_BIN" ]]; then
		echo "error: battery mode needs a built binary - none at $ZEJTRON_BIN" >&2
		echo "hint: build it first (cargo build --release [--target ...]) or run the full check-all" >&2
		exit 1
	fi
elif [[ "$MODE" == "miri" ]]; then
	# miri's own tool needs (nightly cargo + rustc with the miri
	# component, which the caller or --install provides) - it never
	# runs the rustfmt/clippy/codespell lint estate, so demanding it
	# here only wedged the CI lane that installs just the miri
	# toolchain (the Dragon Guard leg's codespell red).
	check_command cargo
	check_command rustc
	check_command git
else
	check_command cargo
	check_command rustc
	check_command git
	check_command rustfmt
	check_command cargo-clippy clippy
	if [[ "${SKIP_CODESPELL:-0}" != "1" ]]; then
		check_command codespell
	fi
fi

tmpdir="$(mktemp -d)"
cleanup() {
	rm -rf "$tmpdir"
}
trap cleanup EXIT

run() {
	if [[ "$QUIET" != "1" ]]; then
		echo "+ $*"
	fi
	"$@"
}

capture() {
	local name="$1"
	shift
	"$@" >"$tmpdir/${name}.out" 2>"$tmpdir/${name}.err"
}

expect_fail_contains() {
	local name="$1"
	local expected="$2"
	shift 2

	set +e
	"$@" >"$tmpdir/${name}.out" 2>"$tmpdir/${name}.err"
	local status=$?
	set -e

	if [[ "$status" -eq 0 ]]; then
		echo "error: $* unexpectedly succeeded" >&2
		cat "$tmpdir/${name}.out" >&2
		exit 1
	fi
	# grep -- : the expected text may lead with a dash (a flag's
	# own error line); without the separator it parses as an
	# option and the smoke reports a tool failure, not a verdict.
	if ! grep -q -- "$expected" "$tmpdir/${name}.out" "$tmpdir/${name}.err"; then
		echo "error: $* did not mention '$expected'" >&2
		cat "$tmpdir/${name}.out" >&2
		cat "$tmpdir/${name}.err" >&2
		exit 1
	fi
}

# The runner file is linted by the same quad as its own entry;
# re-resolving the dynamic path here adds nothing to that verdict.
# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/miri.sh"

if [[ "$MODE" == "check-all" ]]; then
	run rustc --version
	run cargo --version
	run cargo fmt --all -- --check
	run cargo check --all-targets --all-features --locked
	run cargo clippy --all-targets --all-features --locked -- -D warnings
	run cargo test --all-targets --all-features --locked
	# The dormant lane (night-improve-5): --no-default-features is
	# the documented opt-out (the README names it), so the battery
	# guards it the same way it guards the default - the snapshot-
	# only surface must never rot behind the feature flip.
	run cargo clippy --all-targets --no-default-features --locked -- -D warnings
	run cargo test --all-targets --no-default-features --locked
	run cargo build --release --locked
elif [[ "$MODE" == "miri" ]]; then
	run_miri
	exit $?
fi

run "$ZEJTRON_BIN" --help
run "$ZEJTRON_BIN" doctor

capture version "$ZEJTRON_BIN" --version
if ! grep -q "zejtron" "$tmpdir/version.out"; then
	echo "error: version output did not contain 'zejtron'" >&2
	cat "$tmpdir/version.out" >&2
	cat "$tmpdir/version.err" >&2
	exit 1
fi

capture path_sh "$ZEJTRON_BIN" path sh
if ! grep -q "active:" "$tmpdir/path_sh.out"; then
	echo "error: path sh output did not contain 'active:'" >&2
	cat "$tmpdir/path_sh.out" >&2
	cat "$tmpdir/path_sh.err" >&2
	exit 1
fi
if ! grep -q "duplicates:" "$tmpdir/path_sh.out"; then
	echo "error: path sh output did not contain 'duplicates:'" >&2
	cat "$tmpdir/path_sh.out" >&2
	cat "$tmpdir/path_sh.err" >&2
	exit 1
fi

run "$ZEJTRON_BIN" recent . --limit 5
run "$ZEJTRON_BIN" port
run "$ZEJTRON_BIN" port --tcp
run "$ZEJTRON_BIN" port --udp
run "$ZEJTRON_BIN" port --tcp --group
run "$ZEJTRON_BIN" proc --me --depth 1
run "$ZEJTRON_BIN" proc --me --no-pid --depth 1
run "$ZEJTRON_BIN" proc --me --find sh --depth 2
run "$ZEJTRON_BIN" holds 53
touch "$tmpdir/held file"
printf 'hello\n' >"$tmpdir/touched file"
mkdir "$tmpdir/touched dir"
printf 'hello\n' >"$tmpdir/why file with spaces"
capture holds_temp "$ZEJTRON_BIN" holds "$tmpdir/held file"
if ! grep -q "nothing visibly holds the path now" "$tmpdir/holds_temp.out"; then
	echo "error: holds temp file output did not mention the no-holder verdict" >&2
	cat "$tmpdir/holds_temp.out" >&2
	cat "$tmpdir/holds_temp.err" >&2
	exit 1
fi
capture touch_file "$ZEJTRON_BIN" touch "$tmpdir/touched file"
if ! grep -q "type file" "$tmpdir/touch_file.out"; then
	echo "error: touch temp file output did not mention the metadata rows" >&2
	cat "$tmpdir/touch_file.out" >&2
	cat "$tmpdir/touch_file.err" >&2
	exit 1
fi
capture touch_dir "$ZEJTRON_BIN" touch "$tmpdir/touched dir"
if ! grep -q "type directory" "$tmpdir/touch_dir.out"; then
	echo "error: touch temp directory output did not mention the metadata rows" >&2
	cat "$tmpdir/touch_dir.out" >&2
	cat "$tmpdir/touch_dir.err" >&2
	exit 1
fi
run "$ZEJTRON_BIN" why 53
capture why_readme "$ZEJTRON_BIN" why README.md
if ! grep -q "The evidence supports:" "$tmpdir/why_readme.out"; then
	echo "error: why README output did not mention the verdict" >&2
	cat "$tmpdir/why_readme.out" >&2
	cat "$tmpdir/why_readme.err" >&2
	exit 1
fi
run "$ZEJTRON_BIN" why /etc/resolv.conf
capture why_spaces "$ZEJTRON_BIN" why "$tmpdir/why file with spaces"
if ! grep -q "why file with spaces" "$tmpdir/why_spaces.out"; then
	echo "error: why path with spaces output did not mention the path" >&2
	cat "$tmpdir/why_spaces.out" >&2
	cat "$tmpdir/why_spaces.err" >&2
	exit 1
fi
capture recent_zero "$ZEJTRON_BIN" recent . --limit 0
if [[ ! -s "$tmpdir/recent_zero.out" ]]; then
	echo "error: recent --limit 0 produced empty output" >&2
	cat "$tmpdir/recent_zero.err" >&2
	exit 1
fi

expect_fail_contains recent_invalid "invalid duration" "$ZEJTRON_BIN" recent . --since nope
expect_fail_contains port_zero "invalid port" "$ZEJTRON_BIN" port 0
expect_fail_contains port_too_high "invalid port" "$ZEJTRON_BIN" port 65536
expect_fail_contains port_invalid "invalid port" "$ZEJTRON_BIN" port abc
expect_fail_contains port_conflict "cannot be used" "$ZEJTRON_BIN" port --listen --all
expect_fail_contains holds_zero "invalid port" "$ZEJTRON_BIN" holds 0
expect_fail_contains holds_too_high "invalid port" "$ZEJTRON_BIN" holds 65536
expect_fail_contains touch_missing "path not found" "$ZEJTRON_BIN" touch "$tmpdir/missing path"
expect_fail_contains why_zero "invalid port" "$ZEJTRON_BIN" why 0
expect_fail_contains why_too_high "invalid port" "$ZEJTRON_BIN" why 65536
expect_fail_contains why_missing "path not found" "$ZEJTRON_BIN" why "$tmpdir/missing path"
# night-improve-34: the lifecycle surface is gone entirely - --live,
# --watch, and the lifecycle --since window are unknown flags now,
# refused by clap's unknown-argument error, no deprecation alias.
expect_fail_contains proc_live_is_unknown "unexpected argument '--live'" "$ZEJTRON_BIN" proc --live
expect_fail_contains proc_watch_is_unknown "unexpected argument '--watch'" "$ZEJTRON_BIN" proc --watch
expect_fail_contains proc_since_is_unknown "unexpected argument '--since'" "$ZEJTRON_BIN" proc --since 30s

if [[ "$MODE" == "check-all" ]]; then
	if [[ "${SKIP_CODESPELL:-0}" == "1" ]]; then
		echo "+ codespell skipped because SKIP_CODESPELL=1"
	else
		run codespell --config .codespellrc .
	fi
fi

echo "All checks passed. Safe to commit."
