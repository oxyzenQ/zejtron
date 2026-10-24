#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# The runner's variables are a contract with the sourced engine and
# the leg scripts: they are assigned here and read elsewhere, a shape
# the per-file unused-variable rule cannot see.
# shellcheck disable=SC2034 disable=SC1091
# OS: Linux only — zejtron is a Linux introspection tool.
#
# supermassive.sh — the end-to-end suite runner.
#
# The supermassive contract: every surface, every flag, every error
# path, exercised against the REAL compiled binary - not a unit test,
# not a smoke test, not a single happy path. Per surface: at least
# one success check, one error check, one determinism check, and the
# color tri-test. Every SKIP names its reason. The exit code is
# trustworthy: 0 = all passed or skipped-with-reason, 1 = any failure.
#
# Usage:
#   ./scripts/supermassive/supermassive.sh --leg low|best [options]
#
# Options:
#   --leg low|best        required: which time budget the run claims
#                         (low = 60s wall, best = 300s wall; the depth
#                         is identical on both legs - only the budget
#                         differs)
#   --bin PATH            the binary to exercise ($ZEJTRON_BIN_PATH,
#                         then discovery in target/: custom cargo
#                         profile dirs first, release/debug last)
#   --surfaces a,b,c      run only the named surfaces (debug aid; the
#                         legs always run the full list)
#   --keep-scratch        keep per-surface scratch dirs (post-mortem)
#   --self-test           exercise the engine itself, no binary needed
#   --quiet               surface detail lines suppressed, verdict
#                         lines always emitted
#   --help                this text
#
# The suite is bash + coreutils + jq (the typed JSON law's harness
# dependency - the binary itself stays jq-free). It is not part of
# `cargo test`: cargo test covers units, supermassive covers the
# binary a user actually runs.

set -Eeuo pipefail

SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
# The shared binary resolver (scripts/lib/zejtron-bin.sh): the same
# discovery law the build battery and the bench scale audit use.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/zejtron-bin.sh"

usage() {
	sed -n '2,41p' "$SUITE_DIR/supermassive.sh" | sed 's/^# \{0,1\}//'
	exit "${1:-0}"
}

# ---------------------------------------------------------------------------
# Argument parsing.
# ---------------------------------------------------------------------------

LEG=""
BIN=""
SURFACE_FILTER=""
QUIET=0

while [[ $# -gt 0 ]]; do
	case "$1" in
	--leg)
		LEG="${2:-}"
		shift 2
		;;
	--bin)
		BIN="${2:-}"
		shift 2
		;;
	--surfaces)
		SURFACE_FILTER="${2:-}"
		shift 2
		;;
	--keep-scratch)
		SM_KEEP_SCRATCH=1
		shift
		;;
	--quiet | -q)
		QUIET=1
		shift
		;;
	--self-test)
		# Resolved dynamically from BASH_SOURCE; the 1d source-resolution
		# gate verifies the target exists, fail-closed.
		# shellcheck disable=SC1091
		source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/selftest.sh"
		exit $?
		;;
	--help | -h)
		usage 0
		;;
	*)
		echo "error: unknown option: $1 (see --help)" >&2
		exit 2
		;;
	esac
done

case "$LEG" in
low)
	# The low-spec contract: 2 vCPU / 4 GiB class host, 60s wall.
	# Per-test timeout 20s: every zejtron invocation is a fast procfs
	# read; the one slow documented flag (--check-update) carries a
	# 15s in-binary curl ceiling, so 20s is the honest per-test floor.
	SM_WALL_BUDGET=60
	SM_TEST_TIMEOUT=20
	;;
best)
	# The best-spec contract: same depth, 300s wall. Best is faster,
	# never deeper.
	SM_WALL_BUDGET=300
	SM_TEST_TIMEOUT=30
	;;
"")
	echo "error: --leg low|best is required (see --help)" >&2
	exit 2
	;;
*)
	echo "error: unknown leg '$LEG' (want: low|best)" >&2
	exit 2
	;;
esac

# ---------------------------------------------------------------------------
# Binary resolution. The suite exercises the REAL compiled binary; if
# it is missing, that is an honest hard error with a build hint, not
# a skip. The resolver (scripts/lib/zejtron-bin.sh) honors --bin and
# $ZEJTRON_BIN_PATH as authoritative, then discovers the binary under
# the repo target/ tree: the custom cargo profile dirs first (the
# alias lanes this repo builds through, e.g.
# target/pro-linux-amd64-v3-musl/zejtron or
# target/x86_64-unknown-linux-musl/pro-linux-amd64-v3-musl/zejtron),
# the basic release/debug lanes last.
# ---------------------------------------------------------------------------

if [[ -z "$BIN" ]]; then
	zejtron_resolve_bin BIN "$SUITE_DIR/../.."
fi
if [[ -z "$BIN" ]]; then
	echo "error: no zejtron binary found (searched the repo target/ tree: custom cargo profile dirs, then release/debug)" >&2
	echo "hint: build it first (cargo build --release --locked or a cargo profile lane), or pass --bin / ZEJTRON_BIN_PATH" >&2
	exit 2
fi
if [[ ! -x "$BIN" ]]; then
	echo "error: binary not found or not executable: $BIN" >&2
	echo "hint: pass an executable --bin / ZEJTRON_BIN_PATH, or build it first (cargo build --release --locked or a cargo profile lane)" >&2
	exit 2
fi

# The typed JSON law (night-dragon-4): jq is a HARNESS dependency.
# The binary stays jq-free (owner law), but the suite's JSON
# assertions are typed through jq, and a missing jq would silently
# gut the depth the whole suite exists to prove. The honest move is
# the hard error at startup, named, with the escape hatch given.
if ! command -v jq >/dev/null 2>&1; then
	echo "error: jq is not on PATH - the typed JSON law (night-dragon-4) needs it on the harness side (the binary itself stays jq-free)" >&2
	echo "hint: install the distribution jq package, or run the binary-only battery: scripts/build.sh battery" >&2
	exit 2
fi
# There is NO dormant build to hand over: the eBPF support is
# unconditional by owner law (Cargo.toml, night-weekly-maintenance-1,
# the "always enable, permanent" law - aya is a plain dependency and
# no build flag can produce a dormant binary). The lane surfaces
# verify the honest unavailability rendering instead (the doctor's
# [eBPF] Feature/Lane lines, the honest no-fake-observed-rows rule in
# snapshot mode) - see the lane-honesty checks in the surface files
# and the README's dormant-build section.
export SM_DEFAULT_BIN="$BIN"
# The child env allowlist PATH (sm_run wipes the environment; this is
# what the binary's subprocesses may resolve).
export SM_BIN_PATH_ENV="$PATH"
# Tree anchors the surface files read live (the version pin reads the
# manifest; the why fixture pins a file every checkout has).
export SUITE_README="$SUITE_DIR/../../README.md"
export SUITE_CARGO_TOML="$SUITE_DIR/../../Cargo.toml"

# ---------------------------------------------------------------------------
# Lane normalization. The pins (/sys/fs/bpf/zejtron) outlive every process
# that made them: a crashed prior run, a manual `doctor --attach`, or a
# session left by an OLDER binary build would silently put every ledger
# lane (holds/touch/why) live for this whole run - and the live lane sleeps
# the full window width per call (src/commands/lane.rs, capture_file_window:
# "std sleep, no reader thread"), so the suite's wall becomes a ledger of
# 10s collects (the night-dragon-3 post-mortem: 49 failures, 187s wall, a
# stale pin session riding every lane live). The suite owns its lane state:
# leftover pins are detached HERE, named, and every surface that needs the
# live lane attaches (and detaches) itself. The detach is idempotent on a
# clean host (rc 0, the doctor's own contract).
# ---------------------------------------------------------------------------

if [[ -e /sys/fs/bpf/zejtron ]]; then
	"$SM_DEFAULT_BIN" doctor --detach >/dev/null 2>&1 || true
	printf 'note: a leftover probe session was detached at startup - stale pins would ride every ledger lane live\n'
fi

# ---------------------------------------------------------------------------
# The surface manifest (explicit order, never a glob).
# ---------------------------------------------------------------------------

ALL_SURFACES=(path recent port proc holds touch why net doctor doctor-ram
	doctor-cpu doctor-disk doctor-network doctor-gpu help version storm
	simulation)

# The documented-flag manifest. Every documented flag of every
# surface; the runner reports any flag no surface exercised as
# UNTESTED by name (the honest gap report).
FLAG_MANIFEST=(
	"--help" "-h" "--version" "-V" "--check-update"
	"path --print-json" "recent --print-json" "port --print-json"
	"proc --print-json" "holds --print-json" "touch --print-json"
	"why --print-json" "doctor --print-json" "net --print-json"
	"recent --limit" "recent --since"
	"port --tcp" "port --udp" "port --listen" "port --all" "port --numeric"
	"port --group" "port --no-pid" "port --since" "port --events-only" "port --snapshot-only"
	"proc --me" "proc --depth" "proc --find" "proc --no-pid" "proc --no-color"
	"holds --since"
	"touch --since"
	"why --since" "why --trace" "why --raw"
	"doctor --attach" "doctor --detach" "doctor --symptom" "doctor --raw"
)

# ---------------------------------------------------------------------------
# Run.
# ---------------------------------------------------------------------------

sm_init
# Run-level state dir: outlives the per-surface scratch dirs (the
# flag registry lives here). The runner owns its cleanup.
SM_RUN_TMP="$(mktemp -d "${TMPDIR:-/tmp}/supermassive-run.XXXXXX")"
# The promised cleanup, enforced (night-total-lts-2): the comment
# said the runner owns it, no rm existed - a mid-surface set -e
# abort leaked the whole run dir. The EXIT trap owns it now.
trap 'rm -rf "${SM_RUN_TMP}"' EXIT
sm_flags_init
WALL_START=$SECONDS

# The full surface list, or the debug filter, mapped to file paths.
run_surfaces=()
if [[ -n "$SURFACE_FILTER" ]]; then
	IFS=',' read -r -a requested <<<"$SURFACE_FILTER"
	for want in "${requested[@]}"; do
		found=""
		for s in "${ALL_SURFACES[@]}"; do
			[[ "$s" == "$want" ]] && found="$s"
		done
		if [[ -z "$found" ]]; then
			echo "error: unknown surface '$want' (want one of: ${ALL_SURFACES[*]})" >&2
			exit 2
		fi
		run_surfaces+=("$found")
	done
else
	run_surfaces=("${ALL_SURFACES[@]}")
fi

printf 'supermassive: leg=%s bin=%s\n' "$LEG" "$BIN"
printf 'note: no dormant shape exists (owner law, Cargo.toml) - the lane-honesty checks cover the unavailability rendering\n'

# Every surface file is sourced up front, each through the literal
# cd/pwd idiom the commit gate's fail-closed 1d translator resolves -
# a missing surface file fails the run at startup, before a single
# check executes. The loop below only CALLS them, in the manifest's
# order.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/surfaces/path.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/surfaces/recent.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/surfaces/port.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/surfaces/proc.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/surfaces/holds.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/surfaces/touch.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/surfaces/why.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/surfaces/net.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/surfaces/doctor.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/surfaces/doctor-ram.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/surfaces/doctor-cpu.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/surfaces/doctor-disk.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/surfaces/doctor-network.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/surfaces/doctor-gpu.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/surfaces/help.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/surfaces/version.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/surfaces/storm.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/surfaces/simulation.sh"

for surface in "${run_surfaces[@]}"; do
	sm_surface_begin "$surface"
	"surface_${surface//-/_}"
	sm_surface_end
done

WALL_ELAPSED=$((SECONDS - WALL_START))

# ---------------------------------------------------------------------------
# The honest gap report: any manifest flag no surface recorded.
# ---------------------------------------------------------------------------

untested=()
for flag in "${FLAG_MANIFEST[@]}"; do
	# The "--" separator is load-bearing: manifest entries ARE flag
	# spellings (-h, -V, --help...), and without the separator grep
	# parses them as its own options - "-h" turns the registry file
	# into the pattern and grep blocks reading stdin. The same
	# dash-needle class scripts/build.sh warns about, bitten and
	# fixed here in earnest.
	if ! grep -qxF -- "$flag" "$SM_FLAGS_USED_FILE" 2>/dev/null; then
		untested+=("$flag")
	fi
done
if [[ ${#untested[@]} -gt 0 ]]; then
	printf '\nUNTESTED FLAGS (%d - named, never silently skipped):\n' "${#untested[@]}"
	for flag in "${untested[@]}"; do
		printf '  - %s\n' "$flag"
	done
else
	printf '\nUNTESTED FLAGS: none - the documented flag estate is covered\n'
fi

# ---------------------------------------------------------------------------
# The verdict. Exit 0 = all passed or skipped-with-reason; exit 1 =
# any failure. The wall budget is part of the leg's contract: over
# budget is a failed leg even when every check passed.
# ---------------------------------------------------------------------------

printf '\n== verdict ==\n'
printf 'pass: %d  fail: %d  skip: %d\n' "$SM_PASS" "$SM_FAIL" "$SM_SKIP"
printf 'wall: %ds / budget: %ds (leg: %s)\n' "$WALL_ELAPSED" "$SM_WALL_BUDGET" "$LEG"

if [[ -n "$SM_SKIP_REASONS" ]]; then
	printf 'skips (each names its reason):\n%s' "$SM_SKIP_REASONS"
fi

exit_code=0
if [[ "$SM_FAIL" -gt 0 ]]; then
	printf 'FAILURES:\n%s' "$SM_FAILURES"
	exit_code=1
fi
if [[ "$WALL_ELAPSED" -gt "$SM_WALL_BUDGET" ]]; then
	printf 'WALL BUDGET BREACHED: %ds > %ds - the %s leg failed its own contract\n' \
		"$WALL_ELAPSED" "$SM_WALL_BUDGET" "$LEG"
	exit_code=1
fi

if [[ "$exit_code" -eq 0 ]]; then
	printf 'supermassive verdict: PASS (every surface tested or honestly skipped)\n'
else
	printf 'supermassive verdict: FAIL\n'
fi
exit "$exit_code"
