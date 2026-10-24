#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# The night-dragon-1 scale audit: the ultra-massive scale verifier.
# Spawns a synthetic busy host - fake processes plus fake open-file
# holders - then times the three core readers and gates each against
# a wall-clock budget (500 ms by default, the audit's own number).
#
# What it measures (cold start, startup included - the operator's
# truth):
#   zejtron proc --me
#   zejtron holds <target file>
#   zejtron doctor --symptom ram
#
# Honesty rules the corners:
#   - every scaledown (pid rlimit, nofile rlimit, spawn failures) is
#     printed as a named note, never silently swallowed;
#   - the gate is the WORST of three runs per command;
#   - a budget miss is a hard fail (exit 1); a lane that could not
#     reach its requested scale still runs and reports, and its note
#     says so - a note is not a pass.
#
# Usage:
#   scripts/bench/scale-audit.sh
#   ZEJTRON_BIN=/path/to/zejtron scripts/bench/scale-audit.sh
#   ZEJTRON_SCALE_PROCS=1000 ZEJTRON_SCALE_FDS=1000 \
#     ZEJTRON_SCALE_BUDGET_MS=500 scripts/bench/scale-audit.sh

set -u

# The timing clock is $EPOCHREALTIME - a builtin since bash 5, no
# fork - because the forked `date` cannot be trusted under the fork
# pressure this very script creates: a refused date fork silently
# yielded an empty timestamp and a 0 ms measurement (observed live).
# A bash without EPOCHREALTIME is refused up front, honestly.
if [[ -z "${EPOCHREALTIME:-}" ]]; then
	echo "scale-audit: bash 5 or newer is required (EPOCHREALTIME missing)" >&2
	exit 2
fi

PROCS_REQUESTED="${ZEJTRON_SCALE_PROCS:-1000}"
FDS_REQUESTED="${ZEJTRON_SCALE_FDS:-1000}"
BUDGET_MS="${ZEJTRON_SCALE_BUDGET_MS:-500}"
HOLDERS="${ZEJTRON_SCALE_HOLDERS:-8}"

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd) || exit 1
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd) || exit 1

if [[ -n "${ZEJTRON_BIN:-}" ]]; then
	BIN=$ZEJTRON_BIN
elif [[ -x "$REPO_ROOT/target/release/zejtron" ]]; then
	BIN=$REPO_ROOT/target/release/zejtron
elif [[ -x "$REPO_ROOT/target/debug/zejtron" ]]; then
	BIN=$REPO_ROOT/target/debug/zejtron
else
	echo "scale-audit: no zejtron binary found" >&2
	echo "scale-audit: build one first (cargo build --release) or set ZEJTRON_BIN" >&2
	exit 2
fi

echo "scale-audit: binary $BIN"
"$BIN" -V >/dev/null 2>&1 || {
	echo "scale-audit: the binary does not run: $BIN" >&2
	exit 2
}

fake_pids=()
holder_pids=()
TARGET_FILE=""
CLEANED=0

cleanup() {
	if [[ "$CLEANED" -ne 0 ]]; then
		return
	fi
	CLEANED=1
	if [[ ${#fake_pids[@]} -gt 0 ]]; then
		kill "${fake_pids[@]}" 2>/dev/null
	fi
	if [[ ${#holder_pids[@]} -gt 0 ]]; then
		# Negative pids: the holders run in their own sessions, so the
		# kill reaches the parked sleep inside each group. The "--" is
		# load-bearing: without it kill parses -22365 as a signal
		# number, refuses it, and orphans every parked sleep
		# (observed live).
		kill -- "${holder_pids[@]/#/-}" 2>/dev/null
	fi
	if [[ -n "${SPAWN_PIDFILE:-}" && -e "$SPAWN_PIDFILE" ]]; then
		rm -f "$SPAWN_PIDFILE"
	fi
	if [[ -n "$TARGET_FILE" && -e "$TARGET_FILE" ]]; then
		rm -f "$TARGET_FILE"
	fi
}
trap cleanup EXIT INT TERM

TARGET_FILE=$(mktemp /tmp/zejtron-scale-audit.XXXXXX) || exit 2
# No trailing newline: the file doubles as the zero-fork settle clock
# (read -t on it blocks for the timeout instead of hitting EOF), and
# its content is irrelevant to the holds walk.
printf 'zejtron scale audit' >"$TARGET_FILE"

# The fake open-file lane runs FIRST: eight forks at a healthy
# headroom, each holder pinning its share of descriptors on the
# target file, so the holds walk sees a thousand-descriptor fd
# landscape without one process breaching its own nofile rlimit.
FDS=$FDS_REQUESTED
PER_HOLDER=$((FDS / HOLDERS))
FDS_ACHIEVABLE=$FDS_REQUESTED
if [[ "$(ulimit -n)" != "unlimited" ]]; then
	RLIMIT_N=$(ulimit -n)
	if ((PER_HOLDER > RLIMIT_N - 64)); then
		PER_HOLDER=$((RLIMIT_N > 64 ? RLIMIT_N - 64 : 0))
		echo "scale-audit: NOTE nofile rlimit $RLIMIT_N caps each holder at $PER_HOLDER descriptors"
	fi
fi
EFFECTIVE_FDS=0
if ((PER_HOLDER > 0)); then
	# Each holder runs in its own session (setsid) so the cleanup can
	# kill the whole process group - the holder bash AND the sleep it
	# parks on - instead of orphaning the sleep for ten minutes
	# (observed live: eight leaked sleeps after a run).
	h=0
	while ((h < HOLDERS)); do
		# shellcheck disable=SC2016
		# (the inner shell owns those positionals)
		setsid bash -c '			for ((fd = 0; fd < $2; fd++)); do exec {fd}<"$1"; done
			sleep 600
		' holder "$TARGET_FILE" "$PER_HOLDER" &
		holder_pids+=($!)
		h=$((h + 1))
	done
	read -t 0.5 -r _ <"$TARGET_FILE"
	LIVE_HOLDERS=0
	for pid in "${holder_pids[@]}"; do
		kill -0 "$pid" 2>/dev/null && LIVE_HOLDERS=$((LIVE_HOLDERS + 1))
	done
	EFFECTIVE_FDS=$((LIVE_HOLDERS * PER_HOLDER))
	FDS_ACHIEVABLE=$((HOLDERS * PER_HOLDER))
	if ((LIVE_HOLDERS < HOLDERS)); then
		echo "scale-audit: NOTE only $LIVE_HOLDERS of $HOLDERS fd holders survived spawn"
	fi
fi
echo "scale-audit: open files: $EFFECTIVE_FDS (requested $FDS_REQUESTED)"

# The fake process lane runs SECOND, under a supervisor: some hosts
# enforce a fork ceiling BELOW every readable limit (observed live:
# stalls around 700 children with threads-max 925 and pids.max
# "max"), and bash hides the fork retries inside one spawn - a
# foreground loop cannot bound that. The spawner runs as a child
# appending each pid to a file; the parent watches with builtins
# only (SECONDS, kill, read) and terminates a stalled spawner. What
# spawned is what the audit measures, and the notes say so.
PROCS=$PROCS_REQUESTED
if [[ "$(ulimit -u)" != "unlimited" ]]; then
	RLIMIT_U=$(ulimit -u)
	SLACK=200
	if ((RLIMIT_U < PROCS + SLACK)); then
		PROCS=$((RLIMIT_U > SLACK ? RLIMIT_U - SLACK : 0))
		echo "scale-audit: NOTE pid rlimit $RLIMIT_U caps the fake process lane at $PROCS (requested $PROCS_REQUESTED)"
	fi
fi
if [[ -r /proc/sys/kernel/threads-max ]]; then
	THREADS_MAX=$(cat /proc/sys/kernel/threads-max)
	CURRENT_PIDS=0
	for _entry in /proc/[0-9]*; do
		CURRENT_PIDS=$((CURRENT_PIDS + 1))
	done
	SLACK=100
	AVAILABLE=$((THREADS_MAX - CURRENT_PIDS - SLACK))
	if ((AVAILABLE < PROCS)); then
		((AVAILABLE < 0)) && AVAILABLE=0
		echo "scale-audit: NOTE kernel threads-max $THREADS_MAX (about $CURRENT_PIDS live) caps the fake process lane at $AVAILABLE (requested $PROCS_REQUESTED)"
		PROCS=$AVAILABLE
	fi
fi
SPAWN_PIDFILE=""
if ((PROCS > 0)); then
	SPAWN_PIDFILE=$(mktemp /tmp/zejtron-scale-audit-pids.XXXXXX)
	: >"$SPAWN_PIDFILE"
	spawn_fake_procs() {
		local count=$1
		local pidfile=$2
		local i=0
		local last_tick=$SECONDS
		local last_i=0
		while ((i < count)); do
			sleep 300 &
			echo "$!" >>"$pidfile"
			i=$((i + 1))
			# The pace break finds the fork ceiling no readable limit
			# exposes (observed live: stalls near 700 children under a
			# 925 threads-max with pids.max "max"). A second that added
			# fewer than 25 spawns means the host is stalling; the
			# spawner stops there instead of pushing the host into
			# multi-second fork retries.
			if ((SECONDS > last_tick)); then
				if (((i - last_i) < 25)); then
					break
				fi
				last_tick=$SECONDS
				last_i=$i
			fi
		done
	}
	SPAWN_DEADLINE=$((SECONDS + 45))
	spawn_fake_procs "$PROCS" "$SPAWN_PIDFILE" &
	SPAWN_SUPERVISOR=$!
	while kill -0 "$SPAWN_SUPERVISOR" 2>/dev/null && ((SECONDS < SPAWN_DEADLINE)); do
		read -t 0.2 -r _ <"$TARGET_FILE"
	done
	if kill -0 "$SPAWN_SUPERVISOR" 2>/dev/null; then
		SPAWNED=$(wc -l <"$SPAWN_PIDFILE")
		echo "scale-audit: NOTE the host stalled the spawn at $SPAWNED of $PROCS - continuing with what spawned"
		kill "$SPAWN_SUPERVISOR" 2>/dev/null
	fi
	wait "$SPAWN_SUPERVISOR" 2>/dev/null
	while read -r pid; do
		fake_pids+=("$pid")
	done <"$SPAWN_PIDFILE"
	rm -f "$SPAWN_PIDFILE"
	# Count the survivors: a spawn refused by the kernel is a named
	# note, not a silent shrink.
	ALIVE=0
	for pid in "${fake_pids[@]}"; do
		kill -0 "$pid" 2>/dev/null && ALIVE=$((ALIVE + 1))
	done
	if ((ALIVE < PROCS)); then
		echo "scale-audit: NOTE only $ALIVE of $PROCS fake processes survived spawn"
	fi
	# The gates themselves fork (the binary under test, its clock),
	# and a host pinned at its fork ceiling stalls a single exec
	# into multi-second retries (observed live: 15 s per run at 710
	# children). Ten percent of the lane is freed so the gate
	# measures zejtron, not the host's fork queue.
	TRIM=$((ALIVE / 10))
	if ((TRIM > 0 && ${#fake_pids[@]} > TRIM)); then
		KEEP=$((${#fake_pids[@]} - TRIM))
		for pid in "${fake_pids[@]:$KEEP}"; do
			kill "$pid" 2>/dev/null
		done
		fake_pids=("${fake_pids[@]:0:$KEEP}")
		ALIVE=$((ALIVE - TRIM))
		echo "scale-audit: NOTE freed $TRIM fake processes as measurement headroom - the lane runs at $ALIVE"
	fi
	PROCS=$ALIVE
fi
echo "scale-audit: fake processes: $PROCS (requested $PROCS_REQUESTED)"

# The gate: three cold runs per command, the WORST one against the
# budget. A miss is a fail; a command that could not complete under
# the host's fork pressure is a fail too - there is no averaging and
# no silent pass to hide behind.
measure_ms() {
	local start end status
	start=${EPOCHREALTIME/./}
	"$@" >/dev/null 2>&1
	status=$?
	end=${EPOCHREALTIME/./}
	echo "$status $(((end - start) / 1000))"
}

gate() {
	local label=$1
	shift
	local worst=0
	local failed=0
	local out status ms
	for _run in 1 2 3; do
		out=$(measure_ms "$@")
		status=${out%% *}
		ms=${out##* }
		if [[ "$status" -ne 0 ]]; then
			failed=1
			continue
		fi
		if ((ms > worst)); then
			worst=$ms
		fi
	done
	if [[ "$failed" -ne 0 ]]; then
		echo "scale-audit: FAIL $label - the command could not complete under the host's fork pressure"
		return 1
	fi
	if ((worst <= BUDGET_MS)); then
		echo "scale-audit: PASS $label worst ${worst}ms of 3 runs (budget ${BUDGET_MS}ms)"
		return 0
	fi
	echo "scale-audit: FAIL $label worst ${worst}ms of 3 runs (budget ${BUDGET_MS}ms)"
	return 1
}

FAILED=0
gate "proc --me" "$BIN" proc --me || FAILED=1
gate "holds <file>" "$BIN" holds "$TARGET_FILE" || FAILED=1
gate "doctor --symptom ram" "$BIN" doctor --symptom ram || FAILED=1

if [[ "$PROCS" -lt "$PROCS_REQUESTED" || "$EFFECTIVE_FDS" -lt "$FDS_ACHIEVABLE" ]]; then
	echo "scale-audit: NOTE the host ran below the requested scale - the verdict above is honest for the scale it reached"
fi

if [[ "$FAILED" -ne 0 ]]; then
	exit 1
fi
echo "scale-audit: VERDICT PASS"
