# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_storm.sh — the realtime storm surface (night-improve-51:
# the owner's ask — the E2E depth needs a REALTIME leg: concurrent
# writers hammering the filesystem while the binary answers, the
# verdicts asserted under load, never after it).
#
# Depth: four concurrent churn writers run a fixed six-second
# window of plain write(2) appends (the same writes real tools
# make — no perl, no syscall tricks) while the poller asks `why`
# about the hot files mid-storm. The tap lane must show the churn
# [observed] WHILE it happens (the realtime claim, never an
# after-the-fact reconstruction), with the ledger's `wrote` rows
# and the raw lane's op=write records; the snapshot lane must
# show the honest mode line and no fake [observed] rows under the
# same load (the no-fabrication law, live under concurrency — a
# stronger seat than the idle-host version); the missing-path
# error path must refuse by name WHILE the storm runs; and the
# surface ends clean by its own hand (the attach it made, the
# detach that unpins it, the pin directory gone). Exercised
# flags: why --since, why --raw, doctor --attach, doctor
# --detach (the registry rows those flags own are the why and
# doctor surfaces' — the storm exercises them under load).

surface_storm() {
	local rc
	local storm_dir="$SM_SCRATCH/storm"
	local dur=6
	local hot1="$storm_dir/w-1.txt"
	local hot2="$storm_dir/w-2.txt"
	local -a pids=()
	local i

	mkdir -p "$storm_dir"
	: >"$hot1"
	: >"$hot2"

	# The lane probe: the attach attempt itself (the doctor's own
	# preflight, the why surface's writev-proof precedent). rc 0 =
	# the tap lane; anything else = the snapshot lane, and the
	# refusal direction stays the doctor surface's own contract.
	sm_run "$SM_SCRATCH/st-attach.out" "$SM_SCRATCH/st-attach.err" rc 20 -- \
		"$SM_DEFAULT_BIN" doctor --attach
	local tap_lane=0
	if [[ "$rc" -eq 0 ]]; then
		tap_lane=1
		sm_pass "storm: the tap attaches on this host (the tap lane runs)"
	else
		sm_pass "storm: the snapshot lane runs the storm honestly (attach refused)"
	fi

	# One churn writer: plain appends into its own file for a
	# fixed window, its op count landing in a sidecar file. The
	# write tap's own lane (vfs_write) — four of these run
	# concurrently for the storm's whole window.
	storm_writer() {
		local dir="$1" id="$2" secs="$3" count=0
		local f="$dir/w-$id.txt"
		local end=$((SECONDS + secs))
		: >"$f"
		while ((SECONDS < end)); do
			printf 'zejtron-storm-w%s-%s\n' "$id" "$count" >>"$f"
			count=$((count + 1))
		done
		printf '%s\n' "$count" >"$dir/w-$id.count"
	}
	for ((i = 1; i <= 4; i++)); do
		storm_writer "$storm_dir" "$i" "$dur" &
		pids+=("$!")
	done

	# Poll A: the realtime claim's seat — the render is produced
	# while the writers are still crossing the window.
	sm_run "$SM_SCRATCH/st-pollA.out" "$SM_SCRATCH/st-pollA.err" rc 10 -- \
		"$SM_DEFAULT_BIN" why "$hot1" --since 2s --raw
	sm_assert_rc 0 "$rc" "storm: poll A (why --since 2s --raw) exits 0 mid-storm"

	# The error path, concurrently: a missing target refuses by
	# name while the writers hammer the same directory tree.
	sm_run "$SM_SCRATCH/st-miss.out" "$SM_SCRATCH/st-miss.err" rc 5 -- \
		"$SM_DEFAULT_BIN" why "$storm_dir/no-such-target"
	sm_assert_rc 1 "$rc" "storm: why <missing> exits 1 while the storm runs"
	if grep -q "path not found" "$SM_SCRATCH/st-miss.out" "$SM_SCRATCH/st-miss.err" 2>/dev/null; then
		sm_pass "storm: why <missing> names the missing path under load"
	else
		sm_fail "storm: why <missing> names the missing path under load" \
			"neither stream mentioned 'path not found'"
	fi

	# Poll B: a second hot file, a second mid-storm window.
	sm_run "$SM_SCRATCH/st-pollB.out" "$SM_SCRATCH/st-pollB.err" rc 10 -- \
		"$SM_DEFAULT_BIN" why "$hot2" --since 2s --raw
	sm_assert_rc 0 "$rc" "storm: poll B (why --since 2s --raw) exits 0 mid-storm"

	# The writers land on their own six-second bound; every one of
	# them must have churned at least once.
	for pid in "${pids[@]}"; do
		wait "$pid"
	done
	for ((i = 1; i <= 4; i++)); do
		local n
		n="$(cat "$storm_dir/w-$i.count" 2>/dev/null || echo 0)"
		if [[ "$n" -gt 0 ]]; then
			sm_pass "storm: writer $i churned under load (ops > 0)"
		else
			sm_fail "storm: writer $i churned under load (ops > 0)" \
				"writer $i wrote nothing (count file says '$n')"
		fi
	done

	# The lane-conditional verdicts, asserted on the mid-storm
	# renders themselves.
	if [[ "$tap_lane" -eq 1 ]]; then
		local saw_observed=0
		for poll in st-pollA st-pollB; do
			sm_assert_contains "$SM_SCRATCH/$poll.out" "Mode: live" \
				"storm: $poll declares the live lane mid-storm"
			if grep -q "\[observed\]" "$SM_SCRATCH/$poll.out" 2>/dev/null; then
				saw_observed=1
			fi
		done
		if [[ "$saw_observed" -eq 1 ]]; then
			sm_pass "storm: the churn is [observed] while it happens (the realtime claim)"
		else
			sm_fail "storm: the churn is [observed] while it happens (the realtime claim)" \
				"no [observed] row in either mid-storm render"
		fi
		local saw_wrote=0 saw_raw=0
		for poll in st-pollA st-pollB; do
			if grep -q "wrote" "$SM_SCRATCH/$poll.out" 2>/dev/null; then
				saw_wrote=1
			fi
			if grep -q "op=write" "$SM_SCRATCH/$poll.out" 2>/dev/null; then
				saw_raw=1
			fi
		done
		if [[ "$saw_wrote" -eq 1 ]]; then
			sm_pass "storm: the ledger names the writes (wrote rows)"
		else
			# The post-mortem (the named-never-swallowed law): a tap
			# whose write lane is silent on a whole kernel generation
			# must name ITSELF. The failure detail carries the rows
			# the renders actually did see, and - where tracefs is
			# writable (root inside the witness VMs) - the ftrace
			# probe counts for one controlled write, so a kernel that
			# rerouted its write path says so in the log instead of
			# hiding behind a bare FAIL.
			local seen_rows trace_root wcount="NA" wvcount="NA"
			seen_rows="$(grep -h -m6 "\[observed\]" \
				"$SM_SCRATCH/st-pollA.out" "$SM_SCRATCH/st-pollB.out" 2>/dev/null |
				tr '\n' ';' || true)"
			trace_root="/sys/kernel/tracing"
			[[ -d "$trace_root" ]] || trace_root="/sys/kernel/debug/tracing"
			if [[ -d "$trace_root" && -w "$trace_root/kprobe_events" ]] &&
				echo 'p:zjw vfs_write' >>"$trace_root/kprobe_events" 2>/dev/null &&
				echo 'p:zjwv vfs_writev' >>"$trace_root/kprobe_events" 2>/dev/null &&
				[[ -d "$trace_root/events/kprobes/zjw" ]]; then
				echo 1 >"$trace_root/events/kprobes/zjw/enable" 2>/dev/null || true
				echo 1 >"$trace_root/events/kprobes/zjwv/enable" 2>/dev/null || true
				: >"$trace_root/trace" 2>/dev/null || true
				printf 'zejtron-storm-postmortem\n' >>"$hot1"
				wcount="$(grep -c 'zjw:' "$trace_root/trace" 2>/dev/null || true)"
				wvcount="$(grep -c 'zjwv:' "$trace_root/trace" 2>/dev/null || true)"
				echo >"$trace_root/kprobe_events" 2>/dev/null || true
			fi
			sm_fail "storm: the ledger names the writes (wrote rows)" \
				"no wrote row in either mid-storm render; observed rows: ${seen_rows:-none}; ftrace on one controlled write: vfs_write=${wcount} vfs_writev=${wvcount} (tracefs root: $trace_root)"
		fi
		if [[ "$saw_raw" -eq 1 ]]; then
			sm_pass "storm: the raw lane names op=write records"
		else
			sm_fail "storm: the raw lane names op=write records" \
				"no op=write record in either mid-storm render (post-mortem above)"
		fi
		# The surface ends clean by its own hand: the detach that
		# unpins the tap it attached, then the pin directory gone.
		sm_run "$SM_SCRATCH/st-detach.out" "$SM_SCRATCH/st-detach.err" rc 20 -- \
			"$SM_DEFAULT_BIN" doctor --detach
		sm_assert_rc 0 "$rc" "storm: doctor --detach ends the storm clean (exit 0)"
		if [[ -e /sys/fs/bpf/zejtron ]]; then
			sm_fail "storm: detach removes the pin directory" \
				"/sys/fs/bpf/zejtron still exists after detach"
		else
			sm_pass "storm: detach removes the pin directory"
		fi
	else
		for poll in st-pollA st-pollB; do
			sm_assert_contains "$SM_SCRATCH/$poll.out" "Mode: snapshot" \
				"storm: $poll declares the snapshot lane honestly"
			sm_assert_not_contains "$SM_SCRATCH/$poll.out" "\[observed\]" \
				"storm: $poll renders no fake [observed] rows under load"
		done
		# The idempotent detach on the clean host (the doctor
		# surface's own snapshot-branch law, re-pinned after a
		# storm ran over it).
		sm_run "$SM_SCRATCH/st-detach.out" "$SM_SCRATCH/st-detach.err" rc 5 -- \
			"$SM_DEFAULT_BIN" doctor --detach
		sm_assert_rc 0 "$rc" "storm: doctor --detach stays idempotent after the storm"
	fi

	# The aftermath: the same render, twice, on a file a storm just
	# hammered — normalized byte-equal (the atime the read itself
	# moves), then the color tri-test on the same invocation.
	sm_deterministic "storm aftermath: why determinism" 5 -- \
		"$SM_DEFAULT_BIN" why "$hot1"
	SM_TRITEST_NORMALIZE=1 sm_color_tritest "storm aftermath why" 5 -- \
		"$SM_DEFAULT_BIN" why "$hot1"
}
