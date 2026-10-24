# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_simulation.sh — the server incident simulation, upgraded to
# the brutal inferno (night-dragon-2: the owner's ask — night-badass-8's
# one-rogue scenario is too gentle for the ultra-massive-scale claim;
# the detective must survive a whole-host inferno and still report it
# accurately, on the JSON lane the automation contract pins).
#
# The scenario: a full host under fire, staged by the surface itself.
#
#   The chaos spawner (every actor self-bounded — a wedged harness
#   cannot leak an unbounded consumer):
#   - 500 dummy processes (sleep 300 &).
#   - four rogue python3 processes, each binding a port from the
#     deterministic table 20000/20017/20033/20050 (the :20050 pin is
#     the night-dragon-2 contract; randomness cannot be asserted),
#     allocating 200 MiB, and accepting/closing localhost connections.
#     The fleet holds ~880 MiB by construction - under the task's
#     1 GiB python cap - and 4 x 200 MiB is what cracks a busy host's
#     top-10 RAM table (10 MiB rogues drown among the desktop's own
#     consumers, the night-dragon-3 finding); each rogue carries a
#     1 GiB RLIMIT_AS ceiling (the runaway backstop - virtual, not
#     resident); the staging preflight demands 2 GiB MemAvailable
#     before anything spawns (the runner cannot be OOMed by this
#     surface).
#   - one holder subshell keeping 1000 read descriptors open on a
#     scratch file (fd numbers 10-1009 — under a 1024 soft ceiling
#     by construction, no ulimit surgery needed).
#   - a dd I/O burst: 100 MiB (bs=1M count=100) into a scratch file,
#     written by ONE dd process that reads STDIN fed by a fork-free
#     feeder (the printf builtin, 1 MiB every 0.2s, self-bounded 30s).
#     The night-dragon-3 post-mortem: the old feeder piped into
#     `dd if=/dev/zero`, which ignores stdin entirely - the pacing
#     never paced, dd finished inside a second, and the live lane's
#     why render found a cold trail. dd reads the pipe now: the
#     writer stays alive across the whole assertion window (the live
#     lane resolves the actor from /proc at render time; an exited
#     writer reads as unaccounted by design), its tracked pid is
#     stable, and a fork-starved host cannot silence the burst.
#   - a socket storm: a bounded loop of localhost connects (open and
#     close against the rogues' listeners), counted into a sidecar.
#
#   The detection, under fire (the chaos runs through every assert):
#   - `proc --me --print-json` must finish in < 1 second (measured with
#     EPOCHREALTIME — bash 5's forkless clock; a forked `date` lies
#     under fork pressure, the night-dragon-1 lesson) and must capture
#     > 500 processes (the `"comm":` row count — one per process row;
#     no jq: the suite is bash + coreutils by design, and grep counts
#     the same rows the jq length would). The scan is --me: the inferno
#     runs under the suite's own uid, and a bare `proc` refuses to run
#     without a target (the CLI's own law).
#   - `port 20050 --print-json --snapshot-only` must name the pinned
#     rogue as the listener's owner (the port report's typed owner
#     rows, subject :20050; the snapshot lane resolves owners from
#     /proc and returns instantly - the window law, night-dragon-3:
#     the default 60s collect died as exit 124 under the assert's
#     timeout).
#   - `doctor --symptom ram --print-json` must name rogue pids among
#     the top consumers with PSS above the 100 MB bar (the rogues
#     hold 200 MiB each).
#   - `why <io file> --since 3s --print-json` must ride the live lane
#     (gated on the doctor --attach preflight; the refusal direction
#     is the storm surface's contract) and attribute the write to the
#     dd process by name and pid.
#
#   The teardown: TERM, a grace beat, KILL, a bare wait that reaps
#   every child, then a /proc sweep over every tracked pid — zero
#   zombies among our comms is a check, not a hope. The io file and
#   every report land in the per-surface scratch dir (the fixture
#   hygiene: the runner owns the cleanup — the task's /tmp lanes are
#   served by scratch, and a failed surface's evidence survives for
#   the post-mortem). The probe the surface attached, the surface
#   detaches.
#
# Host contracts: python3 and dd on the harness PATH (each absence a
# named SKIP — no dependency is added to the suite, which stays bash
# + coreutils); MemAvailable below the staging bar is a named SKIP; a
# bind conflict on the rogue ports (a developer box with real
# listeners) is a named SKIP; an fd ceiling below the storm is a
# named SKIP. Any other rogue death is a FAIL.
#
# The massive-scale report: the surface ends with one line carrying
# the real tallies (dummies, rogues, fds staged, socket connects, the
# measured proc latency under fire) — the CI log's massive-scale
# badge, computed from sidecars, never asserted from constants.

surface_simulation() {
	local rc
	local dummy_count=500
	local fd_target=1000 rogue_bar=104857600 proc_bar_ms=1000
	local rogue_pin_pid="" io_pid="" storm_pid="" holder_pid=""
	local probe_lane=0 alive=0 i port
	local -a rogue_ports=(20000 20017 20033 20050)
	local rogue_count=${#rogue_ports[@]}
	local pinned_port=${rogue_ports[rogue_count - 1]}
	local mem_avail_kb fd_opened storm_conns proc_rows proc_ms
	local pss_line pss_bytes rogues_named stat_line state comm
	local zombies residue pid
	local -a chaos_pids=() rogue_pids=()
	local t0 t1

	# ------------------------------------------------------------------
	# Host contracts first: every absence named, nothing staged halfway.
	# ------------------------------------------------------------------
	if ! command -v python3 >/dev/null 2>&1; then
		sm_skip "simulation: the inferno staging" \
			"python3 is not on the harness PATH (the rogues' runtime)"
		return 0
	fi
	if ! command -v dd >/dev/null 2>&1; then
		sm_skip "simulation: the inferno staging" \
			"dd is not on the harness PATH (the io burst's writer)"
		return 0
	fi
	mem_avail_kb="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
	if [[ ! "$mem_avail_kb" =~ ^[0-9]+$ ]] || ((mem_avail_kb < 2048000)); then
		sm_skip "simulation: the inferno staging" \
			"MemAvailable ${mem_avail_kb} kB is under the 2 GiB staging bar (the 1 GiB rogue fleet needs the headroom)"
		return 0
	fi

	# The lane probe: the attach attempt itself (the storm surface's
	# precedent), BEFORE the chaos spawns so the probe sees the
	# inferno from the first fork. rc 0 = the probe lane; anything
	# else = the snapshot lane, and the why assert skips with the
	# reason named (the refusal direction stays the doctor's).
	sm_run "$SM_SCRATCH/sim-attach.out" "$SM_SCRATCH/sim-attach.err" rc 20 -- \
		"$SM_DEFAULT_BIN" doctor --attach
	if [[ "$rc" -eq 0 ]]; then
		probe_lane=1
		sm_pass "simulation: the probe attaches before the inferno (the live lane will run)"
	else
		sm_pass "simulation: the snapshot lane will carry the inferno honestly (attach refused)"
	fi

	# The teardown hand: every exit path after the first spawn goes
	# through here — TERM the fleet, a grace beat, KILL the rest,
	# reap everything, sweep /proc for our zombies.
	inferno_teardown() {
		if ((${#chaos_pids[@]} > 0)); then
			kill "${chaos_pids[@]}" 2>/dev/null || true
		fi
		sleep 0.3
		if ((${#chaos_pids[@]} > 0)); then
			kill -9 "${chaos_pids[@]}" 2>/dev/null || true
		fi
		# The bare wait reaps every child the surface owns —
		# the dd feeder (the pipeline's untracked half) among
		# them — so no tracked pid can outlive this function
		# as a zombie.
		wait 2>/dev/null || true
		zombies=0
		residue=0
		local pid
		for pid in "${chaos_pids[@]}"; do
			# The stderr silence must precede the open: a killed
			# pid's /proc entry is GONE at sweep time (reaped,
			# the good outcome), and with the read's redirect
			# ordered <file first, the failed open shouts to the
			# original stderr - seventeen lines of noise under
			# the real run (the night-dragon-3 finding).
			if read -r stat_line 2>/dev/null <"/proc/$pid/stat"; then
				comm="${stat_line#*(}"
				comm="${comm%%)*}"
				state="${stat_line#*) }"
				state="${state%% *}"
				case "$comm" in
				sleep | python3 | dd | bash)
					if [[ "$state" == "Z" ]]; then
						zombies=$((zombies + 1))
					else
						residue=$((residue + 1))
					fi
					;;
				esac
			fi
		done
		if ((zombies > 0 || residue > 0)); then
			sm_fail "simulation: the inferno leaves no zombie or stray process" \
				"$zombies zombies, $residue strays among the tracked pids after the teardown"
		else
			sm_pass "simulation: the inferno leaves no zombie or stray process"
		fi
		rm -f "$SM_SCRATCH/io-test.bin"
	}

	# ------------------------------------------------------------------
	# The chaos spawner.
	# ------------------------------------------------------------------
	: >"$SM_SCRATCH/fd-pile.txt"
	: >"$SM_SCRATCH/io-test.bin"

	# The fd holder: 1000 read descriptors on the pile file, held
	# open by a bounded sleep, the staged count in a sidecar.
	(
		opened=0
		while ((opened < fd_target)); do
			# The auto-allocated descriptor number is the
			# mechanism, not a value the holder reads.
			# shellcheck disable=SC2034
			if exec {fd}<"$SM_SCRATCH/fd-pile.txt" 2>/dev/null; then
				opened=$((opened + 1))
			else
				break
			fi
		done
		printf '%s\n' "$opened" >"$SM_SCRATCH/fd-staged.txt"
		sleep 45
	) &
	holder_pid=$!
	chaos_pids+=("$holder_pid")

	# The dummies: the task's 500 sleeps, each self-bounded at 300s
	# (a wedged harness leaks at most a fleet of sleeps).
	for ((i = 0; i < dummy_count; i++)); do
		sleep 300 &
		chaos_pids+=("$!")
	done

	# The rogues: bind the deterministic port table, hold 200 MiB,
	# accept and close localhost connections until their own 45s
	# bound. The RLIMIT_AS ceiling is the runaway backstop (virtual
	# 1 GiB; the fleet's resident steady state is ~880 MiB by
	# construction, under the task's 1 GiB cap); exec keeps one
	# process per rogue so the tracked pid IS the python pid.
	for port in "${rogue_ports[@]}"; do
		(
			ulimit -v 1048576 2>/dev/null || true
			exec python3 -c 'import socket, sys, time
port = int(sys.argv[1])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port))
s.listen(64)
ram = bytearray(200 * 1024 * 1024)
end = time.time() + 45
while time.time() < end:
    s.settimeout(1.0)
    try:
        c, _ = s.accept()
        c.close()
    except OSError:
        pass' "$port" 2>>"$SM_SCRATCH/rogues.err" >>"$SM_SCRATCH/rogues.out"
		) &
		rogue_pids+=("$!")
		chaos_pids+=("$!")
	done

	# The spawn window: the interpreters start, the binds and the
	# 200 MiB allocations settle before the responder looks (four
	# rogues settle inside a second).
	sleep 1

	# The rogue gate: all $rogue_count alive, or the incident was
	# never staged (a bind conflict is host state — a named SKIP;
	# any other death is a FAIL).
	alive=0
	for pid in "${rogue_pids[@]}"; do
		if kill -0 "$pid" 2>/dev/null; then
			alive=$((alive + 1))
		fi
	done
	if ((alive < rogue_count)); then
		inferno_teardown
		if grep -q "Address already in use" "$SM_SCRATCH/rogues.err" 2>/dev/null; then
			sm_skip "simulation: the rogue fleet" \
				"a rogue port is already bound on this host (the inferno cannot be staged)"
		else
			sm_fail "simulation: the rogue fleet" \
				"$alive of $rogue_count rogues alive after the spawn window: $(head -c 200 "$SM_SCRATCH/rogues.err" 2>/dev/null || true)"
		fi
		return 0
	fi
	sm_pass "simulation: the rogue fleet is up ($rogue_count rogues, ports ${rogue_ports[*]}, 200 MiB each)"
	rogue_pin_pid="${rogue_pids[rogue_count - 1]}"

	# The io burst: the task's dd shape (100 MiB, bs=1M), written
	# by ONE dd process across the whole assertion window — the
	# live lane's attribution needs the writer alive at render
	# time. dd reads STDIN (the night-dragon-3 finding: if= would
	# ignore the pipe and the pacing would pace nothing); the
	# feeder is the printf builtin — 1 MiB every 0.2s, zero forks,
	# self-bounded at 30s — and dd self-bounds at 100 blocks
	# (~20s at that rate). The tracked pid is dd's (the pipeline's
	# last process) and it is stable for the whole window. When dd
	# exits, the feeder dies of SIGPIPE; the bare wait in the
	# teardown reaps it.
	(
		end=$((SECONDS + 30))
		while ((SECONDS < end)); do
			printf '%1048576s' ''
			sleep 0.2
		done
	) | dd of="$SM_SCRATCH/io-test.bin" bs=1M count=100 \
		iflag=fullblock conv=notrunc status=none 2>>"$SM_SCRATCH/dd.err" &
	io_pid=$!
	chaos_pids+=("$io_pid")

	# The socket storm: bounded localhost connects against rogue 0's
	# listener, paced and counted into a sidecar.
	inferno_storm() {
		local conns=0
		local end=$((SECONDS + 12))
		while ((SECONDS < end)) && ((conns < 400)); do
			if (exec 3<>"/dev/tcp/127.0.0.1/${rogue_ports[0]}") 2>/dev/null; then
				conns=$((conns + 1))
				# The tally lands after every connect: the
				# teardown kills this loop mid-window, and
				# the surface reads the count it reached,
				# never the count a killed loop never wrote.
				printf '%s\n' "$conns" >"$SM_SCRATCH/storm-conns.txt"
			fi
			sleep 0.05
		done
	}
	inferno_storm &
	storm_pid=$!
	chaos_pids+=("$storm_pid")

	# The fire settles one beat before the responder walks in.
	sleep 1

	# ------------------------------------------------------------------
	# The detection, under fire.
	# ------------------------------------------------------------------

	# Proc, timed: the forkless clock around the run, the < 1s law,
	# the > 500 row count. The scan targets the current user (--me):
	# the inferno runs under the suite's own uid, so the population
	# the spawner staged is the population the scan must capture.
	t0=${EPOCHREALTIME/./}
	sm_run "$SM_SCRATCH/proc.json" "$SM_SCRATCH/proc.err" rc 10 -- \
		"$SM_DEFAULT_BIN" proc --me --print-json
	t1=${EPOCHREALTIME/./}
	proc_ms=$(((t1 - t0) / 1000))
	sm_assert_rc 0 "$rc" "simulation: proc --print-json exits 0 under fire"
	sm_assert_file_nonempty "$SM_SCRATCH/proc.json" \
		"simulation: the proc report carries JSON content under fire"
	if [[ "$proc_ms" =~ ^[0-9]+$ ]] && ((proc_ms < proc_bar_ms)); then
		sm_pass "simulation: proc finishes under the 1s law under fire (${proc_ms} ms)"
	else
		sm_fail "simulation: proc finishes under the 1s law under fire" \
			"the proc run measured ${proc_ms:-unknown} ms (want < $proc_bar_ms)"
	fi
	proc_rows="$(grep -o -F '"comm":' "$SM_SCRATCH/proc.json" 2>/dev/null | wc -l || true)"
	[[ "$proc_rows" =~ ^[0-9]+$ ]] || proc_rows=0
	if ((proc_rows > dummy_count)); then
		sm_pass "simulation: proc captures the inferno's population ($proc_rows rows > $dummy_count)"
	else
		sm_fail "simulation: proc captures the inferno's population ($proc_rows rows > $dummy_count)" \
			"the proc report names $proc_rows processes (the spawner staged $dummy_count dummies + $rogue_count rogues)"
	fi
	sm_flag_used "proc --me"

	# Port :20050 - the pinned contract: the listener's owner named
	# from the snapshot lane. The window law (night-dragon-3):
	# --snapshot-only returns instantly; the owner rows resolve
	# from /proc either way, and without the pin the default 60s
	# collect died as exit 124 under the assert's timeout.
	sm_run "$SM_SCRATCH/port.json" "$SM_SCRATCH/port.err" rc 10 -- \
		"$SM_DEFAULT_BIN" port "$pinned_port" --print-json --snapshot-only
	sm_assert_rc 0 "$rc" \
		"simulation: port $pinned_port --print-json --snapshot-only exits 0 under fire"
	sm_assert_file_nonempty "$SM_SCRATCH/port.json" \
		"simulation: the port report carries JSON content under fire"
	sm_assert_contains "$SM_SCRATCH/port.json" \
		"\"subject\":\":${pinned_port}\"" \
		"simulation: the port report pins the subject :${pinned_port}"
	sm_assert_contains "$SM_SCRATCH/port.json" \
		"\"state\":\"LISTEN\"" \
		"simulation: the socket table renders the listening state under fire"
	if [[ -n "$rogue_pin_pid" ]] && grep -q "\"owners\":\[{\"pid\":${rogue_pin_pid},\"process\":\"python3\"" \
		"$SM_SCRATCH/port.json" 2>/dev/null; then
		sm_pass "simulation: the port report names the pinned rogue as :${pinned_port}'s owner (pid $rogue_pin_pid)"
	else
		sm_fail "simulation: the port report names the pinned rogue as :${pinned_port}'s owner (pid ${rogue_pin_pid:-unknown})" \
			"no owner row for the pinned pid in the port report"
	fi

	# RAM: the rogues must surface among the top consumers with
	# their PSS above the 100 MB bar (they hold 200 MiB each).
	sm_run "$SM_SCRATCH/ram.json" "$SM_SCRATCH/ram.err" rc 10 -- \
		"$SM_DEFAULT_BIN" doctor --symptom ram --print-json
	sm_assert_rc 0 "$rc" "simulation: doctor --symptom ram --print-json exits 0 under fire"
	sm_assert_file_nonempty "$SM_SCRATCH/ram.json" \
		"simulation: the RAM report carries JSON content under fire"
	rogues_named=0
	pss_bytes=""
	for pid in "${rogue_pids[@]}"; do
		if grep -q "\"pid\":${pid},\"comm\":\"python3\"" "$SM_SCRATCH/ram.json" 2>/dev/null; then
			rogues_named=$((rogues_named + 1))
			if [[ -z "$pss_bytes" ]]; then
				pss_line="$(grep -o "\"pid\":${pid},\"comm\":\"python3\",\"pss_bytes\":[0-9]*" \
					"$SM_SCRATCH/ram.json" 2>/dev/null | head -1 || true)"
				pss_bytes="${pss_line##*:}"
			fi
		fi
	done
	if ((rogues_named > 0)); then
		sm_pass "simulation: the RAM symptom names $rogues_named of $rogue_count rogues under fire"
	else
		sm_fail "simulation: the RAM symptom names $rogues_named of $rogue_count rogues under fire" \
			"no rogue pid named in the RAM report (the top-K table missed the whole fleet?)"
	fi
	if [[ "$pss_bytes" =~ ^[0-9]+$ ]] && ((pss_bytes > rogue_bar)); then
		sm_pass "simulation: the rogue's PSS clears the 100 MB bar under fire ($pss_bytes bytes)"
	else
		sm_fail "simulation: the rogue's PSS clears the 100 MB bar under fire" \
			"the first named rogue's PSS is ${pss_bytes:-missing} bytes (want > $rogue_bar)"
	fi

	# Why: the dd attribution on the live lane. The probe lane's
	# gate was decided by the attach preflight; on the snapshot
	# lane the assert skips with the reason named.
	if [[ "$probe_lane" -eq 1 ]]; then
		sm_run "$SM_SCRATCH/why.json" "$SM_SCRATCH/why.err" rc 15 -- \
			"$SM_DEFAULT_BIN" why "$SM_SCRATCH/io-test.bin" --since 3s --print-json
		sm_assert_rc 0 "$rc" "simulation: why --since 3s --print-json exits 0 under fire"
		sm_assert_file_nonempty "$SM_SCRATCH/why.json" \
			"simulation: the why report carries JSON content under fire"
		sm_assert_contains "$SM_SCRATCH/why.json" \
			'"mode":"live"' \
			"simulation: the why report declares the live lane under fire"
		sm_assert_contains "$SM_SCRATCH/why.json" \
			'"provenance":"observed"' \
			"simulation: the why report carries observed rows under fire"
		if [[ -n "$io_pid" ]] && grep -q "\"actor\":{\"name\":\"dd\",\"pid\":${io_pid}" \
			"$SM_SCRATCH/why.json" 2>/dev/null; then
			sm_pass "simulation: the why report attributes the writes to dd (pid $io_pid)"
		else
			sm_fail "simulation: the why report attributes the writes to dd (pid ${io_pid:-unknown})" \
				"no observed row names dd's pid as the writer (the writer exited before the render, or the event window missed the burst)"
		fi
		sm_flag_used "why --since"
	else
		sm_skip "simulation: the why lane catches the dd writer" \
			"the probe attach was refused on this host (the honest lane direction is the storm surface's)"
	fi

	# ------------------------------------------------------------------
	# The teardown: the surface closes its own inferno, by its own
	# hand, and the probe it attached is the probe it detaches.
	# ------------------------------------------------------------------
	inferno_teardown

	if [[ "$probe_lane" -eq 1 ]]; then
		sm_run "$SM_SCRATCH/sim-detach.out" "$SM_SCRATCH/sim-detach.err" rc 20 -- \
			"$SM_DEFAULT_BIN" doctor --detach
		sm_assert_rc 0 "$rc" "simulation: doctor --detach ends the inferno clean (exit 0)"
		if [[ -e /sys/fs/bpf/zejtron ]]; then
			sm_fail "simulation: detach removes the pin directory" \
				"/sys/fs/bpf/zejtron still exists after detach"
		else
			sm_pass "simulation: detach removes the pin directory"
		fi
	fi

	# The storm's own tally: the connects it actually landed.
	storm_conns="$(cat "$SM_SCRATCH/storm-conns.txt" 2>/dev/null || echo 0)"
	[[ "$storm_conns" =~ ^[0-9]+$ ]] || storm_conns=0
	if ((storm_conns > 0)); then
		sm_pass "simulation: the socket storm churned ($storm_conns connects landed)"
	else
		sm_fail "simulation: the socket storm churned ($storm_conns connects landed)" \
			"zero localhost connects succeeded against the rogues' listeners"
	fi
	fd_opened="$(cat "$SM_SCRATCH/fd-staged.txt" 2>/dev/null || echo 0)"
	[[ "$fd_opened" =~ ^[0-9]+$ ]] || fd_opened=0
	if ((fd_opened == fd_target)); then
		sm_pass "simulation: the fd storm staged $fd_opened of $fd_target descriptors"
	else
		sm_skip "simulation: the fd storm staged $fd_opened of $fd_target descriptors" \
			"the host's descriptor ceiling stopped the holder at $fd_opened of $fd_target"
	fi

	# The massive-scale report: the CI log's badge, computed from
	# the sidecars and the measured latency, never from constants.
	printf '  scale massive-scale: %s dummies | %s rogues (200 MiB each) on :%s-:%s | %s/%s fds | dd io burst 100 MiB (stdin-paced) | %s socket connects | proc under fire: %s ms\n' \
		"$dummy_count" "$rogue_count" "${rogue_ports[0]}" "$pinned_port" \
		"$fd_opened" "$fd_target" "$storm_conns" "${proc_ms:-?}"

	# Flag registry: the manifest flag this surface exercised.
	sm_flag_used "doctor --symptom"
}
