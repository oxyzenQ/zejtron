# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_simulation.sh — the server incident simulation, upgraded to
# the ultra-scale inferno (night-dragon-4: the owner's ask — the
# night-dragon-2/3 fleet is too gentle for the ultra-massive-scale
# claim; the detective must survive a whole-host inferno at four-digit
# process counts and still report it accurately, on the typed JSON
# lane the automation contract pins).
#
# The scenario: a full host under fire, staged by the surface itself.
#
#   The chaos spawner (every actor self-bounded — a wedged harness
#   cannot leak an unbounded consumer):
#   - 2000 dummy processes (sleep 300 &), the night-dragon-4 scale law.
#   - a 500-rogue python3 fleet: four HEAVY rogues on the deterministic
#     table 20000/20017/20033/20050 (the :20050 pin is the
#     night-dragon-2 contract), each holding 200 MiB so the fleet
#     cracks a busy host's top-10 RAM table (the night-dragon-3
#     finding); the remaining LIGHT rogues bind kernel-assigned random
#     ports (randomness cannot be asserted; the socket-table churn is
#     the point) and carry a governed buffer. The night-dragon-4
#     letter (500 x 20 MiB) is 16 GiB of resident python on a 16 GiB
#     runner — the arithmetic would OOM the very CI the suite must
#     survive — so the fleet's COUNT is the scale law and the buffer
#     adapts: the memory governor caps the python fleet at 60% of
#     MemAvailable, the per-rogue buffer clamps at the spec's own
#     20 MiB, and every scaledown is named. Each rogue carries a
#     RLIMIT_AS ceiling (the runaway backstop); the staging preflight
#     demands 2 GiB MemAvailable before anything spawns.
#   - the fork governor (the night-dragon-1 lesson: the sandbox's
#     ~700-fork ceiling, CI containers' pids cgroups): the fleet must
#     fit the host's task budget — threads-max minus the live task
#     count, 70% offered to the inferno, the rest reserved for the
#     host and the suite. The rogues keep a quarter of the budget
#     (the port fleet is the scenario's spine), the dummies take the
#     rest; a budget under 120 slots is a named SKIP.
#   - one holder subshell keeping 2000 read descriptors open on a
#     scratch file (the soft ceiling is raised to the hard limit
#     inside the holder; a host whose hard ceiling cannot hold the
#     storm stages what it can and the fd assert skips, named).
#   - a dd I/O burst: the night-dragon-4 shape (500 MiB, bs=1M)
#     written by ONE dd process that reads STDIN fed by a fork-free
#     feeder (the printf builtin, 1 MiB every 0.2s, self-bounded
#     30s). The night-dragon-3 post-mortem stands: a feeder piped
#     into `dd if=/dev/zero` paced nothing, because dd ignores stdin
#     when if= is given — the writer finished inside a second and
#     the live lane's why render found a cold trail. dd reads the
#     pipe now: the writer stays alive across the whole assertion
#     window (the live lane resolves the actor from /proc at render
#     time; an exited writer reads as unaccounted by design), its
#     tracked pid is stable, and a fork-starved host cannot silence
#     the burst.
#   - a socket storm: a bounded loop of localhost connects (open and
#     close against the heavy rogues' listeners), counted into a
#     sidecar.
#
#   The detection, under fire (the chaos runs through every assert;
#   every JSON lane is typed — pure stdout, silent stderr, jq filters
#   on the flat Spec v3 grammar):
#   - `proc --me --print-json` must finish in < 1 second (measured
#     with EPOCHREALTIME — bash 5's forkless clock; a forked `date`
#     lies under fork pressure, the night-dragon-1 lesson) and must
#     capture MORE processes than the spawner staged (the typed
#     `.processes` length against the live staged tally — at full
#     spec scale that is the > 2000 law).
#   - `port 20050 --print-json --snapshot-only` must name the pinned
#     heavy rogue as the listener's owner (`.ports[0].state ==
#     "LISTEN"`, `.ports[0].owners[0].pid` — the snapshot lane
#     resolves owners from /proc and returns instantly; the window
#     law, night-dragon-3: the default 60s collect died as exit 124
#     under the assert's timeout).
#   - `doctor --symptom ram --print-json` must name the heavy rogue
#     pids with PSS above the 100 MB bar (they hold 200 MiB each).
#   - `why <io file> --since 2s --print-json` must ride the live lane
#     (gated on the doctor --attach preflight; the refusal direction
#     is the storm surface's contract) and attribute the write to the
#     dd process by name and pid (the typed actor filter).
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
# named SKIP — no dependency is added to the suite beyond the typed
# law's jq, which the runner already demands); MemAvailable below the
# staging bar, a task budget under the fleet floor, or a bind
# conflict on the heavy ports are named SKIPs; an fd ceiling below
# the storm bounds the fd assert, named. Any other rogue death is a
# FAIL. The SIM_DUMMIES / SIM_ROGUES / SIM_FDS valves exist for
# hosts that must run a reduced scenario ON PURPOSE; the defaults
# are the night-dragon-4 spec and the governors never silently
# exceed what the host holds.
#
# The massive-scale report: the surface ends with one line carrying
# the real tallies (dummies, rogues by class, the staged buffer per
# light rogue, fds staged, socket connects, the measured proc latency
# under fire) — the CI log's massive-scale badge, computed from
# sidecars, never asserted from constants.

surface_simulation() {
	local rc
	local dummy_count="${SIM_DUMMIES:-2000}"
	local rogue_target="${SIM_ROGUES:-500}"
	local fd_target="${SIM_FDS:-2000}"
	local rogue_bar=100000000 proc_bar_ms=1000 heavy_buf_mb=200
	local rogue_pin_pid="" io_pid="" storm_pid="" holder_pid=""
	local probe_lane=0 alive=0 i port heavy_count=4 light_count=0
	local light_buf_mb=0 rogue_count=0
	local -a rogue_ports=(20000 20017 20033 20050)
	local -a rogue_pids=() dummy_pids=()
	local -a chaos_pids=()
	local pinned_port=${rogue_ports[3]}
	local mem_avail_kb fd_opened storm_conns proc_ms
	local pss_bytes rogues_named stat_line state comm
	local zombies residue pid dummy_alive rogue_alive
	local tasks_max tasks_now free_tasks fleet_budget heavy_mb light_budget
	local hard_fds
	local t0 t1

	pinned_port=${rogue_ports[3]}

	# ------------------------------------------------------------------
	# Host contracts first: every absence named, nothing staged halfway.
	# All the governors run BEFORE the attach probe, so a skipped
	# inferno never leaves a pin session behind.
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
			"MemAvailable ${mem_avail_kb} kB is under the 2 GiB staging bar (the 1 GiB heavy fleet needs the headroom)"
		return 0
	fi

	# The fork governor: the fleet must fit the host's task budget
	# (threads-max minus the live tasks; the inferno gets 70%, the
	# host and the suite keep the rest). The rogues keep a quarter of
	# the offered budget — the port fleet is the scenario's spine.
	tasks_max="$(cat /proc/sys/kernel/threads-max 2>/dev/null || echo 0)"
	set -- /proc/[0-9]*
	tasks_now=$#
	if [[ ! "$tasks_max" =~ ^[0-9]+$ ]] || ((tasks_max < 400)); then
		tasks_max=$((tasks_now + 400))
	fi
	free_tasks=$((tasks_max - tasks_now - 200))
	fleet_budget=$((free_tasks * 70 / 100))
	if ((dummy_count + rogue_target > fleet_budget)); then
		if ((fleet_budget < 120)); then
			sm_skip "simulation: the inferno staging" \
				"the task budget offers $fleet_budget slots (threads-max $tasks_max, $tasks_now live) - the fleet cannot be staged"
			return 0
		fi
		rogue_target=$((fleet_budget / 4))
		((rogue_target < 8)) && rogue_target=8
		dummy_count=$((fleet_budget - rogue_target))
		printf '  note  the inferno scaled to the task budget: %s dummies, %s rogues (the night-dragon-4 spec is 2000/500)\n' \
			"$dummy_count" "$rogue_target"
	fi

	# The memory governor: the python fleet's resident ceiling is 60%
	# of MemAvailable. The heavy four (200 MiB + a ~12 MiB interpreter
	# each) come first — they carry the top-10 RAM-table contract —
	# and the light fleet's buffer takes what remains, clamped at the
	# spec's own 20 MiB. The fleet's COUNT stays the scale law; a host
	# too small for the interpreters alone gets fewer light rogues,
	# named here and in the badge.
	heavy_mb=$((heavy_count * (heavy_buf_mb + 12)))
	light_budget=$(((mem_avail_kb / 1024) * 60 / 100 - heavy_mb))
	if ((light_budget < (rogue_target - heavy_count) * 12)); then
		light_count=$((light_budget / 12 - 4))
		((light_count < 4)) && light_count=4
		printf '  note  the light fleet scaled to the memory budget: %s rogues (the night-dragon-4 spec is %s)\n' \
			"$light_count" "$((rogue_target - heavy_count))"
	else
		light_count=$((rogue_target - heavy_count))
	fi
	light_buf_mb=$(((light_budget - light_count * 12) / light_count))
	((light_buf_mb < 0)) && light_buf_mb=0
	((light_buf_mb > 20)) && light_buf_mb=20
	rogue_count=$((heavy_count + light_count))

	# The fd ceiling: the soft limit is raised inside the holder; the
	# hard limit decides whether the 2000-descriptor storm can stage.
	hard_fds="$(ulimit -Hn 2>/dev/null || echo 0)"
	if [[ "$hard_fds" =~ ^[0-9]+$ ]] && ((hard_fds > 120 && fd_target > hard_fds - 120)); then
		printf '  note  the fd storm staged to the hard ceiling: %s descriptors (the night-dragon-4 spec is %s)\n' \
			"$((hard_fds - 120))" "$fd_target"
		fd_target=$((hard_fds - 120))
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

	# The fd holder: the night-dragon-4 descriptor storm on the pile
	# file, held open by a bounded sleep, the staged count in a
	# sidecar. The soft ceiling rises to the hard limit inside the
	# holder (a 2000-deep auto-allocation walks past the stock 1024).
	(
		ulimit -Sn "$(ulimit -Hn 2>/dev/null || echo 1024)" 2>/dev/null || true
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

	# The dummies: the night-dragon-4 sleeps, each self-bounded at
	# 300s (a wedged harness leaks at most a fleet of sleeps).
	for ((i = 0; i < dummy_count; i++)); do
		sleep 300 &
		dummy_pids+=("$!")
		chaos_pids+=("$!")
	done

	# The heavy rogues: bind the deterministic port table, hold
	# 200 MiB, accept and close localhost connections until their own
	# 45s bound. The RLIMIT_AS ceiling is the runaway backstop
	# (virtual 1 GiB); exec keeps one process per rogue so the
	# tracked pid IS the python pid.
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
ram[0] = 1
ram[-1] = 1
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

	# The light rogues: kernel-assigned random ports (randomness
	# cannot be asserted; the socket-table churn is the point), the
	# governed buffer touched page-wise so the resident claim is real,
	# the same 45s bound and a 512 MiB address-space backstop.
	for ((i = 0; i < light_count; i++)); do
		(
			ulimit -v 524288 2>/dev/null || true
			exec python3 -c 'import socket, sys, time
port = 0
buf = int(sys.argv[1])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port))
s.listen(16)
if buf > 0:
    ram = bytearray(buf * 1024 * 1024)
    for j in range(0, len(ram), 4096):
        ram[j] = 1
end = time.time() + 45
while time.time() < end:
    s.settimeout(1.0)
    try:
        c, _ = s.accept()
        c.close()
    except OSError:
        pass' "$light_buf_mb" 2>>"$SM_SCRATCH/rogues.err" >>"$SM_SCRATCH/rogues.out"
		) &
		rogue_pids+=("$!")
		chaos_pids+=("$!")
	done

	# The spawn window: the interpreters start, the binds and the
	# allocations settle before the responder looks (the boot storm
	# overlaps; a slow boot still holds its pid).
	sleep 2

	# The rogue gate: all $rogue_count alive, or the incident was
	# never staged (a bind conflict on the heavy table is host state —
	# a named SKIP; any other death is a FAIL).
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
	sm_pass "simulation: the rogue fleet is up ($rogue_count rogues: $heavy_count heavy on ${rogue_ports[*]}, $light_count light on random ports, ${light_buf_mb} MiB governed buffer each)"
	rogue_pin_pid="${rogue_pids[3]}"

	# The io burst: the night-dragon-4 shape (500 MiB, bs=1M), written
	# by ONE dd process across the whole assertion window — the live
	# lane's attribution needs the writer alive at render time. dd
	# reads STDIN (the night-dragon-3 finding: if= would ignore the
	# pipe and the pacing would pace nothing); the feeder is the
	# printf builtin — 1 MiB every 0.2s, zero forks, self-bounded at
	# 30s — and dd self-bounds at 500 blocks. The tracked pid is dd's
	# (the pipeline's last process) and it is stable for the whole
	# window. When dd exits (or is torn down), the feeder dies of
	# SIGPIPE — the by-design death; its stderr rides the dd sidecar
	# so the expected "write error: Broken pipe" never pollutes the
	# suite log (the first e2e run's noise finding) — and the bare
	# wait in the teardown reaps it.
	(
		end=$((SECONDS + 30))
		while ((SECONDS < end)); do
			printf '%1048576s' ''
			sleep 0.2
		done
	) 2>>"$SM_SCRATCH/dd.err" | dd of="$SM_SCRATCH/io-test.bin" bs=1M count=500 \
		iflag=fullblock conv=notrunc status=none 2>>"$SM_SCRATCH/dd.err" &
	io_pid=$!
	chaos_pids+=("$io_pid")

	# The socket storm: bounded localhost connects against heavy
	# rogue 0's listener, paced and counted into a sidecar.
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

	# The staged tally: the live count the asserts ride (a fork
	# failure mid-spawn must name itself, never inflate the claim).
	dummy_alive=0
	for pid in "${dummy_pids[@]}"; do
		if kill -0 "$pid" 2>/dev/null; then
			dummy_alive=$((dummy_alive + 1))
		fi
	done
	rogue_alive=0
	for pid in "${rogue_pids[@]}"; do
		if kill -0 "$pid" 2>/dev/null; then
			rogue_alive=$((rogue_alive + 1))
		fi
	done

	# The fire settles one beat before the responder walks in.
	sleep 1

	# ------------------------------------------------------------------
	# The detection, under fire. Every JSON lane: pure stdout, silent
	# stderr, typed filters on the flat Spec v3 grammar.
	# ------------------------------------------------------------------

	# Proc, timed: the forkless clock around the run, the < 1s law,
	# the typed population assert against the live staged tally (at
	# full spec scale that is the > 2000 law).
	t0=${EPOCHREALTIME/./}
	sm_run "$SM_SCRATCH/proc.json" "$SM_SCRATCH/proc.err" rc 10 -- \
		"$SM_DEFAULT_BIN" proc --me --print-json
	t1=${EPOCHREALTIME/./}
	proc_ms=$(((t1 - t0) / 1000))
	sm_assert_rc 0 "$rc" "simulation: proc --print-json exits 0 under fire"
	sm_assert_silent_stderr "$SM_SCRATCH/proc.err" \
		"simulation: the proc lane keeps stderr silent under fire"
	sm_assert_pure_json "$SM_SCRATCH/proc.json" \
		"simulation: the proc lane is pure JSON under fire"
	if [[ "$proc_ms" =~ ^[0-9]+$ ]] && ((proc_ms < proc_bar_ms)); then
		sm_pass "simulation: proc finishes under the 1s law under fire (${proc_ms} ms)"
	else
		sm_fail "simulation: proc finishes under the 1s law under fire" \
			"the proc run measured ${proc_ms:-unknown} ms (want < $proc_bar_ms)"
	fi
	sm_assert_json "$SM_SCRATCH/proc.json" \
		".processes | length > $dummy_alive" \
		"simulation: proc captures the inferno's population (> $dummy_alive staged)"
	sm_flag_used "proc --me"

	# Port :20050 - the pinned contract, typed: the listener's owner
	# named from the snapshot lane. The window law (night-dragon-3):
	# --snapshot-only returns instantly; the owner rows resolve from
	# /proc either way, and without the pin the default 60s collect
	# died as exit 124 under the assert's timeout.
	sm_run "$SM_SCRATCH/port.json" "$SM_SCRATCH/port.err" rc 10 -- \
		"$SM_DEFAULT_BIN" port "$pinned_port" --print-json --snapshot-only
	sm_assert_rc 0 "$rc" \
		"simulation: port $pinned_port --print-json --snapshot-only exits 0 under fire"
	sm_assert_silent_stderr "$SM_SCRATCH/port.err" \
		"simulation: the port lane keeps stderr silent under fire"
	sm_assert_pure_json "$SM_SCRATCH/port.json" \
		"simulation: the port lane is pure JSON under fire"
	sm_assert_json "$SM_SCRATCH/port.json" \
		".subject == \":$pinned_port\"" \
		"simulation: the port report pins the subject :$pinned_port"
	sm_assert_json "$SM_SCRATCH/port.json" \
		'.ports | length > 0' \
		"simulation: the socket table carries the pinned port under fire"
	sm_assert_json "$SM_SCRATCH/port.json" \
		'.ports[0].state == "LISTEN"' \
		"simulation: the pinned socket renders the listening state under fire"
	sm_assert_json "$SM_SCRATCH/port.json" \
		".ports[0].owners[0].pid == $rogue_pin_pid and .ports[0].owners[0].process == \"python3\"" \
		"simulation: the port report names the pinned heavy rogue as owner (pid $rogue_pin_pid)"

	# The readiness gate (night-dragon-5): a busy desktop boots its
	# interpreters under load, and a heavy rogue can still be
	# mid-allocation when the ram lane reads it - the first live run
	# caught 3 of 4 heavy rogues above the bar and held the fourth
	# short. The harness picks the read's moment: poll every heavy
	# rogue's resident PSS (smaps_rollup, the kernel's own roll-up)
	# until all four clear the bar, one 0.25s beat at a time, 3s of
	# patience at most, early exit the beat all four are fat. The
	# assert below stays the verdict; the gate only moves the scan
	# past the allocation window.
	local gate_round rogues_ready pss_now pid
	gate_round=0
	while ((gate_round < 12)); do
		rogues_ready=1
		for pid in "${rogue_pids[@]:0:4}"; do
			pss_now="$(awk '/^Pss:/ {print $2 * 1024}' "/proc/$pid/smaps_rollup" 2>/dev/null || echo 0)"
			if ! [[ "$pss_now" =~ ^[0-9]+$ ]] || ((pss_now < rogue_bar)); then
				rogues_ready=0
				break
			fi
		done
		if ((rogues_ready == 1)); then
			break
		fi
		sleep 0.25
		gate_round=$((gate_round + 1))
	done
	if ((rogues_ready == 0)); then
		printf '  note  the ram readiness gate timed out: a heavy rogue was still under the %s-byte bar when the scan ran\n' "$rogue_bar"
	fi

	# RAM: the heavy rogues must surface with their PSS above the
	# 100 MB bar (they hold 200 MiB each) — the typed presence and
	# the typed bar in one filter per rogue.
	sm_run "$SM_SCRATCH/ram.json" "$SM_SCRATCH/ram.err" rc 10 -- \
		"$SM_DEFAULT_BIN" doctor --symptom ram --print-json
	sm_assert_rc 0 "$rc" "simulation: doctor --symptom ram --print-json exits 0 under fire"
	sm_assert_silent_stderr "$SM_SCRATCH/ram.err" \
		"simulation: the ram lane keeps stderr silent under fire"
	sm_assert_pure_json "$SM_SCRATCH/ram.json" \
		"simulation: the ram lane is pure JSON under fire"
	sm_assert_json "$SM_SCRATCH/ram.json" \
		'.symptom == "ram"' \
		"simulation: the ram report names the ram symptom under fire"
	rogues_named=0
	pss_bytes=""
	for pid in "${rogue_pids[@]:0:4}"; do
		if jq -e --argjson p "$pid" \
			'.processes | map(select(.pid == $p and .pss_bytes > 100000000)) | length > 0' \
			"$SM_SCRATCH/ram.json" >/dev/null 2>&1; then
			rogues_named=$((rogues_named + 1))
			if [[ -z "$pss_bytes" ]]; then
				pss_bytes="$(jq -r --argjson p "$pid" \
					'.processes[] | select(.pid == $p) | .pss_bytes' \
					"$SM_SCRATCH/ram.json" 2>/dev/null | head -1 || true)"
			fi
		fi
	done
	if ((rogues_named == heavy_count)); then
		sm_pass "simulation: the RAM symptom names all $heavy_count heavy rogues above the bar under fire"
	else
		sm_fail "simulation: the RAM symptom names all $heavy_count heavy rogues above the bar under fire" \
			"$rogues_named of $heavy_count heavy rogues named with PSS > 100 MB (the top table missed the fleet?)"
	fi
	if [[ "$pss_bytes" =~ ^[0-9]+$ ]] && ((pss_bytes > rogue_bar)); then
		sm_pass "simulation: the heavy rogue's PSS clears the 100 MB bar under fire ($pss_bytes bytes)"
	else
		sm_fail "simulation: the heavy rogue's PSS clears the 100 MB bar under fire" \
			"the first named heavy rogue's PSS is ${pss_bytes:-missing} bytes (want > $rogue_bar)"
	fi

	# Why: the dd attribution on the live lane, typed — the actor
	# filter names dd's pid on the state rows the snapshot
	# carries, and the event provenance rides the changes rows:
	# [observed] is the kernel lane's tag and never a state row's
	# (the first live run's finding). The probe lane's gate was
	# decided by the attach preflight; on the snapshot lane the
	# assert skips with the reason named.
	if [[ "$probe_lane" -eq 1 ]]; then
		sm_run "$SM_SCRATCH/why.json" "$SM_SCRATCH/why.err" rc 15 -- \
			"$SM_DEFAULT_BIN" why "$SM_SCRATCH/io-test.bin" --since 2s --print-json
		sm_assert_rc 0 "$rc" "simulation: why --since 2s --print-json exits 0 under fire"
		sm_assert_silent_stderr "$SM_SCRATCH/why.err" \
			"simulation: the why lane keeps stderr silent under fire"
		sm_assert_pure_json "$SM_SCRATCH/why.json" \
			"simulation: the why lane is pure JSON under fire"
		sm_assert_json "$SM_SCRATCH/why.json" \
			'.mode == "live"' \
			"simulation: the why report declares the live lane under fire"
		sm_assert_json "$SM_SCRATCH/why.json" \
			'.measured | type == "array" and length > 0' \
			"simulation: the why report carries measured rows under fire"
		sm_assert_json "$SM_SCRATCH/why.json" \
			'.changes.rows | any(.provenance == "observed")' \
			"simulation: the why report carries observed rows under fire"
		sm_assert_json "$SM_SCRATCH/why.json" \
			".measured | any(.actor != null and .actor.pid == $io_pid and .actor.name == \"dd\")" \
			"simulation: the why report attributes the writes to dd (pid $io_pid)"
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
	printf '  scale massive-scale: %s/%s dummies | %s/%s rogues (%s heavy x 200 MiB on :%s-:%s, %s light x %s MiB on random ports) | %s/%s fds | dd io burst 500 MiB (stdin-paced) | %s socket connects | proc under fire: %s ms\n' \
		"$dummy_alive" "$dummy_count" "$rogue_alive" "$rogue_count" \
		"$heavy_count" "${rogue_ports[0]}" "$pinned_port" \
		"$light_count" "$light_buf_mb" \
		"$fd_opened" "$fd_target" "$storm_conns" "${proc_ms:-?}"

	# Flag registry: the manifest flag this surface exercised.
	sm_flag_used "doctor --symptom"
}
