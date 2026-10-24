# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# surface_simulation.sh — the server incident simulation
# (night-badass-8: the owner's ask — the suite needs a SCENARIO leg:
# a real incident shape, staged and detected end to end, the
# detection asserted on the JSON lane the automation contract pins).
#
# The scenario: a rogue process binds port 9999 and allocates
# 100 MiB, then idles. The surface plays the incident responder:
# `doctor --symptom ram --print-json` must name the rogue's pid with
# its PSS above the 50 MB bar (the memory symptom's typed process
# rows: pid, comm, pss_bytes — the hand-written serializer's field
# order is the pin), and `port 9999 --print-json` must name the same
# pid as the socket's holder (the Evidence Ledger's typed actor, the
# report's subject pinning the port). The rogue is spawned by the
# surface, bounded by its own sleep (a wedged harness cannot leak an
# unbounded consumer), killed and reaped by the surface's own hand.
#
# Host contracts: python3 must exist on the harness PATH (the rogue
# is plain python; no dependency is added to the suite itself, which
# stays bash + coreutils) — its absence is a named SKIP. A bind
# conflict on port 9999 (a developer box with a real listener) is a
# named SKIP too: the incident cannot be staged on that host. Any
# other rogue death is a FAIL.
#
# The write-event half of an incident (what the kernel probe lane
# sees while the rogue works) already has its own surface: the
# realtime storm exercises the [observed]/wrote contracts under
# concurrent load — this surface deliberately does not duplicate it.
#
# Reports land in the per-surface scratch dir (the suite's fixture
# hygiene), not /tmp: the runner owns the cleanup, and a failed
# surface's evidence survives for the post-mortem.

surface_simulation() {
	local rc
	local rogue_pid=""
	local pss_line pss_bytes

	# The host contract first: no python3, no scenario — named.
	if ! command -v python3 >/dev/null 2>&1; then
		sm_skip "simulation: the rogue spawn" \
			"python3 is not on the harness PATH (the scenario's runtime)"
		return 0
	fi

	# The rogue: listen on 9999, hold 100 MiB, idle. The sleep
	# bounds the process even if this harness dies mid-surface.
	python3 -c 'import socket, time
s = socket.socket()
s.bind(("0.0.0.0", 9999))
s.listen(5)
ram = bytearray(100 * 1024 * 1024)
time.sleep(45)' >"$SM_SCRATCH/rogue.out" 2>"$SM_SCRATCH/rogue.err" &
	rogue_pid=$!

	# The spawn window: the interpreter start, the bind, and the
	# allocation must all settle before the responder looks.
	sleep 2

	if ! kill -0 "$rogue_pid" 2>/dev/null; then
		# The rogue died before the incident could run. A bind
		# conflict is a host-state skip (a real listener owns
		# 9999 here); anything else is a harness failure.
		wait "$rogue_pid" 2>/dev/null || true
		if grep -q "Address already in use" "$SM_SCRATCH/rogue.err" 2>/dev/null; then
			sm_skip "simulation: the rogue spawn" \
				"port 9999 is already bound on this host (the incident cannot be staged)"
		else
			sm_fail "simulation: the rogue spawn" \
				"the rogue died within the spawn window: $(head -c 200 "$SM_SCRATCH/rogue.err" 2>/dev/null || true)"
		fi
		return 0
	fi
	sm_pass "simulation: the rogue holds port 9999 and 100 MiB (pid $rogue_pid)"

	# Incident response, memory half: the RAM symptom's JSON lane
	# must name the rogue and measure its PSS above the bar.
	sm_run "$SM_SCRATCH/sim-ram.json" "$SM_SCRATCH/sim-ram.err" rc 10 -- \
		"$SM_DEFAULT_BIN" doctor --symptom ram --print-json
	sm_assert_rc 0 "$rc" "simulation: doctor --symptom ram --print-json exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/sim-ram.json" \
		"simulation: the RAM report carries JSON content"
	sm_assert_contains "$SM_SCRATCH/sim-ram.json" \
		"\"pid\":${rogue_pid},\"comm\":" \
		"simulation: the RAM report names the rogue pid (pid $rogue_pid)"

	pss_line="$(grep -o "\"pid\":${rogue_pid},\"comm\":\"[^\"]*\",\"pss_bytes\":[0-9]*" \
		"$SM_SCRATCH/sim-ram.json" 2>/dev/null | head -1 || true)"
	if [[ -n "$pss_line" ]]; then
		pss_bytes="${pss_line##*:}"
		if [[ "$pss_bytes" =~ ^[0-9]+$ ]] && ((pss_bytes > 50000000)); then
			sm_pass "simulation: the rogue's PSS clears the 50 MB bar ($pss_bytes bytes)"
		else
			sm_fail "simulation: the rogue's PSS clears the 50 MB bar" \
				"the rogue's measured PSS is $pss_bytes bytes (want > 50000000)"
		fi
	else
		sm_fail "simulation: the rogue's PSS clears the 50 MB bar" \
			"no pss_bytes row extracted for pid $rogue_pid (the serializer's field order moved?)"
	fi

	# Incident response, network half: the port report's ledger
	# must pin the port, name the rogue as the holder, and carry
	# the held row the fd table scan produces.
	sm_run "$SM_SCRATCH/sim-port.json" "$SM_SCRATCH/sim-port.err" rc 10 -- \
		"$SM_DEFAULT_BIN" port 9999 --print-json
	sm_assert_rc 0 "$rc" "simulation: port 9999 --print-json exits 0"
	sm_assert_file_nonempty "$SM_SCRATCH/sim-port.json" \
		"simulation: the port report carries JSON content"
	sm_assert_contains "$SM_SCRATCH/sim-port.json" \
		"\"subject\":\":9999\"" \
		"simulation: the port report pins the subject :9999"
	sm_assert_contains "$SM_SCRATCH/sim-port.json" \
		"\"pid\":${rogue_pid}" \
		"simulation: the port report names the rogue as the holder (pid $rogue_pid)"
	sm_assert_contains "$SM_SCRATCH/sim-port.json" \
		"\"kind\":\"held\"" \
		"simulation: the port report carries the held evidence row"

	# The surface ends clean by its own hand: the rogue killed and
	# reaped, the incident closed.
	kill -9 "$rogue_pid" 2>/dev/null || true
	wait "$rogue_pid" 2>/dev/null || true
	if kill -0 "$rogue_pid" 2>/dev/null; then
		sm_fail "simulation: the rogue is closed by the surface's own hand" \
			"pid $rogue_pid still alive after the kill"
	else
		sm_pass "simulation: the rogue is closed by the surface's own hand"
	fi

	# Flag registry: the manifest flag this surface exercised.
	sm_flag_used "doctor --symptom"
}
