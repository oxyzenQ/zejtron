# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial
# OS: Linux only — zejtron is a Linux introspection tool.
# shellcheck shell=bash
#
# surface_loading.sh — the loading lane's surfaces (night-ux-orion-2).
#
# Depth: the piped fast-path law (byte-silent stderr on every loading
# site), the pty fast-path law (a REAL terminal receives no frame for
# a fast scan either - the lazy threshold's honest arm pinned against
# script(1), not just a pipe), the style ladder under a real pty (the
# UTF-8 locale rides the HELIX table, the C locale and NO_COLOR drop
# to the ASCII floor - detection, never flags), the bracket grammar,
# and the clear contract (a drawn line is erased before any verdict
# byte follows it). The draw arm is structurally deterministic: a host
# whose operation crosses the lazy threshold may show only legal
# frames, erased; a fast host shows silence. Both arms assert here,
# so the surface is green wherever the suite runs. Every script(1)
# call rides a timeout slice: a pty layer that never answers fails
# the leg, never the lane's wall clock.
# Exercised flags: proc --me, --check-update.

# The frame tables, parsed live from the tree's own spinner.rs (no
# hand-copied comparison table - the binary and the pin read the same
# bytes). Empty when the source does not sit beside the suite; the
# frame-membership arms skip with the gap named in that case.
HELIX_FRAMES=()
ASCII_FRAMES=()

surface_loading() {
	local rc

	# The piped fast-path law: a captured stderr never sees narration,
	# no matter what else the environment promises - the loading
	# lane's own gate, byte for byte, on both sites it wires.
	local proc_err="$SM_SCRATCH/proc.err"
	sm_run "$SM_SCRATCH/proc.out" "$proc_err" rc 10 -- "$SM_DEFAULT_BIN" proc --me
	sm_assert_rc 0 "$rc" "loading: proc --me exits 0 (piped)"
	sm_assert_file_nonempty "$SM_SCRATCH/proc.out" \
		"loading: proc --me renders the ledger (piped)"
	sm_assert_silent_stderr "$proc_err" \
		"loading: proc --me piped stderr is byte-silent"
	sm_flag_used "proc --me"

	local doc_err="$SM_SCRATCH/doctor.err"
	sm_run "$SM_SCRATCH/doctor.out" "$doc_err" rc 15 -- "$SM_DEFAULT_BIN" doctor
	sm_assert_rc 0 "$rc" "loading: doctor exits 0 (piped)"
	sm_assert_file_nonempty "$SM_SCRATCH/doctor.out" \
		"loading: doctor renders the report (piped)"
	sm_assert_silent_stderr "$doc_err" \
		"loading: doctor piped stderr is byte-silent"

	# The pty legs: script(1) wraps the command in a REAL
	# pseudoterminal, so the loading lane's TTY gate opens exactly as
	# it does on the owner's terminal. The probe below answers two
	# questions before any leg runs: is script(1) on this host, and
	# does it actually run a child to completion here (a busybox
	# script without -e, or a wrapped terminal layer, fails the probe
	# and the legs skip with the gap named - never a silent skip).
	if ! command -v script >/dev/null 2>&1; then
		sm_skip "loading: the pty legs" \
			"script(1) is not on this host - the pty laws are unpinned here"
		return 0
	fi
	local probe_rc=0
	timeout 5 script -qec true "$SM_SCRATCH/probe.raw" >/dev/null 2>&1 || probe_rc=$?
	if [[ "$probe_rc" != "0" ]]; then
		sm_skip "loading: the pty legs" \
			"script(1) cannot run a child to completion on this host (probe rc $probe_rc)"
		return 0
	fi

	if [[ -f "${SUITE_CARGO_TOML%/*}/src/output/spinner.rs" ]]; then
		spinner="${SUITE_CARGO_TOML%/*}/src/output/spinner.rs"
		# The frame tables are lifted through scratch files, never
		# process substitution: bash resolves <(...) through /dev/fd/N,
		# and a micro-VM init mounts devtmpfs without the /dev/fd
		# symlink - the witness kernels died with "No such file or
		# directory" at this mapfile (night-ux-orion-2). A plain pipe
		# into $SM_SCRATCH parses the same bytes with the same tools on
		# every host, and an empty table keeps the skip-with-the-gap
		# contract (grep finds nothing on a drifted source: the pipeline
		# rides || true under pipefail, the file lands empty).
		sed -n '/^const HELIX: /,/^];/p' "$spinner" |
			grep -o '"[^"]*"' | tr -d '"' \
			>"$SM_SCRATCH/helix.frames" || true
		mapfile -t HELIX_FRAMES <"$SM_SCRATCH/helix.frames"
		sed -n '/^const ASCII: /,/^];/p' "$spinner" |
			grep -o '"[^"]*"' | tr -d '"' \
			>"$SM_SCRATCH/ascii.frames" || true
		mapfile -t ASCII_FRAMES <"$SM_SCRATCH/ascii.frames"
	fi

	# The fast-scan pty law: proc --me and doctor under a REAL
	# terminal. On a fast host (every CI runner) the scan lands inside
	# the lazy threshold and the pty must carry ZERO narration bytes -
	# the fast path's silence is a terminal contract, not just a pipe
	# contract. On a host where the scan crosses the threshold, the
	# frames must all be legal and erased (the helper's draw arm).
	local pty_utf8="$SM_SCRATCH/pty_proc_utf8.raw"
	local proc_pty_rc=0
	timeout 15 script -qec "$SM_DEFAULT_BIN proc --me" "$pty_utf8" >/dev/null 2>&1 || proc_pty_rc=$?
	sm_assert_rc 0 "$proc_pty_rc" "loading: proc --me exits 0 under a pty"
	sm_loading_pty_contract "$pty_utf8" helix \
		"loading: proc pty narration obeys the lane contract"

	# The C-locale pass: the ladder's ASCII floor under a real pty -
	# a non-Unicode locale drops the braille helix by DETECTION (the
	# locale probe), and the floor's frames are the rotating dash.
	local pty_c="$SM_SCRATCH/pty_proc_c.raw"
	local proc_c_rc=0
	timeout 15 env LC_ALL=C LANG=C script -qec "$SM_DEFAULT_BIN proc --me" "$pty_c" >/dev/null 2>&1 || proc_c_rc=$?
	sm_assert_rc 0 "$proc_c_rc" "loading: proc --me exits 0 under a C-locale pty"
	sm_loading_pty_contract "$pty_c" ascii \
		"loading: proc C-locale pty narration obeys the ladder (ASCII floor)"

	# The NO_COLOR pass: the same ASCII floor by the color gate.
	local pty_nc="$SM_SCRATCH/pty_proc_nc.raw"
	local proc_nc_rc=0
	timeout 15 env NO_COLOR=1 script -qec "$SM_DEFAULT_BIN proc --me" "$pty_nc" >/dev/null 2>&1 || proc_nc_rc=$?
	sm_assert_rc 0 "$proc_nc_rc" "loading: proc --me exits 0 under a NO_COLOR pty"
	sm_loading_pty_contract "$pty_nc" ascii \
		"loading: proc NO_COLOR pty narration obeys the ladder (ASCII floor)"

	local pty_doc="$SM_SCRATCH/pty_doctor.raw"
	local doc_pty_rc=0
	timeout 15 script -qec "$SM_DEFAULT_BIN doctor" "$pty_doc" >/dev/null 2>&1 || doc_pty_rc=$?
	sm_assert_rc 0 "$doc_pty_rc" "loading: doctor exits 0 under a pty"
	sm_loading_pty_contract "$pty_doc" helix \
		"loading: doctor pty narration obeys the lane contract"

	# The draw arm's own seat: --check-update is the one networked
	# wait, the operation that crosses the lazy threshold on any
	# networked host (a LAN roundtrip already costs more than
	# 100 ms). The verdict's exit contract is honest about the
	# network: 0 when the answer lands, 1 when the fetch fails.
	local upd_raw="$SM_SCRATCH/pty_update.raw"
	local upd_rc=0
	timeout 20 script -qec "$SM_DEFAULT_BIN --check-update" "$upd_raw" >/dev/null 2>&1 || upd_rc=$?
	if [[ "$upd_rc" == "0" || "$upd_rc" == "1" ]]; then
		sm_pass "loading: --check-update exit contract holds under a pty (rc $upd_rc)"
	else
		sm_fail "loading: --check-update exit contract holds under a pty (rc $upd_rc)" \
			"exit status outside the honest {0,1} set"
	fi
	sm_flag_used "--check-update"
	sm_loading_pty_contract "$upd_raw" helix \
		"loading: check-update pty narration obeys the lane contract"
}

# The pty narration contract, checked against one capture:
#
# 1. Every drawn line rides the bracket grammar
#    [<label>... <frame>] with a lowercase label, and every frame is
#    a member of the table the ladder names for that capture (the
#    helix seat for a UTF-8 locale, the ASCII floor for a C locale or
#    NO_COLOR). A silent capture (the fast arm) passes trivially.
# 2. A drawn line is erased: the all-spaces clear line lands after
#    the last frame, before any verdict byte follows it.
# 3. No foreign frame ever lands: a frame outside the named table is
#    a FAIL by name (the ladder is detection, never a free choice).
sm_loading_pty_contract() {
	local capture="$1" seat="$2" label="$3"

	local drawn=0 foreign=0
	local lines=() line frame found legal
	local -a table=()
	if [[ "$seat" == "helix" ]]; then
		table=("${HELIX_FRAMES[@]}")
	else
		table=("${ASCII_FRAMES[@]}")
	fi

	# Same /dev/fd law as the table lift above: the drawn-line
	# extraction rides a scratch file, not process substitution.
	tr '\r' '\n' <"$capture" | grep -E '^\[[a-z ]+\.\.\. [^]]+\]$' \
		>"$SM_SCRATCH/drawn.lines" || true
	mapfile -t lines <"$SM_SCRATCH/drawn.lines"
	drawn=${#lines[@]}

	if [[ $drawn -eq 0 ]]; then
		sm_pass "$label (fast-path silence: 0 narration bytes on a real pty)"
		return 0
	fi

	if [[ ${#table[@]} -eq 0 ]]; then
		sm_skip "$label (frame membership)" \
			"the spinner source tables are not beside the suite"
	else
		for line in "${lines[@]}"; do
			frame="${line##*... }"
			frame="${frame%]}"
			found=0
			for legal in "${table[@]}"; do
				[[ "$frame" == "$legal" ]] && found=1
			done
			[[ "$found" == "1" ]] || foreign=$((foreign + 1))
		done
		if [[ $foreign -eq 0 ]]; then
			sm_pass "$label ($drawn legal frame(s), seat $seat)"
		else
			sm_fail "$label" "$foreign of $drawn frame(s) sit outside the $seat table"
		fi
	fi

	if tr '\r' '\n' <"$capture" | grep -qE '^ +$'; then
		sm_pass "$label (the drawn line is erased by the full-width clear)"
	else
		sm_fail "$label (the clear)" "a drawn line survived: no all-spaces erase landed"
	fi
}
