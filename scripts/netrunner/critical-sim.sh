#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only - zejtron is a Linux introspection tool.
#
# netrunner-night-C77 (night-total-hardening-1): the critical-usage
# simulation the owner asked for before zejtron lands on critical
# infrastructure. One script, two realities, honest about which one
# it is running:
#
#   root (uid 0)        - the full estate: every verb, every JSON
#                         lane, the -V/-h sweep, the safety battery,
#                         the stream law, AND the live eBPF forensic
#                         pair (create -> write -> unlink -> "who
#                         deleted this file?"; create -> rename ->
#                         the renamed row), one attach, one detach,
#                         plus the question-census leg
#                         (night-frontier-Z5): 1024 stale-key fills,
#                         two named refusals, the conservation
#                         identity accepted + refused == attempts,
#                         and the sleep-gap leg (night-frontier-Z6,
#                         D3, riding BEFORE the census fill: a clean
#                         camera is the negative arm's precondition):
#                         the awake host names no blackout - a
#                         healthy host's third clock holds its
#                         breath.
#   non-root            - the same estate minus the privileged leg,
#                         and the refusal direction is asserted: the
#                         attach MUST refuse, naming the reason -
#                         a fake success is the one unforgivable
#                         answer on this lane.
#
# The forensic pair is the night-verify-1 proof shape (the twin-row
# net): one unlink(2) crossing vfs_unlink renders exactly one
# "unlinked" row and drains exactly one op=unlink record; one
# rename(2) renders exactly one renamed row. The probes are the
# night-frontier-2 innovation - the ledger's oldest hole ("who
# deleted this file?") - and this script is where they prove
# themselves end to end, as root, on every lane that can carry them.
#
# Usage:
#   scripts/netrunner/critical-sim.sh [--bin PATH]
#
# Exit code: 0 = every check green, 1 = any check failed. The last
# line is always "NETRUNNER-C77: PASS|FAIL (n checks)" so CI and the
# micro-VM init relay the verdict without parsing prose.

set -u

BIN="${ZEJTRON_BIN:-}"
while [ $# -gt 0 ]; do
	case "$1" in
	--bin)
		BIN="${2:?}"
		shift 2
		;;
	*)
		echo "[c77] unknown flag: $1" >&2
		exit 2
		;;
	esac
done

if [ -z "$BIN" ]; then
	# The repo build probe: the NEWEST build product wins, by mtime
	# across every lane the repo produces (night-total-hardening-1:
	# the candidate list did not know the pro-profile musl dir and
	# the loop took the first existing path, so a stale plain-release
	# binary from an earlier session silently answered for a fresh
	# pro-v3 build - the "newest wins" the comment always claimed,
	# now the code's own law). The stat walk keeps shellcheck's
	# SC2012 law (no ls parsing). CI passes --bin explicitly and
	# never rides here.
	newest_bin=""
	newest_mtime=0
	for cand in \
		target/x86_64-unknown-linux-musl/pro-linux-amd64-v3-musl/zejtron \
		target/x86_64-unknown-linux-musl/release/zejtron \
		target/release/zejtron; do
		[ -x "$cand" ] || continue
		cand_mtime="$(stat -c %Y "$cand" 2>/dev/null)" || continue
		if [ "$cand_mtime" -gt "$newest_mtime" ]; then
			newest_mtime="$cand_mtime"
			newest_bin="$cand"
		fi
	done
	BIN="$newest_bin"
fi
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
	echo "[c77] FAIL: no zejtron binary (build one or pass --bin PATH)" >&2
	exit 1
fi
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/c77.XXXXXX")"
trap 'rm -rf "$SCRATCH"' EXIT

PASS=0
FAIL=0

pass() {
	PASS=$((PASS + 1))
	echo "[c77] PASS: $1"
}

fail() {
	FAIL=$((FAIL + 1))
	echo "[c77] FAIL: $1 - ${2:-no detail}"
}

note() {
	echo "[c77] note: $1"
}

# The JSON lane: jq when the lane carries it (a real parse), the
# structural floor when it does not (one line, balanced braces) -
# the degradation is named, never silent.
json_ok() {
	local file="$1"
	if command -v jq >/dev/null 2>&1; then
		jq -e . "$file" >/dev/null 2>&1
		return $?
	fi
	local line
	line="$(tr -d '\n' <"$file")"
	case "$line" in
	"{"*"}") return 0 ;;
	*) return 1 ;;
	esac
}

if ! command -v jq >/dev/null 2>&1; then
	note "jq absent - the JSON lane rides the structural floor"
fi

UID_NOW="$(id -u)"
IS_ROOT=0
if [ "$UID_NOW" = "0" ]; then
	IS_ROOT=1
	note "running as root (uid 0) - the live eBPF forensic leg is in"
else
	note "running as non-root (uid $UID_NOW) - the refusal direction is in"
fi

VERBS="path recent port proc holds touch why doctor net"

# 1. The version surface: -V on the root and on every verb, exit 0,
#    the report, never a missing-argument impostor.
"$BIN" -V >"$SCRATCH/v-root.out" 2>&1
v_rc=$?
if [ "$v_rc" -eq 0 ] && grep -q "^zejtron: v" "$SCRATCH/v-root.out"; then
	pass "root -V renders the report"
else
	fail "root -V renders the report" "rc=$v_rc: $(head -1 "$SCRATCH/v-root.out")"
fi
for verb in $VERBS; do
	if "$BIN" "$verb" -V >"$SCRATCH/v-$verb.out" 2>&1 &&
		grep -q "^zejtron: v" "$SCRATCH/v-$verb.out"; then
		pass "$verb -V renders the report"
	else
		fail "$verb -V renders the report" "$(head -1 "$SCRATCH/v-$verb.out")"
	fi
done
# --version is the same surface.
"$BIN" --version >"$SCRATCH/v-long.out" 2>&1
if cmp -s "$SCRATCH/v-root.out" "$SCRATCH/v-long.out"; then
	pass "--version is byte-equal to -V"
else
	fail "--version is byte-equal to -V" "the two spellings differ"
fi

# 2. The help surface: -h exit 0 on every verb, --help byte-equal.
for verb in $VERBS; do
	"$BIN" "$verb" -h >"$SCRATCH/h-$verb.out" 2>"$SCRATCH/h-$verb.err"
	h_rc=$?
	if [ "$h_rc" -eq 0 ] && [ -s "$SCRATCH/h-$verb.out" ] &&
		[ ! -s "$SCRATCH/h-$verb.err" ]; then
		pass "$verb -h exits 0 with stdout-only help"
	else
		fail "$verb -h exits 0 with stdout-only help" "rc=$h_rc"
	fi
	"$BIN" "$verb" --help >"$SCRATCH/hh-$verb.out" 2>/dev/null
	if cmp -s "$SCRATCH/h-$verb.out" "$SCRATCH/hh-$verb.out"; then
		pass "$verb --help is byte-equal to -h"
	else
		fail "$verb --help is byte-equal to -h" "the two spellings differ"
	fi
done

# 3. The full estate, text lane: every verb runs and renders.
"$BIN" path sh >"$SCRATCH/run-path.out" 2>&1
run_path_rc=$?
if [ "$run_path_rc" -eq 0 ] && grep -q "sh" "$SCRATCH/run-path.out"; then
	pass "path sh resolves"
else
	fail "path sh resolves" "$(head -1 "$SCRATCH/run-path.out")"
fi

"$BIN" proc --me --depth 2 >"$SCRATCH/run-proc.out" 2>&1
run_proc_rc=$?
if [ "$run_proc_rc" -eq 0 ] && grep -q "pid=" "$SCRATCH/run-proc.out"; then
	pass "proc --me renders the tree"
else
	fail "proc --me renders the tree" "$(head -1 "$SCRATCH/run-proc.out")"
fi

if "$BIN" holds /etc/resolv.conf >/dev/null 2>&1; then
	pass "holds /etc/resolv.conf runs"
else
	fail "holds /etc/resolv.conf runs" "non-zero exit"
fi

if "$BIN" touch /etc/hosts >/dev/null 2>&1; then
	pass "touch /etc/hosts runs"
else
	fail "touch /etc/hosts runs" "non-zero exit"
fi

if "$BIN" why /etc/hosts >/dev/null 2>&1; then
	pass "why /etc/hosts runs"
else
	fail "why /etc/hosts runs" "non-zero exit"
fi

if "$BIN" net >/dev/null 2>&1; then
	pass "net renders"
else
	fail "net renders" "non-zero exit"
fi

if "$BIN" port --listen --no-pid >/dev/null 2>&1; then
	pass "port --listen renders"
else
	fail "port --listen renders" "non-zero exit"
fi

# doctor's exit contract: FAIL count > 0 exits non-zero either lane,
# so the verdict is the report rendering, not the code.
"$BIN" doctor >"$SCRATCH/run-doctor.out" 2>&1
doc_rc=$?
if [ "$doc_rc" -eq 0 ] || grep -qi "summary" "$SCRATCH/run-doctor.out"; then
	pass "doctor renders the readiness report (exit $doc_rc)"
else
	fail "doctor renders the readiness report" "rc=$doc_rc, no summary line"
fi

mkdir -p "$SCRATCH/tree/nested"
echo "c77 fixture" >"$SCRATCH/tree/nested/recent-fixture.txt"
"$BIN" recent "$SCRATCH/tree" --since 5m >"$SCRATCH/run-recent.out" 2>&1
run_recent_rc=$?
if [ "$run_recent_rc" -eq 0 ] &&
	grep -q "recent-fixture.txt" "$SCRATCH/run-recent.out"; then
	pass "recent finds the fresh fixture"
else
	fail "recent finds the fresh fixture" "$(head -1 "$SCRATCH/run-recent.out")"
fi

# 4. The JSON lane: every verb's --print-json parses.
"$BIN" path sh --print-json >"$SCRATCH/j-path.out" 2>/dev/null
if json_ok "$SCRATCH/j-path.out"; then
	pass "path --print-json parses"
else
	fail "path --print-json parses" "$(head -c 80 "$SCRATCH/j-path.out")"
fi
"$BIN" proc --me --depth 2 --print-json >"$SCRATCH/j-proc.out" 2>/dev/null
if json_ok "$SCRATCH/j-proc.out"; then
	pass "proc --print-json parses"
else
	fail "proc --print-json parses" "$(head -c 80 "$SCRATCH/j-proc.out")"
fi
"$BIN" recent "$SCRATCH/tree" --limit 5 --print-json >"$SCRATCH/j-recent.out" 2>/dev/null
if json_ok "$SCRATCH/j-recent.out"; then
	pass "recent --print-json parses"
else
	fail "recent --print-json parses" "$(head -c 80 "$SCRATCH/j-recent.out")"
fi
"$BIN" holds /etc/resolv.conf --print-json >"$SCRATCH/j-holds.out" 2>/dev/null
if json_ok "$SCRATCH/j-holds.out"; then
	pass "holds --print-json parses"
else
	fail "holds --print-json parses" "$(head -c 80 "$SCRATCH/j-holds.out")"
fi
"$BIN" touch /etc/hosts --print-json >"$SCRATCH/j-touch.out" 2>/dev/null
if json_ok "$SCRATCH/j-touch.out"; then
	pass "touch --print-json parses"
else
	fail "touch --print-json parses" "$(head -c 80 "$SCRATCH/j-touch.out")"
fi
"$BIN" why /etc/hosts --print-json >"$SCRATCH/j-why.out" 2>/dev/null
if json_ok "$SCRATCH/j-why.out"; then
	pass "why --print-json parses"
else
	fail "why --print-json parses" "$(head -c 80 "$SCRATCH/j-why.out")"
fi
"$BIN" doctor --print-json >"$SCRATCH/j-doctor.out" 2>/dev/null
if json_ok "$SCRATCH/j-doctor.out"; then
	pass "doctor --print-json parses"
else
	fail "doctor --print-json parses" "$(head -c 80 "$SCRATCH/j-doctor.out")"
fi
"$BIN" net --print-json >"$SCRATCH/j-net.out" 2>/dev/null
if json_ok "$SCRATCH/j-net.out"; then
	pass "net --print-json parses"
else
	fail "net --print-json parses" "$(head -c 80 "$SCRATCH/j-net.out")"
fi
"$BIN" port --listen --no-pid --print-json >"$SCRATCH/j-port.out" 2>/dev/null
if json_ok "$SCRATCH/j-port.out"; then
	pass "port --print-json parses"
else
	fail "port --print-json parses" "$(head -c 80 "$SCRATCH/j-port.out")"
fi

# 5. The stream law: -v speaks on stderr and stdout stays byte-clean.
# The verb rides as separate argv words (quoted through the shift
# walk - the word-splitting SC2086 warns about never happens).
# --normalize takes a sed program applied to BOTH captures before
# the compare, for verbs whose stdout names kernel-owned facts that
# legitimately move between two spawns. Three classes on the proc
# leg: pid= labels (the two runs are different processes), state=
# chars (a daemon flips S/R between the captures), and kworker rows
# - kernel workers hang under kthreadd at depth 2 in the root
# scan and spawn/exit with scheduler activity, so the two captures
# legitimately hold different kworker sets (the root-native lane
# failed twice in a row right after a cargo build for exactly this
# reason; the micro-VM and non-root lanes, with no kthreadd in the
# scanned tree, never saw it). The footer counts follow the rows,
# so their numbers ride the same normalization. Normalizing keeps
# the check on its actual contract - verbose must not leak into
# stdout - instead of failing on scheduler noise no read-only tool
# can promise to freeze. Any leaked diagnostic line still fails
# the compare: the vlog wording carries no pid=/state= tokens and
# no kworker glyphs for the sed to eat.
stream_law() {
	local label="$1" normalize=""
	shift
	if [ "${1:-}" = "--normalize" ]; then
		normalize="$2"
		shift 2
	fi
	"$BIN" "$@" >"$SCRATCH/s-plain.out" 2>/dev/null
	"$BIN" "$@" -v >"$SCRATCH/s-verbose.out" 2>"$SCRATCH/s-verbose.err"
	local plain="$SCRATCH/s-plain.out" verbose="$SCRATCH/s-verbose.out"
	if [ -n "$normalize" ]; then
		sed -E "$normalize" "$plain" >"$plain.norm"
		sed -E "$normalize" "$verbose" >"$verbose.norm"
		plain="$plain.norm"
		verbose="$verbose.norm"
	fi
	if cmp -s "$plain" "$verbose" &&
		[ -s "$SCRATCH/s-verbose.err" ]; then
		pass "verbose keeps stdout byte-clean ($label)"
	else
		# Name the half that failed and show the drift: a failed
		# compare prints the first eight diffing lines, an empty
		# stderr prints both capture sizes. The next pair of eyes
		# reads the cause from the log instead of re-deriving it.
		if [ -s "$SCRATCH/s-verbose.err" ]; then
			fail "verbose keeps stdout byte-clean ($label)" \
				"stdout drifted: $(diff "$plain" "$verbose" | head -8 | tr '\n' ' ')"
		else
			fail "verbose keeps stdout byte-clean ($label)" \
				"stderr empty: plain $(wc -c <"$SCRATCH/s-plain.out") bytes, verbose $(wc -c <"$SCRATCH/s-verbose.out") bytes on stdout"
		fi
	fi
}
stream_law "doctor" doctor
stream_law "proc" --normalize '/kworker/d; s/pid=[0-9]+/pid=N/g; s/state=[RSDZTt?]/state=X/g; s/^[0-9]+ roots Â· [0-9]+ processes$/N roots Â· M processes/' proc --me --depth 2
stream_law "recent" recent "$SCRATCH/tree"
stream_law "path" path sh
# The net leg's normalize (the proc leg's own doctrine, one class
# over): the interface counters are kernel-owned facts that
# legitimately move between two spawns - the runner's own NIC ticks
# between the captures, and the root-native lane failed on exactly
# this drift. The check's contract is verbose-must-not-leak-into-
# stdout, not a promise to freeze /proc/net/dev mid-read: the
# packet/byte/error counter values ride the normalization, and any
# leaked diagnostic line still fails the compare (the vlog wording
# carries none of these tokens).
stream_law "net" --normalize 's/rx=[0-9]+/rx=N/g; s/tx=[0-9]+/tx=N/g; s/errors=[0-9]+/errors=N/g; s/drops=[0-9]+/drops=N/g; s/rx [0-9.]+[KMG]?B/rx SUM/g; s/tx [0-9.]+[KMG]?B/tx SUM/g' net

# 6. The safety battery (night-total-hardening-1): the absurd asks are
#    parse-time refusals (exit 2), the sane asks ride, every refusal
#    names its grammar or its operand.
"$BIN" proc --me --depth 1000000000000000 >/dev/null 2>&1
if [ $? -eq 2 ]; then
	pass "proc --depth 10^15 is a parse-time refusal"
else
	fail "proc --depth 10^15 is a parse-time refusal" "wrong exit"
fi
"$BIN" proc --me --depth 0 >/dev/null 2>&1
if [ $? -eq 2 ]; then
	pass "proc --depth 0 is a parse-time refusal"
else
	fail "proc --depth 0 is a parse-time refusal" "wrong exit"
fi
if "$BIN" proc --me --depth 1024 >/dev/null 2>&1; then
	pass "proc --depth 1024 (the ceiling) rides"
else
	fail "proc --depth 1024 (the ceiling) rides" "non-zero exit"
fi
"$BIN" recent "$SCRATCH/tree" --limit 99999999999999999999 >/dev/null 2>&1
if [ $? -eq 2 ]; then
	pass "recent --limit overflow is a refusal"
else
	fail "recent --limit overflow is a refusal" "wrong exit"
fi
if "$BIN" recent "$SCRATCH/tree" --since 2s >/dev/null 2>&1; then
	pass "recent --since 2s rides (one duration grammar)"
else
	fail "recent --since 2s rides (one duration grammar)" "non-zero exit"
fi
"$BIN" recent "$SCRATCH/tree" --since 3 >"$SCRATCH/s-bad-dur.out" 2>&1
bad_dur_rc=$?
if [ "$bad_dur_rc" -eq 1 ] && grep -q "(use e.g." "$SCRATCH/s-bad-dur.out"; then
	pass "bad duration refusal names the grammar"
else
	fail "bad duration refusal names the grammar" "$(head -1 "$SCRATCH/s-bad-dur.out")"
fi
"$BIN" holds /etc/resolv.conf --since 1d >"$SCRATCH/s-clamp.out" 2>"$SCRATCH/s-clamp.err"
clamp_rc=$?
if [ "$clamp_rc" -eq 0 ] && grep -qi "clamp" "$SCRATCH/s-clamp.err"; then
	pass "window --since 1d rides with the named clamp note"
else
	fail "window --since 1d rides with the named clamp note" \
		"stderr: $(head -1 "$SCRATCH/s-clamp.err")"
fi
"$BIN" path "" >/dev/null 2>&1
if [ $? -eq 1 ]; then
	pass "path '' refuses with the operand named"
else
	fail "path '' refuses with the operand named" "wrong exit"
fi
"$BIN" recent /no/such/dir/c77 >"$SCRATCH/s-nodir.out" 2>&1
nodir_rc=$?
if [ "$nodir_rc" -eq 1 ] && grep -q "/no/such/dir/c77" "$SCRATCH/s-nodir.out"; then
	pass "recent missing dir refusal names the path"
else
	fail "recent missing dir refusal names the path" "$(head -1 "$SCRATCH/s-nodir.out")"
fi
"$BIN" proc --me root >/dev/null 2>&1
if [ $? -eq 2 ]; then
	pass "proc --me + user conflict is a usage error"
else
	fail "proc --me + user conflict is a usage error" "wrong exit"
fi
"$BIN" definitely-not-a-verb >/dev/null 2>&1
if [ $? -eq 2 ]; then
	pass "unknown verb is a usage error"
else
	fail "unknown verb is a usage error" "wrong exit"
fi

# 6b. The UX honesty battery (night-total-hardening-1, the agent
#     pass): the empty operands refuse with their examples named,
#     the pathological echo is capped, the floor clamp speaks like
#     the ceiling clamp, and the limit-0 cut names itself - the four
#     laws the fixes pinned, asserted end to end on every lane.
"$BIN" holds "" >"$SCRATCH/s-empty-holds.out" 2>&1
empty_holds_rc=$?
if [ "$empty_holds_rc" -eq 1 ] &&
	grep -q "the target is empty" "$SCRATCH/s-empty-holds.out"; then
	pass "holds '' names the empty target"
else
	fail "holds '' names the empty target" "$(head -1 "$SCRATCH/s-empty-holds.out")"
fi
"$BIN" why "" >"$SCRATCH/s-empty-why.out" 2>&1
empty_why_rc=$?
if [ "$empty_why_rc" -eq 1 ] &&
	grep -q "the target is empty" "$SCRATCH/s-empty-why.out"; then
	pass "why '' names the empty target"
else
	fail "why '' names the empty target" "$(head -1 "$SCRATCH/s-empty-why.out")"
fi
"$BIN" port "" >"$SCRATCH/s-empty-port.out" 2>&1
empty_port_rc=$?
if [ "$empty_port_rc" -eq 1 ] &&
	grep -q "the port is empty" "$SCRATCH/s-empty-port.out"; then
	pass "port '' names the empty operand"
else
	fail "port '' names the empty operand" "$(head -1 "$SCRATCH/s-empty-port.out")"
fi

"$BIN" why /etc/hosts --since 0s >"$SCRATCH/s-floor.out" 2>"$SCRATCH/s-floor.err"
floor_rc=$?
if [ "$floor_rc" -eq 0 ] &&
	grep -q "below the 1s minimum" "$SCRATCH/s-floor.err"; then
	pass "window --since 0s names the floor clamp (both directions speak)"
else
	fail "window --since 0s names the floor clamp (both directions speak)" \
		"stderr: $(head -1 "$SCRATCH/s-floor.err")"
fi

long_missing="$SCRATCH/$(head -c 150 /dev/zero | tr '\0' 'l')"
"$BIN" holds "$long_missing" >"$SCRATCH/s-long.out" 2>&1
long_rc=$?
long_line="$(head -1 "$SCRATCH/s-long.out")"
long_ellipsis=0
case "$long_line" in
*"..."*) long_ellipsis=1 ;;
esac
if [ "$long_rc" -eq 1 ] && [ "$long_ellipsis" -eq 1 ] &&
	[ "${#long_line}" -le 200 ]; then
	pass "holds caps the pathological echo (150-char ask, one line)"
else
	fail "holds caps the pathological echo (150-char ask, one line)" \
		"rc=$long_rc len=${#long_line}"
fi

"$BIN" recent "$SCRATCH/tree" --limit 0 >"$SCRATCH/s-limit0.out" 2>&1
limit0_rc=$?
if [ "$limit0_rc" -eq 0 ] &&
	grep -q "0 of 1 modified files shown (--limit 0)" "$SCRATCH/s-limit0.out"; then
	pass "recent --limit 0 names the cut (never 'no modified files found')"
else
	fail "recent --limit 0 names the cut (never 'no modified files found')" \
		"$(head -1 "$SCRATCH/s-limit0.out")"
fi

# 7. The privileged leg: root gets the live forensic pair, non-root
#    gets the honest refusal. One attach, two proofs, one detach.
attach_ok=0
if [ "$IS_ROOT" = "1" ]; then
	if "$BIN" doctor --attach >"$SCRATCH/attach.out" 2>"$SCRATCH/attach.err"; then
		attach_ok=1
		pass "doctor --attach attaches on this host"
		# The off-path truth label (night-frontier-Z7, D4): the attach
		# summary names the capability set it planted AND record-
		# verified (each capability fired its real action through the
		# probe before the label may claim it) - never a silent claim.
		if grep -q "off-path truth:" "$SCRATCH/attach.out"; then
			offpath_label="$(grep -oE 'off-path truth: [a-z_+-]+' "$SCRATCH/attach.out" | head -1 | cut -d' ' -f3-)"
			pass "attach names its off-path capability set: ${offpath_label}"
		else
			fail "attach names its off-path capability set" \
				"the summary carries no off-path label: $(head -1 "$SCRATCH/attach.out")"
		fi
	else
		note "attach refused on this host ($(head -1 "$SCRATCH/attach.err")) - the forensic pair rides the refusal direction"
	fi
else
	if "$BIN" doctor --attach >"$SCRATCH/attach.out" 2>"$SCRATCH/attach.err"; then
		fail "non-root doctor --attach refuses" "it must never fake a success"
	else
		pass "non-root doctor --attach refuses with the reason named"
	fi
fi

if [ "$IS_ROOT" = "1" ] && [ "$attach_ok" = "1" ] && command -v perl >/dev/null 2>&1; then
	# The unlink half: watch the file, kill it by real syscall, demand
	# the ledger name the actor - and render exactly one row.
	un_file="$SCRATCH/unlink-proof.txt"
	: >"$un_file"
	timeout 20 "$BIN" why "$un_file" --since 5s --raw \
		>"$SCRATCH/unlink.out" 2>"$SCRATCH/unlink.err" &
	un_why=$!
	sleep 1
	perl -e '
                $| = 1;
                my $f = shift;
                my $r = syscall(87, $f);
                die "unlink failed: $!" unless $r == 0;
                print "pid=$$\n";
                sleep 8;
        ' "$un_file" >"$SCRATCH/unlink-writer.out" 2>/dev/null &
	un_writer=$!
	un_rc=0
	wait "$un_why" || un_rc=$?
	if [ "$un_rc" -eq 0 ]; then
		pass "unlink proof: why --since 5s --raw exits 0"
	else
		fail "unlink proof: why --since 5s --raw exits 0" "rc=$un_rc"
	fi
	if grep -q "unlinked" "$SCRATCH/unlink.out"; then
		pass "unlink proof: the ledger names the unlink"
	else
		fail "unlink proof: the ledger names the unlink" "no 'unlinked' row"
	fi
	if grep -q "op=unlink" "$SCRATCH/unlink.out"; then
		pass "unlink proof: the raw lane names op=unlink"
	else
		fail "unlink proof: the raw lane names op=unlink" "no op=unlink record"
	fi
	un_rows="$(grep -c " unlinked " "$SCRATCH/unlink.out" || true)"
	un_raws="$(grep -c "op=unlink" "$SCRATCH/unlink.out" || true)"
	if [ "$un_rows" = "1" ]; then
		pass "unlink proof: one act renders exactly one row (the single-publish law)"
	else
		fail "unlink proof: one act renders exactly one row (the single-publish law)" \
			"found ${un_rows:-0} rows"
	fi
	if [ "$un_raws" = "1" ]; then
		pass "unlink proof: one act drains exactly one raw record"
	else
		fail "unlink proof: one act drains exactly one raw record" \
			"found ${un_raws:-0} records"
	fi
	kill "$un_writer" 2>/dev/null || true
	wait "$un_writer" 2>/dev/null || true

	# The rename half: the same contract, rename(2) via syscall 82.
	rn_file="$SCRATCH/rename-proof.txt"
	rn_new="$SCRATCH/rename-proof-moved.txt"
	: >"$rn_file"
	timeout 20 "$BIN" why "$rn_file" --since 5s --raw \
		>"$SCRATCH/rename.out" 2>"$SCRATCH/rename.err" &
	rn_why=$!
	sleep 1
	perl -e '
                $| = 1;
                my ($f, $t) = @ARGV;
                my $r = syscall(82, $f, $t);
                die "rename failed: $!" unless $r == 0;
                print "pid=$$\n";
                sleep 8;
        ' "$rn_file" "$rn_new" >"$SCRATCH/rename-writer.out" 2>/dev/null &
	rn_writer=$!
	rn_rc=0
	wait "$rn_why" || rn_rc=$?
	if [ "$rn_rc" -eq 0 ]; then
		pass "rename proof: why --since 5s --raw exits 0"
	else
		fail "rename proof: why --since 5s --raw exits 0" "rc=$rn_rc"
	fi
	if grep -qi "renamed" "$SCRATCH/rename.out"; then
		pass "rename proof: the ledger names the rename"
	else
		fail "rename proof: the ledger names the rename" "no 'renamed' row"
	fi
	rn_rows="$(grep -ci " renamed " "$SCRATCH/rename.out" || true)"
	if [ "$rn_rows" = "1" ]; then
		pass "rename proof: one act renders exactly one row"
	else
		fail "rename proof: one act renders exactly one row" \
			"found ${rn_rows:-0} rows"
	fi
	kill "$rn_writer" 2>/dev/null || true
	wait "$rn_writer" 2>/dev/null || true

	# 7b. The sleep-gap leg (night-frontier-Z6, D3): the third clock's
	#     live arms on this host. The awake-host negative: a real
	#     window on a host that did not sleep inside it must name NO
	#     blackout - a boundary that fires on healthy hosts is the
	#     lie D3 refuses (the Z2 companion: an NTP step reads as wall
	#     skew, never as a sleep; the gap does not move under wall
	#     steps). The sampling law itself is cross-pinned live at test
	#     time against /proc/uptime (the boottime domain's two
	#     independent sources), so every kernel this suite runs on
	#     proves the third clock reads true. The SUSPEND arm (a real
	#     guest suspend mid-window, the report == ground-truth
	#     assertion) needs a disposable guest with ACPI S3 + an RTC
	#     wakealarm seat - this harness's seats carry none (the
	#     micro-VM machine type has no ACPI power management), and a
	#     decorative skip arm that can never fire is not the honest
	#     shape: the seat's recipe lives in docs/EBPF_LIFECYCLE.md,
	#     the blackout math rides the pure pins, and the divergence
	#     rests on the kernel's own documented BOOTTIME definition.
	sleep_dir="$SCRATCH/sleep-gap"
	mkdir -p "$sleep_dir"
	sleep_file="$sleep_dir/hot.bin"
	: >"$sleep_file"
	"$BIN" why "$sleep_file" --since 2s --raw >"$sleep_dir/why.out" 2>&1
	sleep_rc=$?
	if [ "$sleep_rc" -eq 0 ] &&
		! grep -q "sleep blackout" "$sleep_dir/why.out" &&
		! grep -q "sleep clock anomaly" "$sleep_dir/why.out"; then
		pass "sleep gap: the awake host's window names no blackout (the third clock holds its breath)"
	else
		fail "sleep gap: the awake host's window names no blackout" \
			"rc=$sleep_rc: $(grep -E 'sleep (blackout|clock anomaly)' "$sleep_dir/why.out" | head -1)"
	fi

	# 7b-2. The off-path live windows (night-frontier-Z7, D4): the
	#       attach's own record verification already fired real mmap,
	#       splice, and io_uring writes through the probes (an attach
	#       that cannot demonstrate a record unplants and names the
	#       capability); these legs drive REAL off-path actions inside
	#       REAL why windows and demand the rows name the silent
	#       paths. The actor compiles from the tree's own C source;
	#       a seat without cc (the micro-VM witnesses) skips by name -
	#       the attach verification carried the live proof there.
	if [ "$attach_ok" = "1" ] && command -v cc >/dev/null 2>&1; then
		cc -O2 -o "$SCRATCH/offpath-actor" scripts/ci/offpath-actor.c 2>/dev/null || true
	fi
	if [ "$attach_ok" = "1" ] && [ -x "$SCRATCH/offpath-actor" ]; then
		op_file="$SCRATCH/offpath-proof.bin"
		: >"$op_file"
		timeout 20 "$BIN" why "$op_file" --since 5s --raw \
			>"$SCRATCH/offpath-mmap.out" 2>"$SCRATCH/offpath-mmap.err" &
		op_why=$!
		sleep 0.5
		"$SCRATCH/offpath-actor" mmap "$op_file"
		op_rc=$?
		wait "$op_why" || true
		if [ "$op_rc" -eq 0 ] && grep -q "write (mmap dirty page)" "$SCRATCH/offpath-mmap.out"; then
			pass "off-path live window: a real mmap store renders the dirty-page row"
		else
			fail "off-path live window: a real mmap store renders the dirty-page row" \
				"actor rc=$op_rc: $(grep -E 'write|splice|unknown' "$SCRATCH/offpath-mmap.out" | head -2 | tr '\n' ' ')"
		fi

		: >"$op_file"
		timeout 20 "$BIN" why "$op_file" --since 5s --raw \
			>"$SCRATCH/offpath-splice.out" 2>"$SCRATCH/offpath-splice.err" &
		op_why=$!
		sleep 0.5
		"$SCRATCH/offpath-actor" splice "$op_file"
		op_rc=$?
		wait "$op_why" || true
		if [ "$op_rc" -eq 0 ] && grep -q "splice (into)" "$SCRATCH/offpath-splice.out"; then
			pass "off-path live window: a real splice renders the into row"
		else
			fail "off-path live window: a real splice renders the into row" \
				"actor rc=$op_rc: $(grep -E 'write|splice|unknown' "$SCRATCH/offpath-splice.out" | head -2 | tr '\n' ' ')"
		fi

		# The memory-backed live window (night-frontier-Z9, D6): the
		# actor creates a REAL memfd, publishes its /proc/self/fd path
		# through the control file, and fires two real MAP_SHARED
		# stores once the window is watching (the fresh-mapping store,
		# the non-present fault arm; the read-then-store ride, the
		# write-protection arm). The why window tracks the memfd's own
		# (inode, device) through the /proc path - the same identity
		# the probe's s_dev walk computes. MASK-AWARE, both directions
		# honest: a host whose attach carried the memory-backed
		# capability MUST render the row; a host where the capability
		# was named down must NOT render one (a row without the
		# capability would be the exact lie the estate refuses).
		if printf '%s' "${offpath_label:-}" | grep -q "memory-backed"; then
			ctl="$SCRATCH/memfd-ctl"
			: >"$ctl"
			"$SCRATCH/offpath-actor" memfd "$ctl" &
			memfd_pid=$!
			memfd_path=""
			for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
				if [ -s "$ctl" ]; then
					memfd_path="$(head -1 "$ctl" | cut -d' ' -f1)"
					[ -n "$memfd_path" ] && break
				fi
				sleep 0.1
			done
			if [ -n "$memfd_path" ] && [ -d "/proc/$memfd_pid" ]; then
				: >"$SCRATCH/memfd-why.out"
				timeout 20 "$BIN" why "$memfd_path" --since 5s --raw \
					>"$SCRATCH/memfd-why.out" 2>"$SCRATCH/memfd-why.err" &
				memfd_why=$!
				sleep 0.5
				echo go >>"$ctl"
				wait "$memfd_why" || true
				kill -9 "$memfd_pid" 2>/dev/null || true
				wait "$memfd_pid" 2>/dev/null || true
				if grep -q "write (mmap memory-backed page)" "$SCRATCH/memfd-why.out"; then
					pass "memory-backed live window: a real memfd store renders the memory-backed row"
				else
					fail "memory-backed live window: a real memfd store renders the memory-backed row" \
						"the attach carried the capability ($(head -1 "$SCRATCH/attach.out" 2>/dev/null | cut -c1-80)...): $(grep -E 'write|unknown' "$SCRATCH/memfd-why.out" | head -2 | tr '\n' ' ')"
				fi
			else
				fail "memory-backed live window: the actor never published its memfd path" \
					"the capability is claimed but the seat could not drive it (ctl=$(cat "$ctl" 2>/dev/null | head -1))"
			fi
		else
			note "memory-backed live window: the capability was named down on this host - the attach summary carries the reason, and the row must not exist"
		fi
	elif [ "$attach_ok" = "1" ]; then
		note "off-path live windows skipped (no cc on this seat) - the attach's record verification carried the proof"
	fi

	# 7c. The question-census leg (night-frontier-Z5): the camera's
	#     question map obeys the census law like every bounded resource
	#     it owns - a question the kernel refuses for capacity (E2BIG,
	#     the hash map full) is counted in the pinned census slot, and
	#     the refusing command names the cumulative count. The
	#     conservation shape, over ONE attach session:
	#
	#       accepted  (the stale keys the killed windows left behind)
	#       + refused (the census's own count, read back through the
	#                  refusing commands' errors)
	#       == attempts (every window this leg started that landed:
	#                    1024 synced-and-leaked + the clean refusals)
	#
	#     The fill rides the stale-key law (src/ebpf/tracked.rs: a
	#     SIGKILL mid-window leaves the key): 16 rounds of 64 windows,
	#     every window synced on the kernel's own post-track sleep
	#     state (/proc/<pid>/wchan == hrtimer_nanosleep - the loss
	#     certificate's lesson: only a /proc row cannot lie), then
	#     killed. 1024 leaked keys fill the map exactly; then two
	#     clean questions must refuse, naming the counts 1 and 2 -
	#     counting exactness, one census increment per refusal. A
	#     window that never syncs is a broken sync seat (named FAIL),
	#     never an uncounted attempt - a sync that lies would make the
	#     conservation arithmetic fiction.
	if [ "$attach_ok" = "1" ]; then
		qc_dir="$SCRATCH/qc"
		mkdir -p "$qc_dir"
		fill_ok=1
		round=0
		while [ "$fill_ok" = "1" ] && [ "$round" -lt 16 ]; do
			round=$((round + 1))
			pids=""
			r=0
			while [ "$r" -lt 64 ]; do
				r=$((r + 1))
				n=$(((round - 1) * 64 + r))
				qc_file="$qc_dir/hot-$n.bin"
				: >"$qc_file"
				"$BIN" why "$qc_file" --since 8s --raw \
					>"$qc_dir/w-$n.out" 2>&1 &
				pids="$pids $!"
			done
			synced=0
			deadline=$((SECONDS + 10))
			while [ "$synced" -lt 64 ] && [ "$SECONDS" -lt "$deadline" ]; do
				synced=0
				for p in $pids; do
					if grep -q "hrtimer_nanosleep" "/proc/$p/wchan" 2>/dev/null; then
						synced=$((synced + 1))
					fi
				done
				[ "$synced" -lt 64 ] && sleep 0.1
			done
			if [ "$synced" -eq 64 ]; then
				for p in $pids; do
					kill -9 "$p" 2>/dev/null || true
				done
			else
				fail "question census: every fill window reaches its post-track sleep" \
					"round $round synced $synced/64 within 10s - the fill cannot be trusted, the conservation arithmetic would be fiction"
				fill_ok=0
			fi
			for p in $pids; do
				wait "$p" 2>/dev/null || true
			done
		done
		if [ "$fill_ok" = "1" ]; then
			pass "question census: 1024 windows tracked and leaked (16 rounds x 64)"
			clean=1
			while [ "$clean" -le 2 ]; do
				qc_file="$qc_dir/clean-$clean.bin"
				: >"$qc_file"
				"$BIN" why "$qc_file" --since 2s --raw \
					>"$qc_dir/refuse-$clean.out" 2>&1
				refuse_rc=$?
				want="$clean"
				if [ "$refuse_rc" -ne 0 ] &&
					grep -q "refused this question" "$qc_dir/refuse-$clean.out" &&
					grep -q "${want} refused since attach" "$qc_dir/refuse-$clean.out" &&
					grep -q "doctor --detach" "$qc_dir/refuse-$clean.out"; then
					pass "question census: clean question $clean refuses naming count $want (the census counts every refusal)"
				else
					fail "question census: clean question $clean refuses naming count $want" \
						"rc=$refuse_rc: $(head -1 "$qc_dir/refuse-$clean.out")"
				fi
				clean=$((clean + 1))
			done
			if grep -q "1 refused since attach" "$qc_dir/refuse-1.out" &&
				grep -q "2 refused since attach" "$qc_dir/refuse-2.out"; then
				pass "question census: accepted 1024 + refused 2 == 1026 attempts (conservation exact, counting sequential-exact)"
			else
				fail "question census: accepted 1024 + refused 2 == 1026 attempts" \
					"the counts did not land consecutively: $(grep -h 'refused since attach' "$qc_dir"/refuse-*.out | tr '\n' ' ')"
			fi
		fi
	fi

	if "$BIN" doctor --detach >/dev/null 2>&1; then
		pass "doctor --detach leaves the host clean"
	else
		fail "doctor --detach leaves the host clean" "non-zero exit"
	fi
fi

TOTAL=$((PASS + FAIL))
VERDICT="FAIL"
if [ "$FAIL" -eq 0 ]; then
	VERDICT="PASS"
fi
echo "NETRUNNER-C77: $VERDICT ($TOTAL checks)"
if [ "$VERDICT" = "PASS" ]; then
	exit 0
fi
exit 1
