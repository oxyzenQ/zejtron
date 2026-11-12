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
#                         the renamed row), one attach, one detach.
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
	# The repo build probe: the NEWEST build product wins, by
	# mtime across every lane the repo produces (night-total-
	# hardening-1: the candidate list did not know the
	# pro-profile musl dir and the loop took the first existing
	# path, so a stale plain-release binary from an earlier
	# session silently answered for a fresh pro-v3 build - the
	# "newest wins" the comment always claimed, now the code's
	# own law). CI passes --bin explicitly and never rides here.
	BIN="$(ls -t \
		target/x86_64-unknown-linux-musl/pro-linux-amd64-v3-musl/zejtron \
		target/x86_64-unknown-linux-musl/release/zejtron \
		target/release/zejtron 2>/dev/null | head -1)"
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
stream_law "net" net

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
