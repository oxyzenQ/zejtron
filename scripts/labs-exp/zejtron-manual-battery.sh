#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial
# OS: Linux only — zejtron is a Linux introspection tool.
#
# NON_LATIN_FIXTURE: the multibyte --since unit probe is the test
# vector itself (the parser must refuse it cleanly, no panic,
# night-dragon-lts-1); the CJK character is the fixture, not prose.
#
# night-dragon-fly-1 (the manual lane): the end-to-end manual battery.
#
# Every probe below is derived from the SOURCE surface - src/cli/mod.rs
# is the help contract, src/cli/ux.rs is the rescue contract - so the
# battery covers 100% of what -h/--help advertises plus the lanes the
# help cannot show: the parse-error and rescue lanes, the JSON field
# paths, the clamp and ceiling refusals, the SIGPIPE law, and the
# privileged attach/detach lane.
#
# Run it on a real host, then send the report file back for the audit:
#
#   bash scripts/labs-exp/zejtron-manual-battery.sh
#
# The report lands at ./zejtron-manual-battery-report.txt (override
# with ZEJTRON_BATTERY_OUT). Every probe line prints the exact command
# first, so the report doubles as the manual: what you see is what ran.
#
# The privileged lane (doctor --attach / --detach, the real kernel
# probes) needs root or CAP_BPF + CAP_PERFMON. It is gated:
#
#   sudo ZEJTRON_BATTERY_ROOT=1 bash scripts/labs-exp/zejtron-manual-battery.sh
#
# Without the gate the privileged probes print a named SKIP, never a
# fake pass. Do not commit the report file - it is machine-specific
# evidence for the audit, not tree content.

set -u

# ── the binary under audit ────────────────────────────────────────────
# ZEJTRON_BIN_PATH wins, then the build-tree lanes, then $PATH - the
# same resolve order the shared resolver (scripts/lib/zejtron-bin.sh)
# carries, replicated inline so this battery needs no source line.
BIN="${ZEJTRON_BIN_PATH:-}"
if [ -z "$BIN" ]; then
	for candidate in target/debug/zejtron target/release/zejtron \
		target/x86_64-unknown-linux-musl/release/zejtron; do
		if [ -x "$candidate" ]; then
			BIN="$candidate"
			break
		fi
	done
fi
if [ -z "$BIN" ]; then
	BIN="$(command -v zejtron 2>/dev/null || true)"
fi
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
	echo "error: no zejtron binary found (set ZEJTRON_BIN_PATH or build one)" >&2
	exit 1
fi

REPORT="${ZEJTRON_BATTERY_OUT:-zejtron-manual-battery-report.txt}"
exec > >(tee "$REPORT") 2>&1

PASS=0
FAIL=0
WARN=0
SKIP=0

rail() {
	echo ""
	echo "━━━ $* ━━━"
}

probe() { # label, expected_exit, command...
	local label="$1"
	local want="$2"
	shift 2
	echo ""
	echo "+ $*"
	local out err rc
	out="$("$@" 2>/tmp/zmb-err.txt)"
	rc=$?
	err="$(cat /tmp/zmb-err.txt)"
	if [ -n "$out" ]; then
		echo "$out"
	fi
	if [ -n "$err" ]; then
		echo "[stderr] $err"
	fi
	if [ "$rc" -eq "$want" ]; then
		echo "[exit $rc - as expected]"
		PASS=$((PASS + 1))
	else
		echo "[exit $rc - EXPECTED $want: MISMATCH]"
		FAIL=$((FAIL + 1))
	fi
}

probe_warn() { # label, command... - informational, exit recorded not judged
	local label="$1"
	shift
	echo ""
	echo "+ $*   [informational]"
	"$@" 2>/tmp/zmb-err.txt
	local rc=$?
	local err
	err="$(cat /tmp/zmb-err.txt)"
	if [ -n "$err" ]; then
		echo "[stderr] $err"
	fi
	echo "[exit $rc - recorded, not judged]"
	WARN=$((WARN + 1))
}

probe_fail() { # label, needle, command... - expects non-zero + needle
	local label="$1"
	local needle="$2"
	shift 2
	echo ""
	echo "+ $*"
	"$@" >/tmp/zmb-out.txt 2>/tmp/zmb-err.txt
	local rc=$?
	cat /tmp/zmb-out.txt /tmp/zmb-err.txt
	if [ "$rc" -eq 0 ]; then
		echo "[exit 0 - EXPECTED FAILURE: MISMATCH]"
		FAIL=$((FAIL + 1))
		return
	fi
	if grep -q -- "$needle" /tmp/zmb-out.txt /tmp/zmb-err.txt; then
		echo "[exit $rc, refusal names '$needle' - as expected]"
		PASS=$((PASS + 1))
	else
		echo "[exit $rc but output never mentions '$needle': MISMATCH]"
		FAIL=$((FAIL + 1))
	fi
}

probe_json() { # label, jq-filter-as-python-expr, command...
	# The filter rides python: 'd["os"]' style. The raw JSON line is
	# printed whole - the audit reads the field names, not a summary.
	local label="$1"
	local expr="$2"
	shift 2
	echo ""
	echo "+ $*"
	"$@" >/tmp/zmb-json.txt 2>/tmp/zmb-err.txt
	local rc=$?
	local err
	err="$(cat /tmp/zmb-err.txt)"
	cat /tmp/zmb-json.txt
	if [ -n "$err" ]; then
		echo "[stderr] $err"
	fi
	if [ "$rc" -ne 0 ]; then
		echo "[exit $rc - EXPECTED 0: MISMATCH]"
		FAIL=$((FAIL + 1))
		return
	fi
	if [ ! -s /tmp/zmb-json.txt ]; then
		echo "[empty JSON output: MISMATCH]"
		FAIL=$((FAIL + 1))
		return
	fi
	if python3 -c "
import json, sys
with open('/tmp/zmb-json.txt') as fh:
    text = fh.read()
d = json.loads(text)
r = eval('$expr')
print('[json ok -', repr(r)[:80], ']')
"; then
		PASS=$((PASS + 1))
	else
		echo "[json lane failed: $expr: MISMATCH]"
		FAIL=$((FAIL + 1))
	fi
}

probe_skip() {
	echo ""
	echo "+ $*   [SKIP - run with sudo ZEJTRON_BATTERY_ROOT=1]"
	SKIP=$((SKIP + 1))
}

# ═════════════════════════════════════════════════════════════════════════
rail "0. the binary and the global surface"
# ═════════════════════════════════════════════════════════════════════════
echo "binary: $BIN"
"$BIN" -V

probe "bare invocation (the banner + help)" 0 "$BIN"
probe "-h" 0 "$BIN" -h
probe "--help" 0 "$BIN" --help
probe "-V" 0 "$BIN" -V
probe "--version" 0 "$BIN" --version
probe "version short-circuit before a required positional" 0 "$BIN" path -V
probe "-v before verb (stderr diagnostics)" 0 "$BIN" -v doctor
probe "-v after verb (global placement)" 0 "$BIN" doctor -v
probe_warn "--check-update (network lane, exit recorded)" "$BIN" --check-update

# ═════════════════════════════════════════════════════════════════════════
rail "1. every verb's own -h (the ten surfaces + the sig alias)"
# ═════════════════════════════════════════════════════════════════════════
for verb in path recent port proc holds touch why doctor net sig; do
	probe "$verb -h" 0 "$BIN" "$verb" -h
done
probe "signature (the sig alias)" 0 "$BIN" signature -h

# ═════════════════════════════════════════════════════════════════════════
rail "2. path (resolution + duplicates + package owner)"
# ═════════════════════════════════════════════════════════════════════════
probe "path sh" 0 "$BIN" path sh
probe "path python3 (the interpreter chain)" 0 "$BIN" path python3
probe_json "path --print-json field map" 'd["command"], d["found"], bool(d["active"])' \
	"$BIN" path sh --print-json
probe_fail "path missing-command refusal" "not found" "$BIN" path no-such-binary-xyz

# ═════════════════════════════════════════════════════════════════════════
rail "3. recent (limit ceiling, the no-clamp window)"
# ═════════════════════════════════════════════════════════════════════════
probe "recent default" 0 "$BIN" recent
probe "recent --limit 0 (the honest cut)" 0 "$BIN" recent . --limit 0
probe "recent --limit 1" 0 "$BIN" recent . --limit 1
probe "recent --since 1h" 0 "$BIN" recent . --since 1h
probe "recent --since 100h (unbounded window: accepted)" 0 "$BIN" recent . --since 100h
probe "recent --since 5d" 0 "$BIN" recent . --since 5d
probe_fail "recent --limit 1000001 (the ceiling refusal)" "is not in 0..=1000000" \
	"$BIN" recent . --limit 1000001
probe_fail "recent --since nope (invalid duration)" "invalid duration" \
	"$BIN" recent . --since nope
probe_fail "recent --since 5x (multibyte-free bad unit)" "invalid duration" \
	"$BIN" recent . --since 5x
probe_fail "recent --since 5分 (multibyte unit: clean refusal)" "invalid duration" \
	"$BIN" recent . --since 5分
probe_json "recent --print-json field map" 'type(d["files"]) is list' \
	"$BIN" recent . --limit 3 --print-json

# ═════════════════════════════════════════════════════════════════════════
rail "4. port (flag matrix, clamps, conflicts)"
# ═════════════════════════════════════════════════════════════════════════
probe "port default" 0 "$BIN" port
probe "port --tcp" 0 "$BIN" port --tcp
probe "port --udp" 0 "$BIN" port --udp
probe "port --listen" 0 "$BIN" port --listen
probe "port --all" 0 "$BIN" port --all
probe "port --all --numeric" 0 "$BIN" port --all --numeric
probe "port --tcp --group" 0 "$BIN" port --tcp --group
probe "port --tcp --group --no-pid" 0 "$BIN" port --tcp --group --no-pid
probe "port --events-only" 0 "$BIN" port --events-only
probe "port --snapshot-only" 0 "$BIN" port --snapshot-only
probe "port --since 2h (the clamp: warning line expected)" 0 "$BIN" port --since 2h
probe "port --since 0s (below the floor: clamp expected)" 0 "$BIN" port --since 0s
probe "port 443 (single port)" 0 "$BIN" port 443
probe_fail "port --listen --all (conflict)" "cannot be used" "$BIN" port --listen --all
probe_fail "port --events-only --snapshot-only (conflict)" "cannot be used" \
	"$BIN" port --events-only --snapshot-only
probe_fail "port 0 refusal" "invalid port" "$BIN" port 0
probe_fail "port 65536 refusal" "invalid port" "$BIN" port 65536
probe_fail "port abc refusal" "invalid port" "$BIN" port abc
probe_json "port --print-json field map" 'd["subject"], type(d["ports"]) is list' \
	"$BIN" port --print-json
probe_json "port 9999 JSON (the empty-port shape)" 'd["subject"], d["ports"]' \
	"$BIN" port 9999 --print-json

# ═════════════════════════════════════════════════════════════════════════
rail "5. proc (target group, depth ceiling, find)"
# ═════════════════════════════════════════════════════════════════════════
probe "proc bare (the whole table)" 0 "$BIN" proc
probe "proc --me" 0 "$BIN" proc --me
probe "proc --me --depth 1" 0 "$BIN" proc --me --depth 1
probe "proc --me --depth 1024 (the ceiling)" 0 "$BIN" proc --me --depth 1024
probe "proc --me --find sh" 0 "$BIN" proc --me --find sh
probe "proc --find sshd (host may have none)" 0 "$BIN" proc --find sshd
probe "proc --me --no-pid" 0 "$BIN" proc --me --no-pid
probe "proc --me --no-color" 0 "$BIN" proc --me --no-color
probe "proc root (the uid-0 tree)" 0 "$BIN" proc root
probe "proc 0 (numeric UID)" 0 "$BIN" proc 0
probe_fail "proc --me root (the target conflict)" "cannot be used" "$BIN" proc --me root
probe_fail "proc --me --depth 0 (below the floor)" "is not in 1..=1024" \
	"$BIN" proc --me --depth 0
probe_fail "proc --me --depth 1025 (above the ceiling)" "is not in 1..=1024" \
	"$BIN" proc --me --depth 1025
probe_json "proc --print-json field map" 'type(d["processes"]) is list, d["processes"][0]["pid"] >= 0' \
	"$BIN" proc --print-json

# ═════════════════════════════════════════════════════════════════════════
rail "6. holds (file, port, the temp lane)"
# ═════════════════════════════════════════════════════════════════════════
TMPDIR_B="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_B"' EXIT
touch "$TMPDIR_B/held file"
probe "holds /etc/resolv.conf" 0 "$BIN" holds /etc/resolv.conf
probe "holds 53" 0 "$BIN" holds 53
probe "holds 443" 0 "$BIN" holds 443
probe "holds <temp file> (the no-holder verdict)" 0 "$BIN" holds "$TMPDIR_B/held file"
probe "holds --since 30s" 0 "$BIN" holds 53 --since 30s
probe_fail "holds 0 refusal" "invalid port" "$BIN" holds 0
probe_fail "holds 65536 refusal" "invalid port" "$BIN" holds 65536
# The holds refusal names the errno (no such file or directory) where
# touch and why name path not found - the one wording seam this
# battery found; the freeze keeps the bytes, the audit records it.
probe_fail "holds missing-path refusal" "no such file or directory" \
	"$BIN" holds "$TMPDIR_B/missing path"
probe_json "holds --print-json field map" 'd["verdict"], bool(d["verdict"]["supports"]) is not None' \
	"$BIN" holds /etc/resolv.conf --print-json

# ═════════════════════════════════════════════════════════════════════════
rail "7. touch (file, dir, the modify-nothing law)"
# ═════════════════════════════════════════════════════════════════════════
printf 'hello\n' >"$TMPDIR_B/touched file"
mkdir -p "$TMPDIR_B/touched dir"
probe "touch <file>" 0 "$BIN" touch "$TMPDIR_B/touched file"
probe "touch <dir>" 0 "$BIN" touch "$TMPDIR_B/touched dir"
probe "touch /etc/hosts" 0 "$BIN" touch /etc/hosts
probe "touch --since 30s" 0 "$BIN" touch /etc/hosts --since 30s
probe_fail "touch missing-path refusal" "not found" "$BIN" touch "$TMPDIR_B/missing path"
probe_json "touch --print-json field map" 'd["subject"], type(d["measured"]) is list, d["verdict"]["supports"]' \
	"$BIN" touch /etc/hosts --print-json

# ═════════════════════════════════════════════════════════════════════════
rail "8. why (trace, raw, the JSON conflict)"
# ═════════════════════════════════════════════════════════════════════════
probe "why /etc/passwd" 0 "$BIN" why /etc/passwd
probe "why --trace (the explainability ladder)" 0 "$BIN" why /etc/passwd --trace
probe "why --raw (the kernel events)" 0 "$BIN" why /etc/passwd --trace --raw
probe "why 53 (port target)" 0 "$BIN" why 53
probe "why --since 30s" 0 "$BIN" why /etc/passwd --since 30s
probe_fail "why --print-json --trace (conflict)" "cannot be used" \
	"$BIN" why /etc/passwd --print-json --trace
probe_fail "why 0 refusal" "invalid port" "$BIN" why 0
probe_fail "why missing-path refusal" "not found" "$BIN" why "$TMPDIR_B/missing path"
probe_json "why --print-json field map" 'd["measured"], type(d["unaccounted"]) is list, d["verdict"]["supports"]' \
	"$BIN" why /etc/passwd --print-json

# ═════════════════════════════════════════════════════════════════════════
rail "9. doctor (readiness, symptoms, the JSON map)"
# ═════════════════════════════════════════════════════════════════════════
probe "doctor (the readiness check)" 0 "$BIN" doctor
probe_fail "doctor --raw without --symptom (the named refusal)" "--symptom" \
	"$BIN" doctor --raw
for symptom in ram cpu disk network gpu slow; do
	probe "doctor --symptom $symptom" 0 "$BIN" doctor --symptom "$symptom"
done
probe_fail "doctor --symptom xyz (the vocabulary echo)" "xyz" \
	"$BIN" doctor --symptom xyz
probe_fail "doctor --attach --symptom ram (conflict)" "cannot be used" \
	"$BIN" doctor --attach --symptom ram
probe_fail "doctor --attach --detach (conflict)" "cannot be used" \
	"$BIN" doctor --attach --detach
probe_json "doctor --print-json field map" 'd["os"], d["kernel"], d["ebpf_lane"]' \
	"$BIN" doctor --print-json
probe_json "doctor --symptom ram JSON" 'type(d["processes"]) is list' \
	"$BIN" doctor --symptom ram --print-json

# ═════════════════════════════════════════════════════════════════════════
rail "10. the privileged lane (root or CAP_BPF + CAP_PERFMON)"
# ═════════════════════════════════════════════════════════════════════════
if [ "${ZEJTRON_BATTERY_ROOT:-0}" = "1" ]; then
	probe "doctor --attach (the one-shot plant)" 0 "$BIN" doctor --attach
	probe "why after attach (the event window)" 0 "$BIN" why /etc/passwd --since 30s
	probe "port --events-only after attach" 0 "$BIN" port --events-only
	probe "doctor --detach (unpin everything, idempotent)" 0 "$BIN" doctor --detach
	probe "doctor --detach again (idempotence)" 0 "$BIN" doctor --detach
else
	probe_skip "doctor --attach / --detach"
fi

# ═════════════════════════════════════════════════════════════════════════
rail "11. net and sig"
# ═════════════════════════════════════════════════════════════════════════
probe "net" 0 "$BIN" net
probe_json "net --print-json field map" 'type(d["interfaces"]) is list' \
	"$BIN" net --print-json
probe_warn "sig (unsigned-commit exit 1 is the honest verdict)" "$BIN" sig
echo ""
echo "+ $BIN sig --print-json   [the unsigned-commit lane: exit 1, JSON whole]"
"$BIN" sig --print-json >/tmp/zmb-json.txt 2>/tmp/zmb-err.txt
sig_rc=$?
cat /tmp/zmb-json.txt
if python3 -c "
import json
with open('/tmp/zmb-json.txt') as fh:
    d = json.load(fh)
assert d['depths'] and d['identity'] and d['verdict']
print('[json ok - verdict', d['verdict'], d['verified'], ']')
"; then
	if [ "$sig_rc" -eq 1 ]; then
		echo "[exit 1 - the honest unsigned verdict]"
		PASS=$((PASS + 1))
	else
		echo "[exit $sig_rc - EXPECTED 1 on this unsigned tree: MISMATCH]"
		FAIL=$((FAIL + 1))
	fi
else
	echo "[sig json invalid: MISMATCH]"
	FAIL=$((FAIL + 1))
fi

# ═════════════════════════════════════════════════════════════════════════
rail "12. the UX bridge (rescues, redirects, the one-tip contract)"
# ═════════════════════════════════════════════════════════════════════════
probe_fail "help (the muscle-memory redirect)" "--help" "$BIN" help
probe_fail "whoholds (the removed-verb redirect)" "holds" "$BIN" whoholds /etc/resolv.conf
probe_fail "lasttouch (the removed-verb redirect)" "touch" "$BIN" lasttouch /etc/hosts
probe_fail "whyopen (the removed-verb redirect)" "why" "$BIN" whyopen /etc/passwd
probe_fail "envpath (the removed-verb redirect)" "path" "$BIN" envpath sh
probe_fail "stat (the near-miss hint)" "doctor" "$BIN" stat
probe_fail "status (the near-miss hint)" "sig" "$BIN" status
probe_fail "unknown verb" "unrecognized" "$BIN" prt
probe_fail "--ME case rescue" "--me" "$BIN" proc --ME
probe_fail "--Print-Json case rescue" "--print-json" "$BIN" proc --Print-Json
probe_fail "--check-updated rescue (top-level only flag)" "--check-update" \
	"$BIN" --check-updated
probe_fail "unknown flag" "unexpected argument" "$BIN" proc --bogus-flag
probe_fail "proc --since (retired lifecycle flag)" "unexpected argument" \
	"$BIN" proc --since 30s
probe_fail "path with no argument" "required arguments" "$BIN" path

# ═════════════════════════════════════════════════════════════════════════
rail "13. the pipe law (SIGPIPE, exit 141)"
# ═════════════════════════════════════════════════════════════════════════
echo ""
echo "+ $BIN doctor | head -1   [informational]"
"$BIN" doctor 2>/dev/null | head -1
rc="${PIPESTATUS[0]}"
echo "[pipe exit ${rc} - the UNIX law expects 141, silent, no backtrace]"
if [ "$rc" = "141" ]; then
	PASS=$((PASS + 1))
else
	WARN=$((WARN + 1))
	echo "[exit ${rc} - recorded for the audit (0 means head won the race)]"
fi

# ═════════════════════════════════════════════════════════════════════════
rail "verdict"
# ═════════════════════════════════════════════════════════════════════════
echo ""
echo "battery: $PASS passed, $FAIL failed, $WARN recorded, $SKIP skipped"
if [ "$FAIL" -gt 0 ]; then
	echo "the report names every mismatch - send the whole file back for the audit"
	exit 1
fi
echo "all expectations held - send $REPORT back for the audit"
