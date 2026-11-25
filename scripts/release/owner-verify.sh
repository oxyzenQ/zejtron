#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial
# OS: Linux only - the manual lane runs on a real kernel, root.
# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
#
# The owner-verify runner (night-witness-pids, the manual lane): the
# owner-side counterpart of the CI lanes. Every step runs the
# project's own mechanisms, tees the FULL output to a timestamped
# results directory, and names PASS/FAIL per step - the honest-
# failure rule: a red step is a finding to send back, never a thing
# to rerun until green.
#
# The binary under test is detected, /usr/bin/zejtron first (the
# install lane's seat), so the run verifies what the machine runs -
# ZEJTRON_BIN overrides. The results directory is gitignored residue
# by design (the dist/ class: a product of the machine, never a
# tracked file).
#
# Usage:
#   sudo bash scripts/release/owner-verify.sh
#   sudo ZEJTRON_BIN=/path ZEJTRON_ROOT=/path bash scripts/release/owner-verify.sh

set -u

TS=$(date -u +%Y%m%dT%H%M%SZ)
SANDBOX=/opt/zejtron/.sandbox
MARKER="$SANDBOX/marker-file"

fail_out() {
	printf 'FAIL: %s\n' "$1"
	exit 1
}

# ── 0. preflight (the audit list's step 1: a clean room) ─────────────
# Console-only until the preflight passes: a failed preflight leaves
# NO results directory behind.
DATE_UTC=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
KERNEL=$(uname -r)
printf '%s\n' "== 0. preflight (the audit list's step 1: a clean room) =="
printf -- '- date: %s\n' "$DATE_UTC"
printf -- '- kernel: %s\n' "$KERNEL"

ROOT="${ZEJTRON_ROOT:-}"
if [ -z "$ROOT" ]; then
	SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
	ROOT=$(git -C "$SCRIPT_DIR/../.." rev-parse --show-toplevel 2>/dev/null || true)
fi
[ -n "$ROOT" ] || fail_out "no zejtron checkout resolved (run inside the repo or set ZEJTRON_ROOT)"
[ -f "$ROOT/Cargo.toml" ] && [ -f "$ROOT/scripts/sandbox/detect-rootkit.sh" ] ||
	fail_out "$ROOT is not the zejtron checkout (Cargo.toml and the sandbox lanes are missing)"
[ "$(id -u)" -eq 0 ] ||
	fail_out "not root - the event windows need the eBPF lane; rerun with sudo"
command -v jq >/dev/null 2>&1 ||
	fail_out "jq missing (the typed JSON law's harness dependency)"

# The binary under test: /usr/bin/zejtron first (the install lane's
# seat - the run verifies what the machine runs), the repo's musl
# target build second, then whatever `which zejtron` names.
BIN="${ZEJTRON_BIN:-}"
if [ -z "$BIN" ]; then
	if [ -x /usr/bin/zejtron ]; then
		BIN=/usr/bin/zejtron
	elif [ -x "$ROOT/target/x86_64-unknown-linux-musl/pro-linux-amd64-v3-musl/zejtron" ]; then
		BIN="$ROOT/target/x86_64-unknown-linux-musl/pro-linux-amd64-v3-musl/zejtron"
	else
		BIN=$(command -v zejtron 2>/dev/null || true)
	fi
fi
[ -n "$BIN" ] && [ -x "$BIN" ] ||
	fail_out "no zejtron binary resolved (install-on-my-machine first, or set ZEJTRON_BIN)"

LEFT=$(pgrep -af pidhide | grep -v 'grep\|owner-verify' || true)
if [ -n "$LEFT" ]; then
	printf '%s\n' "FAIL: leftover pidhide processes are alive - the audit demands a dead fixture before anything starts:"
	printf '%s\n' "$LEFT"
	fail_out "wait for the loader's own exit, then rerun; do not proceed on a dirty room"
fi
printf '%s\n' "PASS: no leftover pidhide processes"
printf -- '- repo root: %s\n' "$ROOT"
printf -- '- binary under test: %s\n' "$BIN"
cd "$ROOT" || fail_out "cannot cd $ROOT"
export ZEJTRON_BIN="$BIN"

# The build-commit honesty check: the binary names its own build sha;
# a mismatch with the checkout HEAD is named, not hidden.
BUILD_SHA=$("$BIN" --version 2>/dev/null | sed -n 's/^Build: .* (\([0-9a-f]\{7,\}\))$/\1/p' | head -1)
HEAD_SHA=$(git rev-parse --short HEAD 2>/dev/null || true)
if [ -n "$BUILD_SHA" ] && [ -n "$HEAD_SHA" ] && [ "$BUILD_SHA" != "$HEAD_SHA" ]; then
	printf '%s\n' "ATTENTION: the binary's build sha ($BUILD_SHA) differs from the checkout HEAD ($HEAD_SHA) - the run verifies the installed binary, both shas ride the record"
fi

# ── the results directory (gitignored residue, the dist/ class) ──────
OUT="$ROOT/owner-verify-$TS"
mkdir -p "$OUT" || fail_out "cannot create $OUT"
RESULTS="$OUT/RESULTS.md"
{
	printf '\n## 0. preflight (the audit list'"'"'s step 1: a clean room)\n\n'
	printf -- '- date: %s\n' "$DATE_UTC"
	printf -- '- kernel: %s\n' "$KERNEL"
	printf -- '- repo root: %s\n' "$ROOT"
	printf -- '- binary under test: %s\n' "$BIN"
	printf -- '- checkout HEAD: %s / binary build sha: %s\n' "${HEAD_SHA:-unreadable}" "${BUILD_SHA:-not named by the binary}"
	printf '\n'
} > "$RESULTS"

section() {
	printf '\n## %s\n\n' "$1" | tee -a "$RESULTS"
}

note() {
	printf '%s\n' "$1" | tee -a "$RESULTS"
}

# runlog TAG CMD... - runs the command, tees console + RESULTS + its
# own artifact file, and records the exit code in RESULTS (the
# verdict). A red step never stops the run: the steps after it carry
# their own verdicts.
runlog() {
	local artifact="$OUT/$1.log"
	shift
	local tag="$1"
	shift
	printf '```\n$ %s\n' "$tag" | tee -a "$RESULTS"
	"$@" >"$artifact" 2>&1
	local rc=$?
	tail -n 200 "$artifact" | tee -a "$RESULTS"
	printf '```\n\nrc=%s (full output: %s)\n\n' "$rc" "$artifact" | tee -a "$RESULTS"
	return "$rc"
}

section "1. the binary's own claims (version + the sig row, recorded honestly)"
runlog version "$BIN" --version || true
runlog sig "$BIN" sig || true
note "(a sig REFUSED row on an unsigned build is the designed fail-closed behavior - it is a finding, not a script error)"

section "2. baseline doctor + cleanup via the project mechanism (audit step 2)"
runlog doctor-before "$BIN" doctor || true
runlog detach "$BIN" doctor --detach || true
runlog doctor-after "$BIN" doctor || true

section "3. negative control - no fixture, full JSON saved (audit step 4)"
runlog negative-why-text "$BIN" why /etc/hostname --since 10s || true
runlog negative-why-json "$BIN" why /etc/hostname --since 10s --print-json || true
NEG_UNACC=$(jq -c '.unaccounted // []' "$OUT/negative-why-json.log" 2>/dev/null | head -c 2000 || true)
note "- negative-control unaccounted: ${NEG_UNACC:-<unreadable>}"
if [ "$NEG_UNACC" = "[]" ]; then
	note "PASS: the clean window names nothing (the leg-a shape)"
else
	note "ATTENTION: a no-fixture window named boundaries - send this back (it may be the host's own truth, e.g. a hidepid mount)"
fi

section "4. the full detonation proof - all five legs (audit step 5: the FULL output, teed)"
# detect-rootkit.sh builds the fixture pair itself when absent or
# stale (its own rebuild lane) and plants the real mechanism per leg.
runlog detect-rootkit bash scripts/sandbox/detect-rootkit.sh || true
grep -E 'SANDBOX-(VERDICT|RESULT):' "$OUT/detect-rootkit.log" 2>/dev/null |
	sed 's/^/- /' | tee -a "$RESULTS" || true

section "5. the manual live ride - the why window during a planted hide"
LOADER="$ROOT/test-fixtures/pidhide/target/x86_64-unknown-linux-musl/release/pidhide-loader"
OBJECT="$ROOT/test-fixtures/pidhide/ebpf/target/bpfel-unknown-none/release/pidhide-ebpf"
if [ ! -x "$LOADER" ] || [ ! -f "$OBJECT" ]; then
	note "SKIP: the fixture pair is not at the repo's build seats (the detector's own run in step 4 manages its own copies); build with scripts/sandbox/build-fixtures.sh and rerun this step"
else
	# The exact invocation leg-b uses: the loader takes the bpfel
	# object and a lifetime in seconds; 25s covers both 10s windows
	# (the camera drains on read - the second run sees its own watch).
	"$LOADER" "$OBJECT" 25 >"$OUT/manual-loader.log" 2>&1 &
	LOADER_PID=$!
	MARKER_PID=""
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		MARKER_PID=$(sed -n 's/^PIDHIDE-PLANTED marker=//p' "$OUT/manual-loader.log" 2>/dev/null | head -1)
		[ -n "$MARKER_PID" ] && break
		sleep 1
	done
	if [ -n "$MARKER_PID" ]; then
		note "- loader planted the hide: marker pid $MARKER_PID"
		if [ -d "/proc/$MARKER_PID" ]; then
			note "- direct lookup: /proc/$MARKER_PID resolves while the listing omits it - the disagreement the why windows render"
		else
			note "ATTENTION: /proc/$MARKER_PID does not resolve - the hide dropped early; send manual-loader.log back"
		fi
	else
		note "FAIL: the loader printed no PIDHIDE-PLANTED sentinel in 10s - send manual-loader.log back"
	fi
	runlog manual-why-text "$BIN" why "$MARKER" --since 10s || true
	runlog manual-why-json "$BIN" why "$MARKER" --since 10s --print-json || true
	wait "$LOADER_PID" 2>/dev/null || true
	note "- loader exited (its exit drops the hide by design)"
fi

section "6. post-run cleanup verify (audit step 1 again + the bpf-rm law)"
runlog detach-final "$BIN" doctor --detach || true
if [ -d /sys/fs/bpf/zejtron ]; then
	note "ATTENTION: /sys/fs/bpf/zejtron still exists after doctor --detach - list what rides there:"
	ls -la /sys/fs/bpf/zejtron | tee -a "$RESULTS"
else
	note "PASS: /sys/fs/bpf/zejtron absent after the project's own detach"
fi
LEFT=$(pgrep -af pidhide | grep -v 'grep\|owner-verify' || true)
if [ -n "$LEFT" ]; then
	note "ATTENTION: pidhide processes still alive after the run:"
	printf '%s\n' "$LEFT" | tee -a "$RESULTS"
else
	note "PASS: no pidhide processes remain"
fi

section "7. the math block (proof by numbers, each number labeled)"
HIDDEN=$(jq -r '[.unaccounted[] | select(.category == "hidden pids")][0] // empty' "$OUT/manual-why-json.log" 2>/dev/null || true)
if [ -n "$HIDDEN" ]; then
	EVENTS=$(printf '%s' "$HIDDEN" | jq -r '.count')
	REASON=$(printf '%s' "$HIDDEN" | jq -r '.reason')
	DISTINCT=$(printf '%s' "$REASON" | grep -oE 'pid [0-9]+ x[0-9]+' | wc -l)
	MORE=$(printf '%s' "$REASON" | grep -oE '\([+][0-9]+ more pids unlisted\)' | grep -oE '[0-9]+' | head -1 || echo 0)
	note "- hidden-pids entry count (EVENTS recorded on the marker file): $EVENTS"
	note "- distinct pids from the entry's sample clause: $((DISTINCT + MORE))"
	note "- clause verbatim: ...$(printf '%s' "$REASON" | tail -c 400)"
	ROW_PIDS=$(grep -oE 'pid=[0-9]+' "$OUT/manual-why-text.log" 2>/dev/null | sort -u | wc -l)
	note "- distinct pids among the rendered rows: $ROW_PIDS"
	note "- the math: EVENTS count recordings, not processes; the audit question is answered by the distinct figure above"
else
	note "- no hidden-pids entry in the manual ride's JSON - if the loader planted and the window caught nothing, send manual-loader.log and manual-why-json.log back (the timing may have missed, or the hide was caught by the text window only)"
fi

section "8. send back"
note "The deliverable is this directory (gitignored residue - never a commit): $OUT"
TARBALL="owner-verify-$TS.tar.gz"
tar -czf "$TARBALL" -C "$(dirname "$OUT")" "$(basename "$OUT")" 2>/dev/null &&
	note "tarball: $ROOT/$TARBALL - send it back (or paste RESULTS.md + the .log files)"
note "Every FAIL/ATTENTION line above is a finding, not a nuisance: send it as-is."
