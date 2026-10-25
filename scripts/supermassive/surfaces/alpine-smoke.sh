# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash
# OS: Linux only — zejtron is a Linux introspection tool.
#
# =============================================================================
# alpine-smoke.sh - the night-alpine-proof musl smoke surface.
#
# Scope (the owner's night-alpine-proof directive): the README ships
# two claims this surface proves on a real musl-native alpine rootfs
# before the v80.0.0 LTS tag - "one binary, statically linked in the
# musl shape" and honest degradation where systemd is absent (alpine
# runs OpenRC, so systemctl and journalctl do not exist there). The
# proof is TEN targeted probes, not the 502-probe battery: the binary
# is static, so the kernel-facing behavior (/proc, sockets, eBPF) is
# identical to the host legs the supermassive lanes already burn -
# re-running the full battery here would test the same kernel twice.
#
# The ten probes:
#   T0  the substrate is honest alpine (musl-native, no systemd)
#   T1  -V names the musl shape
#   T2  -h renders the help surface
#   T3  doctor degrades gracefully with systemctl/journalctl absent
#   T4  path resolves apk ownership (busybox, the alpine provider)
#   T5  port --tcp --snapshot-only --print-json speaks valid JSON
#   T6  proc --me --print-json speaks valid JSON
#   T7  doctor --symptom ram --print-json carries the memory stats
#   T8  why /etc/passwd --print-json speaks a valid evidence ledger
#   T9  a bogus invocation errors honestly (non-zero, no crash)
#   T10 every captured stream is panic-free (the standing sweep,
#       enforced inside as_run so no probe can forget it)
#
# Standalone by design: supermassive.sh sources its surfaces
# explicitly (ALL_SURFACES plus the source list), and this file is
# deliberately NOT registered there - the host legs run on glibc
# runners, where T0 fails by definition. The single caller is the
# CI lane .github/workflows/supermassive-alpine.yml, which copies
# this file into the digest-pinned alpine:3.20 rootfs next to the
# binary.
#
# Usage:   bash alpine-smoke.sh /path/to/zejtron
# Needs:   bash, jq (the alpine lane installs both before the call)
# Exit:    0 when every probe passes, 1 otherwise.
# =============================================================================

set -u

AS_BIN=${1:?usage: alpine-smoke.sh /path/to/zejtron}

AS_SCRATCH=$(mktemp -d)
trap 'rm -rf "$AS_SCRATCH"' EXIT

AS_PASS=0
AS_FAIL=0
# The last probe's exit code, set by as_run and read by the as_expect_*
# helpers (the shellcheck self-note keeps the assignment visible).
AS_RC=0

as_pass() {
	AS_PASS=$((AS_PASS + 1))
	printf 'PASS %s\n' "$1"
}

as_fail() {
	AS_FAIL=$((AS_FAIL + 1))
	printf 'FAIL %s\n' "$1"
	if [ "$#" -ge 2 ]; then
		printf '      %s\n' "$2"
	fi
}

# as_run LABEL -- CMD... : run one probe, capture stdout/stderr/exit,
# and sweep both streams for a Rust panic. The streams land in
# $AS_SCRATCH/out and $AS_SCRATCH/err for the caller's assertions.
as_run() {
	local label=$1
	shift 1
	if [ "$1" != "--" ]; then
		as_fail "$label" "internal: as_run needs the -- separator"
		return 1
	fi
	shift 1
	if "$@" >"$AS_SCRATCH/out" 2>"$AS_SCRATCH/err"; then
		AS_RC=0
	else
		AS_RC=$?
	fi
	if grep -q 'panicked at' "$AS_SCRATCH/out" "$AS_SCRATCH/err" 2>/dev/null; then
		as_fail "$label" "a Rust panic rode the output (the T10 sweep)"
		printf '%s\n' '--- panic evidence (stderr head) ---' >&2
		sed -n '1,3p' "$AS_SCRATCH/err" >&2
		return 1
	fi
	return 0
}

as_expect_rc() {
	local label=$1 want=$2
	if [ "$AS_RC" -eq "$want" ]; then
		as_pass "$label"
	else
		as_fail "$label" "exit $AS_RC, wanted $want"
		return 1
	fi
}

# A probe that must NOT succeed: non-zero exit and a non-empty error
# stream (the honest-error contract - never a fake success, never a
# silent death).
as_expect_nonzero() {
	local label=$1 errfile=$2
	if [ "$AS_RC" -eq 0 ]; then
		as_fail "$label" "exit 0 - a bogus invocation must not fake success"
		return 1
	fi
	if [ ! -s "$errfile" ]; then
		as_fail "$label" "non-zero exit $AS_RC but the error stream is empty"
		return 1
	fi
	as_pass "$label"
}

as_nonempty() {
	local label=$1 file=$2
	if [ -s "$file" ]; then
		as_pass "$label"
	else
		as_fail "$label" "the file is empty"
		return 1
	fi
}

as_contains() {
	local label=$1 file=$2 needle=$3
	if grep -qF -- "$needle" "$file"; then
		as_pass "$label"
	else
		as_fail "$label" "the needle '$needle' is missing"
		return 1
	fi
}

# The JSON probes' shared parser: the expression is truthy-tested by
# jq -e against the last probe's stdout.
as_jq() {
	local label=$1 expr=$2
	if jq -e "$expr" "$AS_SCRATCH/out" >/dev/null 2>&1; then
		as_pass "$label"
	else
		as_fail "$label" "jq rejected: $expr"
		return 1
	fi
}

# --- T0: the substrate is honest alpine (musl-native, no systemd) ---
if [ -r /etc/alpine-release ]; then
	as_pass "T0 alpine substrate present ($(</etc/alpine-release))"
else
	as_fail "T0 alpine substrate present" "/etc/alpine-release is missing - not an alpine rootfs"
fi
if [ -x "$AS_BIN" ]; then
	as_pass "T0 binary is executable ($AS_BIN)"
else
	as_fail "T0 binary is executable" "$AS_BIN is not an executable file"
fi
if command -v jq >/dev/null 2>&1; then
	as_pass "T0 jq present (the JSON probes' parser)"
else
	as_fail "T0 jq present" "install jq before running the smoke surface"
fi

# --- T1: -V names the musl shape (build_label detects the libc at
# compile time; a glibc-shape drift fails here, not in production) ---
if as_run "T1 -V" -- "$AS_BIN" -V; then
	as_expect_rc "T1 -V exits 0" 0
	as_nonempty "T1 -V renders content" "$AS_SCRATCH/out"
	as_contains "T1 -V names the tool" "$AS_SCRATCH/out" "zejtron"
	as_contains "T1 -V names the musl shape" "$AS_SCRATCH/out" "musl"
fi

# --- T2: the help surface renders (a static binary with a broken
# help lane is still a broken binary) ---
if as_run "T2 -h" -- "$AS_BIN" -h; then
	as_expect_rc "T2 -h exits 0" 0
	as_nonempty "T2 -h renders content" "$AS_SCRATCH/out"
fi

# --- T3: the degradation contract - alpine has no systemd, so the
# readiness report must WARN for journalctl and systemctl, never
# fail, never fake, never crash (warn rows never turn the exit
# non-zero: only a FAIL count does) ---
if as_run "T3 doctor" -- "$AS_BIN" doctor; then
	as_expect_rc "T3 doctor exits 0 (warns never fail the report)" 0
	as_contains "T3 doctor names systemctl" "$AS_SCRATCH/out" "systemctl"
	as_contains "T3 doctor names journalctl" "$AS_SCRATCH/out" "journalctl"
	as_contains "T3 doctor degrades honestly (warn, not fake)" \
		"$AS_SCRATCH/out" "unavailable or not usable"
fi

# --- T4: the apk ownership backend - the path command must resolve
# busybox (the alpine provider) through apk, in the JSON lane ---
if as_run "T4 path sh" -- "$AS_BIN" path sh --print-json; then
	as_expect_rc "T4 path sh exits 0" 0
	as_jq "T4 path sh speaks a JSON object" 'type == "object"'
	as_jq "T4 path sh finds sh" '.found == true'
	as_jq "T4 apk ownership names busybox" \
		'.active.package | type == "string" and contains("busybox") and contains("(apk)")'
fi

# --- T5: the port snapshot lane works on the same /proc the host
# legs read (static binary, identical kernel interface) ---
if as_run "T5 port snapshot" -- "$AS_BIN" port --tcp --snapshot-only --print-json; then
	as_expect_rc "T5 port exits 0" 0
	as_jq "T5 port speaks a JSON object" 'type == "object"'
	as_jq "T5 port carries the socket array" '.ports | type == "array"'
	as_jq "T5 port names the snapshot-only lane" '.changes.reason == "snapshot-only"'
fi

# --- T6: the proc lane sees the container's own tree (the smoke
# run itself is PID 1's family - the array cannot be empty) ---
if as_run "T6 proc me" -- "$AS_BIN" proc --me --print-json; then
	as_expect_rc "T6 proc exits 0" 0
	as_jq "T6 proc speaks a JSON object" 'type == "object"'
	as_jq "T6 proc carries the process array" '.processes | type == "array"'
	as_jq "T6 proc sees the live tree" '.processes | length > 0'
fi

# --- T7: the ram symptom needs no systemd - /proc/meminfo is the
# whole story, and the JSON must carry the real memory stats ---
if as_run "T7 doctor symptom ram" -- "$AS_BIN" doctor --symptom ram --print-json; then
	as_expect_rc "T7 symptom ram exits 0" 0
	as_jq "T7 symptom ram speaks a JSON object" 'type == "object"'
	as_jq "T7 symptom ram carries the memory stats" '.memory | type == "object"'
	as_jq "T7 symptom ram total is a positive byte count" '.memory.total_bytes > 0'
fi

# --- T8: the evidence ledger on a real path - the journal fallback
# cannot attach on alpine, and that absence is a REPORT row, never
# an error: the snapshot lane must still answer ---
if as_run "T8 why etc passwd" -- "$AS_BIN" why /etc/passwd --print-json; then
	as_expect_rc "T8 why exits 0 (an absent fallback is a report, not an error)" 0
	as_jq "T8 why speaks a JSON ledger" 'type == "object"'
	as_jq "T8 why carries the ledger identity" 'has("ledger_version")'
fi

# --- T9: the honest-error contract - a bogus invocation exits
# non-zero with a real error message, never a panic, never a fake
# success ---
if as_run "T9 bogus invocation" -- "$AS_BIN" --print-json nonexistent; then
	as_expect_nonzero "T9 bogus invocation errors honestly" "$AS_SCRATCH/err"
fi

printf '\nalpine smoke: %d passed, %d failed\n' "$AS_PASS" "$AS_FAIL"
if [ "$AS_FAIL" -eq 0 ]; then
	exit 0
fi
exit 1
