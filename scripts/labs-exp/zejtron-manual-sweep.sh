#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial
# OS: Linux only — zejtron is a Linux introspection tool.
#
# NON_LATIN_FIXTURE: the multibyte --since unit probe is the test
# vector itself (the parser must refuse it cleanly, no panic); the
# CJK character is the fixture, not prose.
#
# night-dragon-fly-3 (the manual sweep): the whole -h/--help estate
# plus the lanes the fly-1 battery does not ride.
#
# Derived from the SOURCE surface - src/cli/mod.rs is the help
# contract, src/cli/ux.rs is the rescue contract - so every
# help-listed flag rides at least once, and the boundary, conflict,
# device, symlink, shadow-duplicate, byte-equality and JSON lanes
# the help cannot show are named alongside.
#
# Run it on a real host, then send the report file back for the
# audit:
#
#   bash scripts/labs-exp/zejtron-manual-sweep.sh
#
# The fast lane is the default: every event-window probe rides the
# 1s floor (ZEJTRON_SWEEP_FULL=1, or the battery's
# ZEJTRON_BATTERY_FULL=1, restores the shipped widths - minutes, not
# hours). The clamp probes ride --snapshot-only unconditionally, so
# the clamp note is validated before any lane work waits - the fast
# lane and the FULL lane alike.
#
# Owner law (night-dragon-fly-4): no window value above the 1s floor
# ever rides a live lane in this instrument. A live verb watches its
# (clamped) width in full wall-clock - an hourly ask there is a
# one-hour observation, not a probe. The ceiling and the d/m unit
# interplay are proven on the snapshot lanes only, which return in
# milliseconds with the same stderr note: port --since 2h/5d/90m
# --snapshot-only and holds 53 --since 2h (a port target is snapshot
# by nature). Those are the only over-1h asks in this file, and none
# of them waits.
#
# The privileged lane (doctor --attach/--detach, the live event
# windows) needs root or CAP_BPF + CAP_PERFMON. It is gated:
#
#   sudo ZEJTRON_SWEEP_ROOT=1 bash scripts/labs-exp/zejtron-manual-sweep.sh
#
# (ZEJTRON_BATTERY_ROOT=1 is honored too, so one sudo line drives
# both instruments.) Without the gate the privileged probes print a
# named SKIP plus the recorded unprivileged refusal, never a fake
# pass. Do not commit the report file - it is machine-specific
# evidence for the audit, not tree content.
#
# The byte-equality lane pins the CURRENT recorded state, seams
# included: bare vs -h differs by exactly one trailing newline
# (F11, open, owner's call) and the sweep says so by construction -
# when the owner closes F11, the F11 probe moves with the fix, the
# same way the battery's pins moved with the fly-2 close-out.

set -u

# ── the binary under audit ────────────────────────────────────────────
# ZEJTRON_BIN_PATH wins, then the build-tree lanes, then $PATH - the
# same resolve order the battery carries, replicated inline so this
# sweep needs no source line.
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

REPORT="${ZEJTRON_SWEEP_OUT:-zejtron-manual-sweep-report.txt}"
exec > >(tee "$REPORT") 2>&1

# The capture files are per-run mktemp children, never fixed /tmp
# names (the battery's night-dragon-lts-2 law): a fixed name written
# by one uid and reopened by another in the sticky world-writable
# /tmp is refused with EACCES even for root (fs.protected_regular).
# Unique names per run mean the opener is always the owner.
S_OUT="$(mktemp -d /tmp/zsw-out.XXXXXXXX)"
ZSW_OUT="$(mktemp /tmp/zsw-raw.XXXXXXXX)"
ZSW_ERR="$(mktemp /tmp/zsw-err.XXXXXXXX)"
ZSW_JSON="$(mktemp /tmp/zsw-json.XXXXXXXX)"
trap 'rm -rf "${TMPDIR_B:-}" "$S_OUT" "$ZSW_OUT" "$ZSW_ERR" "$ZSW_JSON"' EXIT

PASS=0
FAIL=0
WARN=0
SKIP=0

# The fast lane (night-dragon-fly-3, the battery's wait contract
# carried over): every event-window probe rides the 1s floor, the
# clamp probe rides --snapshot-only, and the full lane restores the
# shipped widths. The vars are ARRAYS expanded quoted - the shellcheck
# quad's d19ef03 law - so the argv bytes stay two words where the
# grammar wants two words.
SWEEP_FULL="${ZEJTRON_SWEEP_FULL:-${ZEJTRON_BATTERY_FULL:-0}}"
if [ "$SWEEP_FULL" = "1" ]; then
        PORT_WIN=()
        LEDGER_WIN=()
        LEDGER_SPAN="30s"
else
        PORT_WIN=(--since 1s)
        LEDGER_WIN=(--since 1s)
        LEDGER_SPAN="2s"
fi

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
        echo "  probe: $label"
        local out err rc
        out="$("$@" 2>"$ZSW_ERR")"
        rc=$?
        err="$(cat "$ZSW_ERR")"
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
        echo "+ $*   [informational: $label]"
        "$@" 2>"$ZSW_ERR"
        local rc=$?
        local err
        err="$(cat "$ZSW_ERR")"
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
        echo "  probe: $label"
        "$@" >"$ZSW_OUT" 2>"$ZSW_ERR"
        local rc=$?
        cat "$ZSW_OUT" "$ZSW_ERR"
        if [ "$rc" -eq 0 ]; then
                echo "[exit 0 - EXPECTED FAILURE: MISMATCH]"
                FAIL=$((FAIL + 1))
                return
        fi
        if grep -q -- "$needle" "$ZSW_OUT" "$ZSW_ERR"; then
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
        echo "  probe: $label"
        "$@" >"$ZSW_JSON" 2>"$ZSW_ERR"
        local rc=$?
        local err
        err="$(cat "$ZSW_ERR")"
        cat "$ZSW_JSON"
        if [ -n "$err" ]; then
                echo "[stderr] $err"
        fi
        if [ "$rc" -ne 0 ]; then
                echo "[exit $rc - EXPECTED 0: MISMATCH]"
                FAIL=$((FAIL + 1))
                return
        fi
        if [ ! -s "$ZSW_JSON" ]; then
                echo "[empty JSON output: MISMATCH]"
                FAIL=$((FAIL + 1))
                return
        fi
        if python3 -c "
import json, sys
with open('$ZSW_JSON') as fh:
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

probe_cmp() { # label, file_a, file_b - byte equality between two captures
        local label="$1"
        local fa="$2"
        local fb="$3"
        echo ""
        echo "  cmp: $label"
        if cmp -s "$fa" "$fb"; then
                echo "[byte-identical - as expected]"
                PASS=$((PASS + 1))
        else
                echo "[bytes differ: MISMATCH]"
                FAIL=$((FAIL + 1))
        fi
}

probe_skip() {
        echo ""
        echo "+ $*   [SKIP - run with sudo ZEJTRON_SWEEP_ROOT=1]"
        SKIP=$((SKIP + 1))
}

# ═════════════════════════════════════════════════════════════════════════
rail "SW0. byte-equality laws (the global surface)"
# ═════════════════════════════════════════════════════════════════════════
echo "binary: $BIN"
if [ "$SWEEP_FULL" = "1" ]; then
        echo "lane: full - the shipped window widths (port 60s, ledger 10s, the 30s spans)"
else
        echo "lane: fast - every window probe rides the 1s floor (ZEJTRON_SWEEP_FULL=1 restores the shipped widths)"
fi
"$BIN" -V

"$BIN" >"$S_OUT/bare.out" 2>/dev/null
"$BIN" -h >"$S_OUT/help.out" 2>/dev/null
"$BIN" --help >"$S_OUT/longhelp.out" 2>/dev/null
"$BIN" -V >"$S_OUT/v.out" 2>/dev/null
"$BIN" --version >"$S_OUT/version.out" 2>/dev/null
{
        cat "$S_OUT/help.out"
        printf '\n'
} >"$S_OUT/help_f11.out"
probe_cmp "-h vs --help (byte-identical)" "$S_OUT/help.out" "$S_OUT/longhelp.out"
probe_cmp "bare vs -h + one newline (the F11 record, open)" "$S_OUT/bare.out" "$S_OUT/help_f11.out"
probe_cmp "-V vs --version (byte-identical)" "$S_OUT/v.out" "$S_OUT/version.out"
probe "-v alone dispatches nothing (the A6 law: bare help, exit 0)" 0 "$BIN" -v
for verb in path recent port proc holds touch why doctor net sig; do
        "$BIN" -v "$verb" --help >"$S_OUT/vhelp_a.out" 2>/dev/null
        "$BIN" "$verb" --help >"$S_OUT/vhelp_b.out" 2>/dev/null
        probe_cmp "-v before $verb --help: stdout byte-identical" "$S_OUT/vhelp_a.out" "$S_OUT/vhelp_b.out"
done

# ═════════════════════════════════════════════════════════════════════════
rail "SW1. path (the shadow lane, the absolute arg, the JSON lanes)"
# ═════════════════════════════════════════════════════════════════════════
probe "path sh" 0 "$BIN" path sh
if command -v python3 >/dev/null 2>&1; then
        probe "path python3 (the interpreter chain)" 0 "$BIN" path python3
else
        probe_warn "path python3 (skipped: no python3 on this host, recorded)" "$BIN" path python3
fi
TMPDIR_B="$(mktemp -d)"
TMPBIN="$TMPDIR_B/bin"
mkdir -p "$TMPBIN"
printf '#!/bin/sh\nexit 0\n' >"$TMPBIN/sh"
chmod 755 "$TMPBIN/sh"
PATH="$TMPBIN:$PATH" probe "path sh (the shadow-duplicate lane: duplicates names the shadow)" 0 \
        "$BIN" path sh
probe_warn "path /usr/bin/sh (an absolute path as the command arg, recorded)" \
        "$BIN" path /usr/bin/sh
probe_json "path --print-json field map" \
        'd["command"], d["found"], bool(d["active"]), type(d["duplicates"]) is list' \
        "$BIN" path sh --print-json
probe_warn "path missing --print-json (the JSON-on-refusal lane, recorded)" \
        "$BIN" path no-such-binary-xyz --print-json
probe_fail "path missing-command refusal" "not found" "$BIN" path no-such-binary-xyz

# ═════════════════════════════════════════════════════════════════════════
rail "SW2. recent (the unclamped window, the ceilings, the refusals)"
# ═════════════════════════════════════════════════════════════════════════
probe "recent (the default cut)" 0 "$BIN" recent
probe "recent . --limit 0 (the honest cut)" 0 "$BIN" recent . --limit 0
probe "recent . --limit 1" 0 "$BIN" recent . --limit 1
probe "recent . --limit 1000000 (the ceiling: accepted)" 0 "$BIN" recent . --limit 1000000
probe_fail "recent --limit 1000001 (the ceiling refusal)" "is not in 0..=1000000" \
        "$BIN" recent . --limit 1000001
probe_warn "recent --limit -1 (the negative ask, the F7 family, recorded)" "$BIN" recent . --limit -1
probe_warn "recent --limit abc (the non-numeric ask, recorded)" "$BIN" recent . --limit abc
probe_warn "recent . --since 0s (the zero window on the unclamped lane, recorded)" \
        "$BIN" recent . --since 0s
probe "recent . --since 30m (the wide cut on the unclamped lane)" 0 \
        "$BIN" recent . --since 30m
probe "recent . --since 100m (the unbounded window: accepted, no window clamp)" 0 \
        "$BIN" recent . --since 100m
# the d unit rides the snapshot clamp lane (SW3 port --since 5d,
# instant); hourly and daily asks stay out of this instrument per the
# owner law in the header.
probe_warn "recent . --since 5m (the m unit on the unclamped lane, recorded)" "$BIN" recent . --since 5m
probe_fail "recent --since nope (invalid duration)" "invalid duration" "$BIN" recent . --since nope
probe_fail "recent --since 5x (bad unit)" "invalid duration" "$BIN" recent . --since 5x
probe_fail "recent --since 5分 (multibyte unit: clean refusal)" "invalid duration" \
        "$BIN" recent . --since 5分
probe_fail "recent on a missing directory (the house refusal shape)" "path not found" \
        "$BIN" recent /no/such/dir --since 30m
probe_warn "recent on a file as the scan root (recorded)" "$BIN" recent /etc/hosts --since 30m
probe_json "recent --print-json field map" \
        'd["path"], type(d["files"]) is list, d["files"][0]["mtime_unix_secs"] > 0' \
        "$BIN" recent . --limit 2 --print-json

# ═════════════════════════════════════════════════════════════════════════
rail "SW3. port (the full flag matrix, the clamp interplay, the edges)"
# ═════════════════════════════════════════════════════════════════════════
probe "port (the fast window)" 0 "$BIN" port "${PORT_WIN[@]}"
probe "port --tcp" 0 "$BIN" port --tcp "${PORT_WIN[@]}"
probe "port --udp" 0 "$BIN" port --udp "${PORT_WIN[@]}"
probe "port --tcp --udp (the combined protocol lane)" 0 "$BIN" port --tcp --udp "${PORT_WIN[@]}"
probe "port --listen" 0 "$BIN" port --listen "${PORT_WIN[@]}"
probe "port --all" 0 "$BIN" port --all "${PORT_WIN[@]}"
probe "port --all --numeric" 0 "$BIN" port --all --numeric "${PORT_WIN[@]}"
probe "port --tcp --group" 0 "$BIN" port --tcp --group "${PORT_WIN[@]}"
probe "port --tcp --group --no-pid" 0 "$BIN" port --tcp --group --no-pid "${PORT_WIN[@]}"
probe "port --no-pid" 0 "$BIN" port --no-pid "${PORT_WIN[@]}"
probe "port --events-only" 0 "$BIN" port --events-only "${PORT_WIN[@]}"
probe "port --snapshot-only" 0 "$BIN" port --snapshot-only
probe_fail "port --listen --all (conflict)" "cannot be used" "$BIN" port --listen --all
probe_fail "port --events-only --snapshot-only (conflict)" "cannot be used" \
        "$BIN" port --events-only --snapshot-only
probe "port --since 0s (below the floor: the clamp note rides the dump)" 0 "$BIN" port --since 0s
probe "port --since 2h --snapshot-only (the ceiling note: instant, nothing waits)" 0 \
        "$BIN" port --since 2h --snapshot-only
probe "port --since 5d --snapshot-only (the d unit on the clamped lane: instant)" 0 \
        "$BIN" port --since 5d --snapshot-only
probe "port --since 90m --snapshot-only (the m unit on the clamped lane: instant)" 0 \
        "$BIN" port --since 90m --snapshot-only
probe_fail "port --since nope (invalid duration)" "invalid duration" "$BIN" port --since nope
probe "port 22" 0 "$BIN" port 22 "${PORT_WIN[@]}"
probe "port 1 (the bottom edge)" 0 "$BIN" port 1 "${PORT_WIN[@]}"
probe "port 65535 (the top edge: accepted)" 0 "$BIN" port 65535 "${PORT_WIN[@]}"
probe_fail "port 0 refusal" "invalid port" "$BIN" port 0
probe_fail "port 65536 refusal" "invalid port" "$BIN" port 65536
probe_fail "port abc refusal" "invalid port" "$BIN" port abc
probe_json "port --print-json field map" \
        'd["subject"], type(d["ports"]) is list' \
        "$BIN" port --print-json "${PORT_WIN[@]}"
probe_json "port --print-json --no-pid --numeric (the render flags inside JSON)" \
        'd["subject"], type(d["ports"]) is list' \
        "$BIN" port --print-json --no-pid --numeric "${PORT_WIN[@]}"
probe_json "port 9999 JSON (the empty-port shape)" 'd["subject"], d["ports"]' \
        "$BIN" port 9999 --print-json "${PORT_WIN[@]}"

# ═════════════════════════════════════════════════════════════════════════
rail "SW4. proc (target lanes, depth edges, find, the render flags)"
# ═════════════════════════════════════════════════════════════════════════
probe "proc (the whole table)" 0 "$BIN" proc
probe "proc --me" 0 "$BIN" proc --me
probe "proc <current user> (the name arg)" 0 "$BIN" proc "$(id -un)"
probe "proc <current uid> (the numeric arg)" 0 "$BIN" proc "$(id -u)"
probe_warn "proc no-such-user-xyz (the unknown-user refusal shape, recorded)" \
        "$BIN" proc no-such-user-xyz
probe "proc --me --depth 1" 0 "$BIN" proc --me --depth 1
probe "proc --me --depth 1024 (the ceiling)" 0 "$BIN" proc --me --depth 1024
probe_fail "proc --me --depth 0 (below the floor)" "is not in 1..=1024" "$BIN" proc --me --depth 0
probe_fail "proc --me --depth 1025 (above the ceiling)" "is not in 1..=1024" \
        "$BIN" proc --me --depth 1025
probe_fail "proc --me --depth -5 (the F7 record: the sign loses the range name)" \
        "invalid digit" "$BIN" proc --me --depth -5
probe_warn "proc --me --depth abc (the non-numeric ask, recorded)" "$BIN" proc --me --depth abc
probe "proc --me --find sh" 0 "$BIN" proc --me --find sh
probe "proc --find no-such-name-xyz (the honest none)" 0 "$BIN" proc --find no-such-name-xyz
probe_warn "proc --find '' (the empty pattern, recorded)" "$BIN" proc --find ""
probe "proc --me --no-pid" 0 "$BIN" proc --me --no-pid
probe "proc --me --no-color" 0 "$BIN" proc --me --no-color
probe "proc --me --no-pid --no-color (the combined render lane)" 0 \
        "$BIN" proc --me --no-pid --no-color
probe_fail "proc --me root (the target conflict)" "cannot be used" "$BIN" proc --me root
probe_json "proc --print-json field map" \
        'type(d["processes"]) is list, d["processes"][0]["pid"] >= 0' \
        "$BIN" proc --print-json
probe_json "proc --me --print-json --no-pid (the render flag inside JSON)" \
        'type(d["processes"]) is list' \
        "$BIN" proc --me --print-json --no-pid

# ═════════════════════════════════════════════════════════════════════════
rail "SW5. holds (file, port, device, the clamps, the JSON lanes)"
# ═════════════════════════════════════════════════════════════════════════
probe "holds /etc/resolv.conf" 0 "$BIN" holds /etc/resolv.conf "${LEDGER_WIN[@]}"
probe "holds 53" 0 "$BIN" holds 53 "${LEDGER_WIN[@]}"
probe "holds 65535 (the top edge)" 0 "$BIN" holds 65535 "${LEDGER_WIN[@]}"
probe "holds /dev/null (the device target)" 0 "$BIN" holds /dev/null "${LEDGER_WIN[@]}"
probe "holds /tmp (the directory target)" 0 "$BIN" holds /tmp "${LEDGER_WIN[@]}"
touch "$TMPDIR_B/held file"
probe "holds <temp file> (the no-holder verdict)" 0 \
        "$BIN" holds "$TMPDIR_B/held file" "${LEDGER_WIN[@]}"
probe "holds 53 --since 2s (the explicit width)" 0 "$BIN" holds 53 --since "$LEDGER_SPAN"
probe "holds 53 --since 0s (below the floor: the clamp note rides the dump)" 0 \
        "$BIN" holds 53 --since 0s
probe "holds 53 --since 2h (the ceiling note: instant, a port target is snapshot by nature)" 0 \
        "$BIN" holds 53 --since 2h
probe_fail "holds 0 refusal" "invalid port" "$BIN" holds 0
probe_fail "holds 65536 refusal" "invalid port" "$BIN" holds 65536
probe_fail "holds missing-path refusal (the house shape)" "path not found" \
        "$BIN" holds "$TMPDIR_B/missing path"
probe_json "holds --print-json field map (file target)" \
        'd["subject"], type(d["measured"]) is list, bool(d["verdict"]["supports"])' \
        "$BIN" holds /etc/resolv.conf --print-json "${LEDGER_WIN[@]}"
probe_json "holds --print-json (port target)" \
        'd["subject"], type(d["measured"]) is list' \
        "$BIN" holds 53 --print-json "${LEDGER_WIN[@]}"

# ═════════════════════════════════════════════════════════════════════════
rail "SW6. touch (file, dir, device, symlink, the clamps, the JSON lanes)"
# ═════════════════════════════════════════════════════════════════════════
touch "$TMPDIR_B/touched file"
probe "touch <file>" 0 "$BIN" touch "$TMPDIR_B/touched file" "${LEDGER_WIN[@]}"
mkdir -p "$TMPDIR_B/touched dir"
probe "touch <dir>" 0 "$BIN" touch "$TMPDIR_B/touched dir" "${LEDGER_WIN[@]}"
probe "touch /etc/hosts" 0 "$BIN" touch /etc/hosts "${LEDGER_WIN[@]}"
probe "touch /dev/null (the device target)" 0 "$BIN" touch /dev/null "${LEDGER_WIN[@]}"
ln -sf /etc/hosts "$TMPDIR_B/touched link"
probe_warn "touch <symlink> (the link lane, recorded)" "$BIN" touch "$TMPDIR_B/touched link" \
        "${LEDGER_WIN[@]}"
probe_warn "touch 22 (a port arg on a path-only verb, recorded)" "$BIN" touch 22
probe "touch /etc/hosts --since 2s (the explicit width)" 0 \
        "$BIN" touch /etc/hosts --since "$LEDGER_SPAN"
probe "touch /etc/hosts --since 0s (below the floor: the clamp note rides the dump)" 0 \
        "$BIN" touch /etc/hosts --since 0s
# the 2h ceiling probe is deliberately absent on this live verb: a
# live verb watches its clamped width in full, so the ceiling note is
# proven on the snapshot lanes instead (SW3 port, SW5 holds 53).
probe_fail "touch missing-path refusal (the house shape)" "path not found" \
        "$BIN" touch "$TMPDIR_B/missing path"
probe_json "touch --print-json field map" \
        'd["subject"], type(d["measured"]) is list, d["verdict"]["supports"]' \
        "$BIN" touch /etc/hosts --print-json "${LEDGER_WIN[@]}"

# ═════════════════════════════════════════════════════════════════════════
rail "SW7. why (trace, raw, the JSON conflicts, the clamps)"
# ═════════════════════════════════════════════════════════════════════════
probe "why /etc/passwd" 0 "$BIN" why /etc/passwd "${LEDGER_WIN[@]}"
probe "why /dev/null (the device target)" 0 "$BIN" why /dev/null "${LEDGER_WIN[@]}"
probe "why 53 (the port target)" 0 "$BIN" why 53 "${LEDGER_WIN[@]}"
probe "why --trace (the explainability ladder)" 0 \
        "$BIN" why /etc/passwd --trace "${LEDGER_WIN[@]}"
probe "why --trace --raw (the kernel events)" 0 \
        "$BIN" why /etc/passwd --trace --raw "${LEDGER_WIN[@]}"
probe_fail "why --print-json --trace (conflict)" "cannot be used" \
        "$BIN" why /etc/passwd --print-json --trace
probe_fail "why --print-json --raw (conflict)" "cannot be used" \
        "$BIN" why /etc/passwd --print-json --raw
probe "why /etc/passwd --since 2s (the explicit width)" 0 \
        "$BIN" why /etc/passwd --since "$LEDGER_SPAN"
probe "why /etc/passwd --since 0s (below the floor: the clamp note rides the dump)" 0 \
        "$BIN" why /etc/passwd --since 0s
# the 2h ceiling probe is deliberately absent on this live verb: the
# ceiling note is proven on the snapshot lanes (SW3 port, SW5 holds 53).
probe_fail "why 0 refusal" "invalid port" "$BIN" why 0
probe_fail "why missing-path refusal (the remedy suffix stays why's own)" "not found" \
        "$BIN" why "$TMPDIR_B/missing path"
probe_json "why --print-json field map" \
        'd["subject"], type(d["measured"]) is list, type(d["unaccounted"]) is list, d["verdict"]["supports"]' \
        "$BIN" why /etc/passwd --print-json "${LEDGER_WIN[@]}"

# ═════════════════════════════════════════════════════════════════════════
rail "SW8. doctor (readiness, the symptom estate, the JSON lanes, the privileged lane)"
# ═════════════════════════════════════════════════════════════════════════
probe "doctor (the readiness check)" 0 "$BIN" doctor
probe_fail "doctor --raw without --symptom (the named refusal)" "--symptom" "$BIN" doctor --raw
for symptom in ram cpu disk network gpu slow; do
        probe "doctor --symptom $symptom" 0 "$BIN" doctor --symptom "$symptom"
done
probe "doctor --symptom ram --raw (the drill-down)" 0 "$BIN" doctor --symptom ram --raw
probe_fail "doctor --symptom xyz (the vocabulary echo)" "xyz" "$BIN" doctor --symptom xyz
probe_fail "doctor --attach --symptom ram (conflict)" "cannot be used" \
        "$BIN" doctor --attach --symptom ram
probe_fail "doctor --attach --detach (conflict)" "cannot be used" "$BIN" doctor --attach --detach
probe_fail "doctor --print-json --raw (conflict)" "cannot be used" "$BIN" doctor --print-json --raw
probe_fail "doctor --print-json --attach (conflict)" "cannot be used" \
        "$BIN" doctor --print-json --attach
probe_json "doctor --print-json field map" \
        'd["os"], d["kernel"], d["ebpf_lane"], d["summary"]["ok"] >= 0' \
        "$BIN" doctor --print-json
probe_json "doctor --symptom ram JSON" \
        'type(d["processes"]) is list, d["memory"]["total_bytes"] > 0' \
        "$BIN" doctor --symptom ram --print-json

SWEEP_ROOT="${ZEJTRON_SWEEP_ROOT:-${ZEJTRON_BATTERY_ROOT:-0}}"
if [ "$SWEEP_ROOT" = "1" ]; then
        probe "doctor --detach (nothing pinned yet: the honest no-op)" 0 "$BIN" doctor --detach
        probe "doctor --attach (the one-shot plant)" 0 "$BIN" doctor --attach
        probe "why after attach (the live event window, the single-UTC gap row)" 0 \
                "$BIN" why /etc/passwd --since "$LEDGER_SPAN"
        probe "port --events-only after attach (the live event window)" 0 \
                "$BIN" port --events-only "${PORT_WIN[@]}"
        probe "doctor --detach (unpin everything, idempotent)" 0 "$BIN" doctor --detach
        probe "doctor --detach again (idempotence)" 0 "$BIN" doctor --detach
else
        probe_skip "doctor --attach / --detach (the privileged lane)"
        probe_warn "doctor --attach (the unprivileged refusal, recorded)" "$BIN" doctor --attach
        probe "doctor --detach (nothing to detach: the honest no-op)" 0 "$BIN" doctor --detach
fi

# ═════════════════════════════════════════════════════════════════════════
rail "SW9. net and sig (the byte determinism, the verdict law)"
# ═════════════════════════════════════════════════════════════════════════
probe "net" 0 "$BIN" net
probe_json "net --print-json field map" \
        'type(d["interfaces"]) is list, type(d["routes"]) is list' \
        "$BIN" net --print-json
"$BIN" sig --print-json >"$S_OUT/sig_a.json" 2>/dev/null
"$BIN" sig --print-json >"$S_OUT/sig_b.json" 2>/dev/null
probe_cmp "sig --print-json twice (byte-identical: the static content law)" \
        "$S_OUT/sig_a.json" "$S_OUT/sig_b.json"
probe_warn "sig (the verdict decides the exit code)" "$BIN" sig
echo ""
echo "+ $BIN sig --print-json   [the signature lane: exit follows the verdict, JSON whole]"
"$BIN" sig --print-json >"$ZSW_JSON" 2>"$ZSW_ERR"
sig_rc=$?
cat "$ZSW_JSON"
sig_err="$(cat "$ZSW_ERR")"
if [ -n "$sig_err" ]; then
        echo "[stderr] $sig_err"
fi
if python3 -c "
import json
with open('$ZSW_JSON') as fh:
    d = json.load(fh)
assert d['depths'] and d['identity'] and d['verdict']
print('[json ok - verdict', d['verdict'], d['verified'], ']')
"; then
        # The verdict decides the honest exit code, not the battery's era
        # (night-dragon-lts-4): AUTHENTIC verifies on a signed tree (exit 0),
        # UNSIGNED refuses on an unsigned tree (exit 1). Either verdict
        # riding its matching exit is the honest shape.
        sig_verdict=$(python3 -c "
import json
with open('$ZSW_JSON') as fh:
    print(json.load(fh).get('verdict', ''))
")
        case "$sig_verdict" in
        AUTHENTIC)
                if [ "$sig_rc" -eq 0 ]; then
                        echo "[exit 0 - the signed verdict verified]"
                        PASS=$((PASS + 1))
                else
                        echo "[exit $sig_rc - verdict AUTHENTIC expects exit 0: MISMATCH]"
                        FAIL=$((FAIL + 1))
                fi
                ;;
        UNSIGNED)
                if [ "$sig_rc" -eq 1 ]; then
                        echo "[exit 1 - the honest unsigned verdict]"
                        PASS=$((PASS + 1))
                else
                        echo "[exit $sig_rc - verdict UNSIGNED expects exit 1: MISMATCH]"
                        FAIL=$((FAIL + 1))
                fi
                ;;
        *)
                echo "[verdict '$sig_verdict' outside the judged set {AUTHENTIC, UNSIGNED}: MISMATCH]"
                FAIL=$((FAIL + 1))
                ;;
        esac
else
        echo "[sig json invalid: MISMATCH]"
        FAIL=$((FAIL + 1))
fi

# ═════════════════════════════════════════════════════════════════════════
rail "SW10. the UX bridge (rescues, redirects, the one-tip contract)"
# ═════════════════════════════════════════════════════════════════════════
probe_fail "help (the muscle-memory redirect)" "--help" "$BIN" help
probe_fail "whoholds (the removed-verb redirect)" "holds" "$BIN" whoholds /etc/resolv.conf
probe_fail "lasttouch (the removed-verb redirect)" "touch" "$BIN" lasttouch /etc/hosts
probe_fail "whyopen (the removed-verb redirect)" "why" "$BIN" whyopen /etc/passwd
probe_fail "envpath (the removed-verb redirect)" "path" "$BIN" envpath sh
probe_fail "stat (the near-miss hint)" "doctor" "$BIN" stat
probe_fail "status (the near-miss hint)" "sig" "$BIN" status
probe_fail "prt (the multi-suggestion)" "unrecognized" "$BIN" prt
probe_warn "zjxq (the unknown verb with no suggestion, recorded)" "$BIN" zjxq
probe_fail "--ME case rescue" "--me" "$BIN" proc --ME
probe_fail "--Print-Json case rescue" "--print-json" "$BIN" proc --Print-Json
probe_fail "--check-updated rescue (top-level only flag)" "--check-update" "$BIN" --check-updated
probe_fail "unknown flag" "unexpected argument" "$BIN" proc --bogus-flag
probe_fail "proc --since (retired lifecycle flag)" "unexpected argument" "$BIN" proc --since 30s
probe_fail "path with no argument" "required arguments" "$BIN" path

# ═════════════════════════════════════════════════════════════════════════
rail "SW11. the pipe law (SIGPIPE, exit 141)"
# ═════════════════════════════════════════════════════════════════════════
"$BIN" doctor | head -1
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
echo "sweep: $PASS passed, $FAIL failed, $WARN recorded, $SKIP skipped"
# The report the operator cannot move or open in their own editor is
# not evidence, it is friction (the battery's law, carried over).
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
        chown "${SUDO_USER}" "$REPORT"
fi
if [ "$FAIL" -gt 0 ]; then
        echo "the report names every mismatch - send the whole file back for the audit"
        exit 1
fi
echo "all expectations held - send $REPORT back for the audit"
