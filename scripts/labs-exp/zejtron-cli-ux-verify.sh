# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# shellcheck shell=bash
# OS: Linux only - zejtron is a Linux introspection tool.
#
# labs-exp/zejtron-cli-ux-verify.sh - the CLI UX hardening verifier
# (night-total-hardening-1 follow-up).
#
# Runs the complete usage-error contract against a zejtron binary so
# the owner can verify the fixes on any machine in one shot. Every
# check names the contract it pins; the exit code is the verdict
# (0 = all green).
#
# The binary resolves through the shared estate law
# (lib/zejtron-bin.sh): an explicit argument wins, then
# $ZEJTRON_BIN_PATH, then discovery under the repo's target/ tree -
# the profile-named lanes (pro-native-musl and friends) rank above
# the basic release dir, the newest executable wins within a tier.
#
# Usage:
#   scripts/labs-exp/zejtron-cli-ux-verify.sh [path-to-binary]
#   ZEJTRON_BIN_PATH=/path/to/zejtron scripts/labs-exp/zejtron-cli-ux-verify.sh

set -u

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd) || exit 1
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd) || exit 1

# The shared resolver (one authority for every script that exercises
# the binary): explicit arg, then ZEJTRON_BIN_PATH, then target
# discovery with the profile-over-basic preference.
# shellcheck source=../lib/zejtron-bin.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/zejtron-bin.sh"

zejtron_resolve_bin BIN "$REPO_ROOT" "${1:-}"
if [[ -z "$BIN" || ! -x "$BIN" ]]; then
        echo "verify: no zejtron binary found (tried the argument, ZEJTRON_BIN_PATH, and target/ discovery)" >&2
        echo "verify: build one first - cargo build --release (or scripts/build.sh check-all)" >&2
        exit 2
fi
echo "verify: binary $BIN"

PASS=0
FAIL=0

# expect_exit <expected-code> <description> <args...>
expect_exit() {
        local want="$1" desc="$2"
        shift 2
        "$BIN" "$@" >/dev/null 2>&1
        local got=$?
        if [[ "$got" -eq "$want" ]]; then
                echo "PASS exit=$want : $desc"
                PASS=$((PASS + 1))
        else
                echo "FAIL exit=$got (want $want) : $desc"
                FAIL=$((FAIL + 1))
        fi
}

# expect_tip <needle> <description> <args...>
# The tip line must exist (a rescue fired) - the one-tip contract is
# checked separately, so exactly-one-tip is not asserted here.
expect_tip() {
        local needle="$1" desc="$2"
        shift 2
        local out
        out=$("$BIN" "$@" 2>&1 >/dev/null)
        if [[ "$out" == *"$needle"* ]]; then
                echo "PASS tip '$needle' : $desc"
                PASS=$((PASS + 1))
        else
                echo "FAIL tip '$needle' missing : $desc"
                FAIL=$((FAIL + 1))
        fi
}

# expect_no_tip <needle> <description> <args...>
expect_no_tip() {
        local needle="$1" desc="$2"
        shift 2
        local out
        out=$("$BIN" "$@" 2>&1 >/dev/null)
        if [[ "$out" != *"$needle"* ]]; then
                echo "PASS absent '$needle' : $desc"
                PASS=$((PASS + 1))
        else
                echo "FAIL found '$needle' : $desc"
                FAIL=$((FAIL + 1))
        fi
}

# expect_output <needle> <description> <args...>
expect_output() {
        local needle="$1" desc="$2"
        shift 2
        local out
        out=$("$BIN" "$@" 2>/dev/null)
        if [[ "$out" == *"$needle"* ]]; then
                echo "PASS output '$needle' : $desc"
                PASS=$((PASS + 1))
        else
                echo "FAIL output '$needle' missing : $desc"
                FAIL=$((FAIL + 1))
        fi
}

echo "-- 1. the ceiling wording (the pro-mode row sync) --"
expect_output "(0-1000000)" "--limit row mirrors the CLI struct" -h
expect_output "(1-1024)" "--depth row mirrors the CLI struct" -h
expect_no_tip "default 20)" "stale --limit wording is gone" -h
expect_no_tip "minimum 1)" "stale --depth wording is gone" -h

echo "-- 2. the case-variant subcommand rescue --"
expect_tip "a similar subcommand exists: 'port'" "PORT names the real verb" PORT
expect_tip "a similar subcommand exists: 'holds'" "WHOHOLDS lands on the successor" WHOHOLDS
expect_exit 2 "case-variant verbs stay usage errors" PORT

echo "-- 3. clap's own tips survive (the fallback never doubles) --"
expect_tip "a similar subcommand exists: 'proc'" "prco keeps clap's own tip" prco

echo "-- 4. the migration redirects (exact spellings) --"
expect_tip "'holds'" "whoholds redirects to holds" whoholds
expect_tip "'touch'" "lasttouch redirects to touch" lasttouch
expect_tip "'why'" "whyopen redirects to why" whyopen
expect_tip "'path'" "envpath redirects to path" envpath
expect_tip "zejtron --help" "help lands on the reference" help

echo "-- 5. the non-UTF-8 argv contract (no panic) --"
expect_exit 2 "invalid UTF-8 is a usage error, not exit 101" holds $'\xff'
rendered=$("$BIN" holds $'\xff' 2>&1 >/dev/null || true)
if [[ "$rendered" == *"invalid UTF-8"* ]] && [[ "$rendered" != *"panicked"* ]]; then
        echo "PASS clean render : the UTF-8 refusal renders, no backtrace note"
        PASS=$((PASS + 1))
else
        echo "FAIL render : $rendered"
        FAIL=$((FAIL + 1))
fi

echo "-- 6. the case-variant flag rescue (proc lane) --"
expect_tip "a similar argument exists: '--me'" "proc --ME names the real flag" proc --ME
expect_tip "a similar argument exists: '--depth'" "proc --Depth rescues" proc --Depth

echo "-- 7. the top-level authority rescue --"
expect_tip "--check-update" "subcommand-scoped --check-updated names the top level" proc --check-updated

echo "-- 8. the one-tip contract (rescued errors carry exactly one tip) --"
for probe in PORT WHOHOLDS; do
        tips=$("$BIN" "$probe" 2>&1 >/dev/null | grep -c "tip: " || true)
        if [[ "$tips" -eq 1 ]]; then
                echo "PASS one tip : $probe"
                PASS=$((PASS + 1))
        else
                echo "FAIL tip count $tips : $probe"
                FAIL=$((FAIL + 1))
        fi
done

echo "-- 9. the exit-code law (help 0, usage 2, runtime 1) --"
expect_exit 0 "-h exits 0" -h
expect_exit 0 "--help exits 0" --help
expect_exit 0 "-V exits 0 on stdout" -V
expect_exit 0 "verb -V short-circuits before required args" path -V
expect_exit 1 "runtime failure keeps exit 1" path /definitely/not/a/real/command-xyz

echo
echo "== verdict: $PASS passed, $FAIL failed =="
if [[ "$FAIL" -eq 0 ]]; then
        echo "ALL GREEN - the CLI UX contract holds."
        exit 0
fi
exit 1
