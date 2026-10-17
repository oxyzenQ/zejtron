#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool.
#
# ZEJTRON RUST SOURCE FILE LOC CHECK
#
# Ensures every Rust source file in the tree stays under the hard LOC
# cap. Owner rule (the sibling's NIGHT-improve-44 lineage): the cap is
# 600 lines, it applies to EVERY tracked *.rs file ANYWHERE in the
# tree — the checker walks the whole git index, not a hand-listed
# directory set.
#
# No mercy (night-improve-18, the masterclass discipline): the
# tracked-debt era is over. The ten founding command-surface modules
# are split (holds/procfs, proc/forest, and the whole test/ tree
# relocation that shrank the rest under the cap), so the debt list is
# retired whole: over the cap means FAIL — SPLIT, a pure move, gates
# green in between. There is no list to join, no row to pin, no
# grandfather clause.
#
# Single-file policy (night-improve-14, the sibling's src/ root law,
# now ENFORCED - the grandfather clause is lifted): src/ root carries
# ONLY main.rs. Every other module lives in a directory group (cli/,
# commands/, info/, output/, system/, update/), the zelynic shape.
# The gate below fails the build the day a stray *.rs file joins
# src/ root again.
#
# Usage: scripts/gates/check-loc.sh [MAX_LINES]
#   MAX_LINES: override the default limit (default: 600)
#
# Platform: UNIX-only (uses `git`, `wc -l`). Not for Windows cmd.exe.

set -euo pipefail

MAX_LINES="${1:-600}"
FAILED=0
FOUND=0

echo "Rust source file line counts, tree-wide by type (max ${MAX_LINES}):"
echo ""

# NIGHT-improve-44: autodetect by FILE TYPE, not by directory. Every
# git-tracked *.rs file anywhere in the repo (plus untracked-but-
# present, respecting .gitignore, so a new over-cap file fails BEFORE
# the commit — the pre-commit proxy parity discipline
# check-headers.sh set). Cargo build dirs are excluded by .gitignore
# already; the guard below is defensive.
FILES=$(git ls-files --cached --others --exclude-standard -- '*.rs' 2>/dev/null |
        grep -v -E '^(target|ebpf/target)/' | sort)

if [ -z "$FILES" ]; then
        echo "No .rs files found in the tree"
        exit 0
fi

# night-improve-14: the src/ root single-file policy. Only main.rs may
# sit at src/ root - every other module rides a directory group. A
# stray root-level file fails the build, so the flat layout can never
# grow back.
STRAY_ROOT=$(printf '%s\n' "$FILES" | grep -E '^src/[^/]+\.rs$' | grep -v '^src/main\.rs$' || true)
if [ -n "$STRAY_ROOT" ]; then
        echo "FAIL: src/ root single-file policy (night-improve-14):"
        printf '%s\n' "$STRAY_ROOT" | sed 's/^/  stray: /'
        echo "  Only src/main.rs may live at src/ root; move the file into"
        echo "  its directory group (cli/, commands/, info/, output/, system/,"
        echo "  update/) and wire the hub mod.rs."
        exit 1
fi

# Compute and display line counts sorted descending
while IFS= read -r f; do
        LINES=$(wc -l <"$f")
        printf "  %5d  %s\n" "$LINES" "$f"
        if [ "$LINES" -gt "$MAX_LINES" ]; then
                FAILED=$((FAILED + 1))
                echo "    ^^^ VIOLATES ${MAX_LINES} limit (the no-mercy law:"
                echo "           over the cap means SPLIT, a pure move, gates green in between)"
        fi
        FOUND=$((FOUND + 1))
done <<<"$FILES"

echo ""
echo "Total files: ${FOUND}"
echo "Files over ${MAX_LINES}: ${FAILED} (the no-mercy law: zero allowed)"

if [ "$FAILED" -gt 0 ]; then
        echo ""
        echo "FAIL: ${FAILED} file(s) exceed ${MAX_LINES} lines. Split the file into"
        echo "modules (a pure move, gates green in between) - there is no debt"
        echo "list to join and no grandfather clause."
        exit 1
fi

echo ""
echo "OK: every Rust file in the tree rides under the ${MAX_LINES}-line cap."
exit 0
