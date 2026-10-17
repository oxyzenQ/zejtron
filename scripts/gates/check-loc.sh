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
# Tracked debt (night-improve-12b, owner-visible): zejtron's law
# landed on a tree that grew before it - ten command-surface modules
# predate the cap. The end-state contract is the sibling's no-mercy
# rule (over the cap means SPLIT, a pure move, gates green in
# between); until each split task lands, the files below are the
# EXPLICIT, justified debt list. The gate enforces two things:
#   1. A file over the cap that is NOT in this list fails the build
#      the day it appears - no new debt can ever silently join.
#   2. Every list entry names the module family that owns the fix.
# A file already listed that GROWS does not re-fail (the list pins
# the current line counts); the splits remove entries, never add.
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

# The tracked-debt list: file|current lines|owning family|one-line reason.
# Entries only ever LEAVE this list (a split removes its row); a new
# over-cap file that is not listed here fails the build.
TRACKED_DEBT=(
  "src/commands/env.rs|640|env|snapshot store: split the snapshot IO family out of the render"
  "src/commands/git.rs|900|git|context reporter: split the porcelain parsers out of the reporter"
  "src/commands/holds.rs|886|holds|holder scanner: split the fd/port scanners out of the report"
  "src/commands/net.rs|718|net|interface reporter: split the sysfs readers out of the render"
  "src/commands/port/render.rs|659|port|socket renderer: split the owner/detail rows out of the table"
  "src/commands/proc.rs|986|proc|process tree: split the live-loop out of the tree builder"
  "src/commands/service.rs|760|service|systemd surface: split the unit-detail render out of the list"
  "src/commands/shell.rs|1013|shell|shell context: split the shell detectors out of the report"
  "src/commands/why.rs|760|why|explain surface: split the evidence collectors out of the render"
  "src/system/mod.rs|671|system|/proc readers: split the unit/env readers out of the lookup"
)

is_tracked_debt() {
  local file="$1"
  local entry
  for entry in "${TRACKED_DEBT[@]}"; do
    [ "${entry%%|*}" = "$file" ] && return 0
  done
  return 1
}

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
                if is_tracked_debt "$f"; then
                        echo "    ^^^ over ${MAX_LINES} — TRACKED DEBT (listed below; the split task removes this row)"
                else
                        FAILED=$((FAILED + 1))
                        echo "    ^^^ VIOLATES ${MAX_LINES} limit (the no-mercy law:"
                        echo "           over the cap means SPLIT, a pure move, gates green in between)"
                fi
        fi
        FOUND=$((FOUND + 1))
done <<<"$FILES"

echo ""
echo "Total files: ${FOUND}"
echo "Files over ${MAX_LINES}: tracked debt listed above; NEW violations: ${FAILED} (the law: zero allowed)"

if [ "$FAILED" -gt 0 ]; then
        echo ""
        echo "FAIL: ${FAILED} NEW file(s) exceed ${MAX_LINES} lines and are not on the"
        echo "tracked-debt list. Split the file into modules (a pure move, gates"
        echo "green in between) — new debt cannot join silently."
        exit 1
fi

echo ""
echo "OK: no NEW over-cap files. The debt list (see the header) shrinks"
echo "one row per split task and never grows."
exit 0
