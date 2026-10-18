#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool.
#
# ZEJTRON COMMIT-TIME GATE (the sibling's NIGHT-dinner-1 lineage)
#
# Wired into git via .githooks/pre-commit (core.hooksPath=.githooks,
# self-installed by gate-keepers.sh), so every future commit on a
# clone that ran the wholesale gates once executes this gate even
# when the wholesale run is forgotten.
#
# What it enforces at the moment a commit is created:
#   1. CI actions-pin health (delegated to check-actions-pins.sh,
#      night-improve-8): the freshness of every `uses:` pin against
#      upstream - the actions-pin health contract's one automatic
#      seat. The classification is this engine's major-tier verdict
#      (CURRENT / STALE / AHEAD, plus its honest skip classes); the
#      sibling's MAJOR/MINOR/PATCH table belongs to its bigger sweep
#      and is not this engine's vocabulary.
#
# Advisory by default: pin freshness is a REMOTE fact that needs the
# network and the API's quota right now - a gate that blocks a commit
# on facts it cannot reach would be a dishonest gate. The full
# contract (memoization, timeouts, honesty rules) lives in
# check-actions-pins.sh's header. The escape hatch is git's own:
# --no-verify skips any local hook (a git contract, not a hole).
#
# Usage:
#   bash scripts/gates/check-commit-gate.sh    # the hook's invocation
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

GATE_FAILED=0

if ! bash scripts/gates/check-actions-pins.sh; then
	GATE_FAILED=1
fi

if [ "${GATE_FAILED}" -ne 0 ]; then
	echo "FAIL: commit gate - the actions-pin health seat exited non-zero"
	echo "      (the advisory wiring here can only produce that under a KNOWN-stale"
	echo "      verdict with --strict, which this hook does not pass - if this fires,"
	echo "      the seat's own output above names the verdict)"
	exit 1
fi

echo "OK: commit gate - actions-pin health reported"
