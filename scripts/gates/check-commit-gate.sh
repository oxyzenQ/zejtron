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
#   1. Prebuilt parity (delegated to
#      scripts/dev/regenerate-ebpf-prebuilt.sh --check, night-improve-5,
#      the zylaxion commit-gate shape): the ebpf/ tree hash must still
#      match ebpf-prebuilt/manifest.toml's pin, the staged object must
#      still be the pinned bytes, the toolchain pin must still match
#      ebpf/rust-toolchain.toml, and the version mirror (root Cargo.toml
#      == ebpf/Cargo.toml == the manifest's [contract] version) must
#      hold. This is the commit-time arm of the prebuilt freshness
#      contract: the shipped object can never silently fall behind the
#      sources it claims to carry.
#   2. ebpf/ staged without ebpf-prebuilt/ (night-improve-5): the
#      "refreshed but forgot git add" case - a commit that carries
#      ebpf/ changes without the lane refresh would ship sources the
#      prebuilt object does not describe. Sections 1-2 fail closed
#      because prebuilt parity is a LOCAL fact: the information is on
#      disk right now, and a gate that had it and stayed silent would
#      be the dishonest gate. The refresh command is named in the
#      failure output - one line, one writer.
#   3. CI actions-pin health (delegated to check-actions-pins.sh,
#      night-improve-8): the freshness of every `uses:` pin against
#      upstream - the actions-pin health contract's one automatic
#      seat.
#
# Advisory by default: the actions-pin seat is a REMOTE fact that needs
# the network and the API's quota right now - a gate that blocks a
# commit on facts it cannot reach would be a dishonest gate. Sections
# 1-2 are the opposite class (local, deterministic, quota-free) and so
# they fail the commit. The escape hatch is git's own: --no-verify
# skips any local hook (a git contract, not a hole).
#
# Usage:
#   bash scripts/gates/check-commit-gate.sh    # the hook's invocation
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

GATE_FAILED=0

# ── 1. prebuilt parity (delegated - one implementation, one truth) ────
# The regenerate script's --check verdict is the same fact the build
# lane's manifest verification and the owner's manual run consult; the
# gate only refuses the commit when it answers "stale".
if ! bash scripts/dev/regenerate-ebpf-prebuilt.sh --check; then
	echo "      refresh the lane with: ./scripts/dev/regenerate-ebpf-prebuilt.sh"
	echo "      then stage it (git add ebpf-prebuilt) and commit again."
	GATE_FAILED=1
fi

# ── 2. ebpf/ staged without ebpf-prebuilt/ ─────────────────────────────
if [ -n "$(git diff --cached --name-only -- ebpf/)" ]; then
	if ! git diff --cached --name-only -- ebpf-prebuilt/ | grep -q .; then
		echo "FAIL: ebpf/ changes are staged but ebpf-prebuilt/ is not."
		echo "      The commit would ship sources the prebuilt lane does"
		echo "      not describe. Refresh and stage the lane:"
		echo "        ./scripts/dev/regenerate-ebpf-prebuilt.sh, then"
		echo "          git add ebpf-prebuilt"
		GATE_FAILED=1
	fi
fi

# ── 3. actions-pin health (advisory, the night-improve-8 seat) ────────
if ! bash scripts/gates/check-actions-pins.sh; then
	GATE_FAILED=1
fi

if [ "${GATE_FAILED}" -ne 0 ]; then
	echo "FAIL: commit gate - see the named sections above"
	echo "      (sections 1-2 fail closed on the prebuilt lane; section 3"
	echo "      is the advisory actions-pin seat, which can only produce a"
	echo "      failure under a KNOWN-stale verdict with --strict)"
	exit 1
fi

echo "OK: commit gate - prebuilt lane in parity, ebpf/ staged with its lane, actions-pin health reported"
