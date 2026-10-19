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
#      the zylaxion commit-gate shape; AUTO-HEALED since
#      night-weekly-maintenance-1): the ebpf/ tree hash must still
#      match ebpf-prebuilt/manifest.toml's pin, the staged object must
#      still be the pinned bytes, the toolchain pin must still match
#      ebpf/rust-toolchain.toml, and the version mirror (root Cargo.toml
#      == ebpf/Cargo.toml == the manifest's [contract] version) must
#      hold. A stale verdict now HEALS instead of failing: the one
#      writer rebuilds the object, rewrites the manifest, and the
#      refreshed lane is staged into THIS commit - "edit ebpf/,
#      commit" carries a fresh lane with no separate manual step (the
#      build-time arm, build/ebpf.rs's auto_heal_prebuilt_lane, does
#      the same for every cargo build). The fail-closed arm remains
#      for the heal's own failure mode - missing prerequisites -
#      because a gate that would ship a stale lane silently is the
#      dishonest gate.
#   2. ebpf/ staged without ebpf-prebuilt/ (night-improve-5): the
#      "refreshed but forgot git add" case - a commit that carries
#      ebpf/ changes without the lane refresh would ship sources the
#      prebuilt object does not describe. Auto-healed the same way:
#      when the on-disk lane already verifies (a regenerator ran
#      earlier, the staging was forgotten) the lane is staged into
#      the commit; when it does not, section 1's heal has already run
#      and the fail-closed arm names the fix.
#   3. CI actions-pin health (delegated to check-actions-pins.sh,
#      night-improve-8): the freshness of every `uses:` pin against
#      upstream - the actions-pin health contract's one automatic
#      seat.
#
# Advisory by default: the actions-pin seat is a REMOTE fact that needs
# the network and the API's quota right now - a gate that blocks a
# commit on facts it cannot reach would be a dishonest gate. Sections
# 1-2 are the opposite class (local, deterministic, quota-free) and so
# they fail the commit when the lane cannot be made fresh. The escape
# hatches are git's own --no-verify and the shared
# ZEJTRON_SKIP_PREBUILT_REGEN=1 (build/ebpf.rs honors the same
# variable), which turns the auto-heal back into the fail-closed
# shape.
#
# Usage:
#   bash scripts/gates/check-commit-gate.sh    # the hook's invocation
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

GATE_FAILED=0

# ── 1. prebuilt parity (auto-heal - one implementation, one truth) ───
# The stale verdict heals through the one writer, the refreshed lane
# rides the commit, and the re-check must pass. The build-time arm
# (build/ebpf.rs's auto_heal_prebuilt_lane) does the same for every
# cargo build. ZEJTRON_SKIP_PREBUILT_REGEN=1 is the shared escape
# hatch: under it the stale verdict fails closed again, the pre-heal
# shape.
if [ "${ZEJTRON_SKIP_PREBUILT_REGEN:-}" = "1" ]; then
	if ! bash scripts/dev/regenerate-ebpf-prebuilt.sh --check; then
		echo "      ZEJTRON_SKIP_PREBUILT_REGEN=1 skips the auto-heal; refresh by hand:"
		echo "        ./scripts/dev/regenerate-ebpf-prebuilt.sh, then git add ebpf-prebuilt"
		GATE_FAILED=1
	fi
elif ! bash scripts/dev/regenerate-ebpf-prebuilt.sh --check; then
	echo "      prebuilt lane stale - regenerating through the one writer..."
	if bash scripts/dev/regenerate-ebpf-prebuilt.sh; then
		git add ebpf-prebuilt
		bash scripts/dev/regenerate-ebpf-prebuilt.sh --check || {
			echo "      the rewrite landed but the re-check still says stale."
			GATE_FAILED=1
		}
		if [ "${GATE_FAILED}" -eq 0 ]; then
			echo "      lane regenerated and staged into this commit."
		fi
	else
		echo "      the regeneration failed (missing prerequisites?) - install the pair:"
		echo "        ./scripts/dev/bootstrap-ebpf.sh, then commit again"
		GATE_FAILED=1
	fi
fi

# ── 2. ebpf/ staged without ebpf-prebuilt/ ──────────────────────────
# The "refreshed but forgot git add" case. A fresh on-disk lane (the
# --check verdict above) is staged into the commit; a stale one was
# already healed or failed in section 1, so this arm only ever names
# the fix when the lane itself could not be made fresh.
if [ -n "$(git diff --cached --name-only -- ebpf/)" ]; then
	if ! git diff --cached --name-only -- ebpf-prebuilt/ | grep -q .; then
		if bash scripts/dev/regenerate-ebpf-prebuilt.sh --check; then
			git add ebpf-prebuilt
			echo "      ebpf-prebuilt was fresh but unstaged - staged it into this commit."
		else
			echo "FAIL: ebpf/ changes are staged but ebpf-prebuilt/ is neither staged nor fresh."
			echo "      The commit would ship sources the prebuilt lane does"
			echo "      not describe. Refresh and stage the lane:"
			echo "        ./scripts/dev/regenerate-ebpf-prebuilt.sh, then"
			echo "          git add ebpf-prebuilt"
			GATE_FAILED=1
		fi
	fi
fi

# ── 3. actions-pin health (advisory, the night-improve-8 seat) ──────
if ! bash scripts/gates/check-actions-pins.sh; then
	GATE_FAILED=1
fi

if [ "${GATE_FAILED}" -ne 0 ]; then
	echo "FAIL: commit gate - see the named sections above"
	echo "      (sections 1-2 fail closed when the prebuilt lane cannot be"
	echo "      made fresh; section 3 is the advisory actions-pin seat, which"
	echo "      can only produce a failure under a KNOWN-stale verdict with"
	echo "      --strict)"
	exit 1
fi

echo "OK: commit gate - prebuilt lane in parity, ebpf/ staged with its lane, actions-pin health reported"
