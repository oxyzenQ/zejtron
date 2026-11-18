#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool.
#
# The dependency refresh walk (night-consistent-2): one command that
# sweeps EVERY committed Cargo.toml in the tree - root, ebpf/, fuzz/,
# and any future workspace a test or audit lands in a subfolder -
# without this script or its caller being edited (the night-zen-1
# law, now owning its own file so the workflow stays a one-liner).
#
# The walk excludes target trees, so cache-restored build output can
# never join the lane, and sorts the manifests for a deterministic
# sweep order (the determinism law: the same tree, the same order).
# Each manifest's parent directory becomes the cargo working
# directory, so the lockfile lands beside the manifest that owns it.
#
# Usage:
#   ./scripts/ci/refresh-cargo-deps.sh           run cargo update in
#                                                every detected
#                                                workspace
#   ./scripts/ci/refresh-cargo-deps.sh --check   list the detected
#                                                workspaces and exit
#                                                (no cargo verb)

set -Eeuo pipefail

CHECK_ONLY=0
if [[ "${1:-}" == "--check" ]]; then
	CHECK_ONLY=1
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

# The deterministic manifest walk: every committed Cargo.toml outside
# a target tree, sorted. A manifest the git index does not track still
# sweeps (a scratch workspace is a real workspace), but gitignored
# target output is structurally excluded by the path filter.
workspaces="$(find . -name Cargo.toml -not -path '*/target/*' | sort)"

if [[ -z "$workspaces" ]]; then
	echo "error: no Cargo.toml found under $repo_root" >&2
	exit 1
fi

count=0
while IFS= read -r manifest; do
	dir="$(dirname "$manifest")"
	count=$((count + 1))
	if [[ "$CHECK_ONLY" -eq 1 ]]; then
		echo "workspace $count: $dir"
		continue
	fi
	echo "Refreshing $dir"
	(cd "$dir" && cargo update)
done <<<"$workspaces"

if [[ "$CHECK_ONLY" -eq 1 ]]; then
	echo "$count workspace(s) detected"
else
	echo "Refreshed $count workspace(s)"
fi
