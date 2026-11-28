#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial
# OS: Linux only — zejtron is a Linux introspection tool.
#
# ZEJTRON PACKAGE-SIZE CAP CHECK (night-cafe-mclaren-5)
#
# The registry upload size is a hard external contract: crates.io
# refuses an oversized .crate with HTTP 413 Payload Too Large (max
# upload 10485760 bytes). The sibling estate already lost a publish
# to exactly that answer (cosmostrix v100.1.3-dragon.2, dead in
# 1m36s: a demo webp grew to 9,217,878 bytes while the [package]
# exclude lane covered assets/*.gif and assets/*.png but not
# *.webp, pushing the tarball to ~11.25 MiB). zejtron's manifest
# carries the curated include allowlist instead of an exclude lane -
# the branding assets are repo-only - so the axis that killed the
# sibling publish is structurally closed here; what no lane measured
# was the artifact itself. A dependency jump, a wider include lane,
# or a heavyweight doc would walk the tarball over the cap and fail
# the class at the one seat that cannot rehearse: the registry.
# This gate builds the real .crate (metadata + packaging only, no
# verify build) and asserts its byte count against the documented
# server cap, so the refusal class fails in the gate in seconds
# instead of in the publish job.
#
# Equality with the cap fails too: the server's exact boundary
# behaviour at 10485760 bytes is not part of this contract, headroom
# is. The measured tarball must be the publish candidate, so the
# gate refuses to run over a dirty tree - untracked or modified
# files change the bytes the gate measures, and a size verdict over
# a tree that will never publish is a lie.
#
# Seats: gate-keepers.sh section 21 (every push and PR; the CI seat
# installs the pinned toolchain) and the crates-io.yml ship-set job
# (the same verdict at the tree the release tag names, ahead of the
# compile-heavy dry run and the publish step).
#
# Usage: bash scripts/gates/check-package-size.sh
# Output: one verdict block; exit 0 under the cap / exit 1 at or
# over it.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# crates.io's documented max upload size (the 413 answer quotes it).
CAP=10485760

if ! command -v cargo >/dev/null 2>&1; then
	echo "FAIL: cargo not found on PATH - the gate measures the real"
	echo ".crate bytes, which requires the packaging machinery."
	exit 1
fi

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
if [ -z "$VERSION" ]; then
	echo "FAIL: no package version line found in Cargo.toml"
	exit 1
fi

CRATE="target/package/zejtron-${VERSION}.crate"
rm -f "$CRATE"

if ! cargo package --locked --no-verify >/dev/null 2>&1; then
	echo "FAIL: cargo package --locked --no-verify refused the tree. The"
	echo "gate refuses dirty trees on purpose (untracked or modified"
	echo "files change the measured bytes) - commit or restore the"
	echo "working tree, then re-run this gate."
	exit 1
fi

if [ ! -f "$CRATE" ]; then
	echo "FAIL: expected $CRATE was not produced by cargo package"
	exit 1
fi

BYTES=$(wc -c <"$CRATE" | tr -d ' ')
MIB=$(awk -v b="$BYTES" 'BEGIN { printf "%.2f", b / 1048576 }')

# The five largest members of the tarball - the diagnostic that
# names the heavyweight without opening anything. A .crate is a
# gzipped tar with one top-level zejtron-<version>/ directory; the
# -tv listing's size column is field 3 and the member path field 6.
LARGEST=$(tar -tvzf "$CRATE" | awk '{print "  " $3, $6}' | sort -rn | head -5)

if [ "$BYTES" -ge "$CAP" ]; then
	OVER=$(awk -v b="$BYTES" 'BEGIN { printf "%.2f", (b - 10485760) / 1048576 }')
	echo "FAIL: zejtron-${VERSION}.crate is ${BYTES} bytes (${MIB} MiB)"
	echo "- at or over the crates.io hard upload cap of ${CAP} bytes"
	echo "(10 MiB), over by ${OVER} MiB. The registry answers such an"
	echo "upload with HTTP 413 Payload Too Large. The largest members:"
	echo "${LARGEST}"
	echo "Heal: trim the Cargo.toml [package] include lane or slim what"
	echo "it carries (cargo package --list shows the ship set)."
	exit 1
fi

HEADROOM=$(awk -v b="$BYTES" 'BEGIN { printf "%.2f", (10485760 - b) / 1048576 }')
echo "OK: zejtron-${VERSION}.crate is ${BYTES} bytes (${MIB} MiB),"
echo "under the crates.io hard upload cap of ${CAP} bytes (10 MiB) with"
echo "${HEADROOM} MiB headroom. Largest members:"
echo "${LARGEST}"
