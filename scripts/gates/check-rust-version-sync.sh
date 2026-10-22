#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool; no other OS is supported.
#
# ZEJTRON RUST VERSION SYNC CHECK
#
# Verifies the Rust toolchain version is consistent across all sources:
#   1. rust-toolchain.toml  (channel = "X.Y.Z" — authoritative source)
#   2. Cargo.toml           (rust-version = "X.Y" — MSRV)
#   3. .github/workflows/*.yml (RUST_VERSION: "X.Y.Z" — CI install pin)
#
# Fails if any source disagrees with the others. The write counterpart
# is `scripts/dev/version-to.sh` (the owner-facing release bumper) and
# a manual three-site bump for the toolchain pins (rust-toolchain.toml,
# Cargo.toml MSRV, every workflow RUST_VERSION).
#
# Workflows without a RUST_VERSION declaration are out of scope by policy:
#   audit.yml — security scanning only, builds nothing, any recent
#     toolchain works (same skip policy cosmostrix applies to miri/docs-ci).
#
# Usage: bash scripts/gates/check-rust-version-sync.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# ── 1. rust-toolchain.toml (authoritative) ──
TOOLCHAIN_FILE="rust-toolchain.toml"
if [ ! -f "$TOOLCHAIN_FILE" ]; then
	echo "FAIL: $TOOLCHAIN_FILE not found"
	exit 1
fi
FULL_VERSION=$(grep '^channel = ' "$TOOLCHAIN_FILE" | sed 's/channel = "\(.*\)".*/\1/')
if [ -z "$FULL_VERSION" ]; then
	echo "FAIL: could not parse channel from $TOOLCHAIN_FILE"
	exit 1
fi

# A channel alias means the dormant-mode pin is broken (a future stable
# release could silently change the toolchain). Reject it loudly.
if [[ "$FULL_VERSION" == "stable" || "$FULL_VERSION" == "beta" || "$FULL_VERSION" == nightly* ]]; then
	echo "FAIL: rust-toolchain.toml channel = \"$FULL_VERSION\" is a channel alias."
	echo "      Dormant-mode policy requires a concrete X.Y.Z pin."
	exit 1
fi

# Extract major.minor (strip patch) for MSRV comparison
MSRV_EXPECTED="${FULL_VERSION%.*}"
if [ -z "$MSRV_EXPECTED" ]; then
	echo "FAIL: could not derive MSRV from full version '$FULL_VERSION'"
	exit 1
fi

echo "Authoritative source: rust-toolchain.toml channel = \"$FULL_VERSION\""
echo "Expected MSRV (major.minor): $MSRV_EXPECTED"
echo ""

FAILED=0

# ── 2. Cargo.toml ──
# The sibling manifest pins MSRV as major.minor ("1.98"); zejtron
# pins the full triple ("1.98.1") so the manifest and the toolchain
# channel cannot drift even on a patch release. Both shapes are
# accepted; a real drift (any other value) still fails.
CARGO_MSRV=$(grep '^rust-version = ' Cargo.toml | sed 's/rust-version = "\(.*\)".*/\1/')
if [ "$CARGO_MSRV" != "$FULL_VERSION" ] && [ "$CARGO_MSRV" != "$MSRV_EXPECTED" ]; then
	echo "FAIL: Cargo.toml rust-version = \"$CARGO_MSRV\" — expected \"$FULL_VERSION\" (or major.minor \"$MSRV_EXPECTED\")"
	FAILED=$((FAILED + 1))
else
	echo "OK: Cargo.toml rust-version = \"$CARGO_MSRV\""
fi

# ── 3. .github/workflows/*.yml ──
for wf in .github/workflows/*.yml; do
	[ -f "$wf" ] || continue
	# Skip audit.yml (security scanner, no build, no pinned toolchain).
	[ "$(basename "$wf")" = "audit.yml" ] && continue

	if grep -q 'RUST_VERSION:' "$wf"; then
		# Every RUST_VERSION match rides the check - the first one
		# alone let a drifted later pin hide behind it
		# (night-total-lts-2).
		while IFS= read -r WF_VERSION; do
			[ -z "$WF_VERSION" ] && continue
			if [ "$WF_VERSION" != "$FULL_VERSION" ]; then
				echo "FAIL: $wf RUST_VERSION = \"$WF_VERSION\" — expected \"$FULL_VERSION\""
				FAILED=$((FAILED + 1))
			else
				echo "OK: $wf RUST_VERSION = \"$WF_VERSION\""
			fi
		done < <(grep 'RUST_VERSION:' "$wf" | sed 's/.*RUST_VERSION: *"\(.*\)".*/\1/')
	fi

	# The quoted-literal `toolchain: "X.Y.Z"` install pins
	# (night-total-lts-2): release/crates-io/supermassive spell
	# their pins this way, so a drift was invisible to the
	# RUST_VERSION spelling. Channel aliases (stable, nightly) and
	# matrix references stay out of scope - they are deliberate
	# moving lanes, not pins.
	while IFS= read -r WF_TOOLCHAIN; do
		[ -z "$WF_TOOLCHAIN" ] && continue
		if [ "$WF_TOOLCHAIN" != "$FULL_VERSION" ]; then
			echo "FAIL: $wf toolchain pin = \"$WF_TOOLCHAIN\" — expected \"$FULL_VERSION\""
			FAILED=$((FAILED + 1))
		else
			echo "OK: $wf toolchain pin = \"$WF_TOOLCHAIN\""
		fi
	done < <(grep -E '^[[:space:]]*toolchain: *"[0-9]+\.[0-9]+' "$wf" | sed 's/.*toolchain: *"\(.*\)".*/\1/')
done

# ── 4. The eBPF tool pin constants ──
# BPF_LINKER_VERSION lives in three sites, B3SUM_VERSION in three
# (bootstrap-ebpf.sh, regenerate-ebpf-prebuilt.sh, and the
# Gate-keepers workflow's b3sum install step); the in-file comments
# demand lockstep bumps, so the lockstep is enforced here instead of
# trusted (night-total-lts-2).
check_pin() {
	local name="$1"
	shift
	local expected=""
	local file value
	for file in "$@"; do
		# The first line that names the constant AND carries a
		# quoted number: comment mentions of the name (the
		# lockstep notes) carry no number and are skipped.
		value=$(grep -m1 "${name}.*\"[0-9]" "$file" | sed 's/.*"\([0-9][^"]*\)".*/\1/')
		if [ -z "$expected" ]; then
			expected="$value"
			echo "OK: ${name} = \"${expected}\" (${file})"
		elif [ "$value" != "$expected" ]; then
			echo "FAIL: ${file} ${name} = \"${value}\" — expected \"${expected}\""
			FAILED=$((FAILED + 1))
		fi
	done
}
check_pin "BPF_LINKER_VERSION" build/ebpf.rs scripts/dev/bootstrap-ebpf.sh scripts/dev/regenerate-ebpf-prebuilt.sh
check_pin "B3SUM_VERSION" scripts/dev/bootstrap-ebpf.sh scripts/dev/regenerate-ebpf-prebuilt.sh .github/workflows/gate-keepers.yml

echo ""
if [ "$FAILED" -gt 0 ]; then
	echo "FAIL: $FAILED source(s) out of sync"
	echo ""
	echo "To fix: bump rust-toolchain.toml AND Cargo.toml AND every"
	echo "workflow RUST_VERSION pin together."
	exit 1
else
	echo "OK: all Rust version sources in sync"
	exit 0
fi
