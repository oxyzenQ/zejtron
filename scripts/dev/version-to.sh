#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool.
# Single-crate repo note (sibling-manifest lineage, retargeted by
# night-improve-5): the root pair (Cargo.toml + Cargo.lock) is the
# root version surface, and the detached ebpf/ workspace carries its
# OWN manifest pair that mirrors the root version (the mirror law:
# root == ebpf == the prebuilt lane's [contract] version). The bump
# below rewrites all of them, then refreshes the prebuilt lane
# fail-closed through its one writer - the zylaxion night-dinner-8
# shape: a version bump always stales the lane's pins (the ebpf/ tree
# hash covers ebpf/Cargo.toml and ebpf/Cargo.lock), so the bump
# invocation regenerates the lane instead of leaving the commit to
# fail the parity gate.
# CHANGELOG.md earns its release line (sibling lineage: a bump is a
# release event - the ledger records it the same way the Cargo files
# do: a bare version line under "## [Released]", newest first,
# pre-release and stable alike, above "## [Unreleased]". Probed
# honestly: a missing file, a missing anchor, a version the ledger
# already carries, or a non-standard Released shape warns and writes
# nothing - never claim a write that did not happen, and a ledger
# this script did not create is not one it rewrites).
# The input gate carries the release lane's full tag contract
# (night-improve-9): release.yml validates a v-prefixed semver with an
# OPTIONAL pre-release suffix (vX.Y.Z or vX.Y.Z-prerelease - the
# rc/alpha/beta/dev shapes its previous-tag boundary and --prerelease
# lanes consume), so the version manager accepts the same shape and
# every rewrite lane below consumes an optional OLD-version suffix:
# a tree sitting on v12.0.0-rc.1 bumps to v12.0.0-rc.2 or to v12.0.0
# with no stale -rc.N tail riding the rewritten surfaces.

set -Eeuo pipefail

error() {
	echo "error: $*" >&2
	exit 1
}

if [[ $# -ne 1 ]]; then
	error "usage: ./scripts/dev/version-to.sh vX.Y.Z[-pre]"
fi

input="$1"
# Stable and pre-release alike: the suffix charset mirrors the
# sibling's validate_version lane (-[A-Za-z0-9.], e.g. -rc.1, -alpha.2,
# -beta.3) - the same shape release.yml validates at tag time.
if [[ "$input" =~ ^v?([0-9]+)\.([0-9]+)\.([0-9]+)(-([A-Za-z0-9.]+))?$ ]]; then
	VERSION="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}"
	if [[ -n "${BASH_REMATCH[5]:-}" ]]; then
		VERSION="${VERSION}-${BASH_REMATCH[5]}"
	fi
	TAG="v${VERSION}"
else
	error "version must be semver: vX.Y.Z or vX.Y.Z-pre (e.g. vX.Y.Z-rc.1)"
fi

for command in git cargo; do
	if ! command -v "$command" >/dev/null 2>&1; then
		error "required command not found: $command"
	fi
done

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

[[ -f Cargo.toml ]] || error "Cargo.toml not found"
[[ -f Cargo.lock ]] || error "Cargo.lock not found"
[[ -f README.md ]] || error "README.md not found"
[[ -f docs/workflow/about-ci.md ]] || error "docs/workflow/about-ci.md not found"

# Record the release in CHANGELOG.md's ledger (## [Released], newest
# first). The probes mirror the sibling project's ledger writer:
# every non-standard state warns and writes nothing instead of
# claiming a rewrite that did not happen.
changelog_release() {
	local ver="v$1"
	if [[ ! -f CHANGELOG.md ]]; then
		echo "  ! CHANGELOG.md        -> file absent, nothing to write"
		return 0
	fi
	# A version line never repeats: the re-run at a version the ledger
	# already carries (the usual stale-tree re-entry) writes nothing.
	if grep -qxF "${ver}" CHANGELOG.md; then
		echo "  ! CHANGELOG.md        -> ${ver} already recorded, nothing to write"
		return 0
	fi
	local tmp
	tmp="$(mktemp)"
	if grep -q '^## \[Released\]$' CHANGELOG.md; then
		# The section exists. This tool's own shape puts one blank
		# spacer between the heading and the version lines - the new
		# version splices in under it, above the current top line.
		if [[ -z "$(sed -n '/^## \[Released\]$/{n;p;}' CHANGELOG.md)" ]]; then
			awk -v ver="${ver}" '
        /^## \[Released\]$/ && !done {
          print
          getline spacer
          print spacer
          print ver
          done = 1
          next
        }
        { print }
      ' CHANGELOG.md >"${tmp}"
			mv "${tmp}" CHANGELOG.md
			chmod 644 CHANGELOG.md
			echo "  OK CHANGELOG.md        -> ${ver} (## [Released], newest first)"
		else
			rm -f "${tmp}"
			echo "  ! CHANGELOG.md        -> unexpected ## [Released] shape (no blank spacer under the heading) - nothing to write"
		fi
	else
		# No section yet - create it above "## [Unreleased]" (the
		# unreleased work keeps its own section below the ledger).
		if grep -q '^## \[Unreleased\]$' CHANGELOG.md; then
			awk -v ver="${ver}" '
        /^## \[Unreleased\]$/ && !done {
          print "## [Released]"
          print ""
          print ver
          print ""
          done = 1
        }
        { print }
      ' CHANGELOG.md >"${tmp}"
			mv "${tmp}" CHANGELOG.md
			chmod 644 CHANGELOG.md
			echo "  OK CHANGELOG.md        -> ${ver} (section created above ## [Unreleased])"
		else
			rm -f "${tmp}"
			echo "  ! CHANGELOG.md        -> no ## [Unreleased] anchor found - nothing to write"
		fi
	fi
}

echo "Updating zejtron to ${TAG}"

sed -i -E 's/^version = "[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?"/version = "'"${VERSION}"'"/' Cargo.toml
cargo update -p zejtron

# The mirror law (night-improve-5): the detached ebpf/ workspace and
# the prebuilt lane's manifest follow the root version in the same
# invocation - never a half-mirrored tree.
sed -i -E 's/^version = "[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?"/version = "'"${VERSION}"'"/' ebpf/Cargo.toml
(cd ebpf && cargo update -p zejtron-ebpf --offline)
./scripts/dev/regenerate-ebpf-prebuilt.sh

sed -i -E 's/^TAG=v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?/TAG='"${TAG}"'/' README.md docs/workflow/about-ci.md
sed -i -E 's#(zejtron-)v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?(-linux-)#\1'"${TAG}"'\3#g' README.md docs/workflow/about-ci.md
sed -i -E 's#(/download/)v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?/#\1'"${TAG}"'/#g' README.md docs/workflow/about-ci.md
sed -i -E 's#(git tag -a )v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?#\1'"${TAG}"'#g' docs/workflow/about-ci.md
sed -i -E 's#(git tag -a v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)? -m ")v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?(")#\1'"${TAG}"'\4#g' docs/workflow/about-ci.md
sed -i -E 's#(git push origin )v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?#\1'"${TAG}"'#g' docs/workflow/about-ci.md
sed -i -E 's#(git commit -m "chore: prepare )v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?( release")#\1'"${TAG}"'\3#g' docs/workflow/about-ci.md
sed -i -E 's#(./version-to\.sh )v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?#\1'"${TAG}"'#g' README.md docs/workflow/about-ci.md
sed -i -E 's#(img\.shields\.io/badge/version-)v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?-#\1'"${TAG}"'-#g' README.md
sed -i -E 's#(alt="Version )v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?(")#\1'"${TAG}"'\3#g' README.md

# --- Record the release in CHANGELOG.md (the release ledger line) ---
changelog_release "${VERSION}"

grep -q '^version = "'"${VERSION}"'"$' Cargo.toml || error "Cargo.toml version was not updated"
grep -A3 'name = "zejtron"' Cargo.lock | grep -q 'version = "'"${VERSION}"'"' || error "Cargo.lock zejtron version was not updated"
# The mirror law's verify rows (night-improve-5): the ebpf/ pair and
# the prebuilt lane's pins land on the same version, verified.
grep -q '^version = "'"${VERSION}"'"$' ebpf/Cargo.toml || error "ebpf/Cargo.toml version was not updated"
grep -A3 'name = "zejtron-ebpf"' ebpf/Cargo.lock | grep -q 'version = "'"${VERSION}"'"' || error "ebpf/Cargo.lock zejtron-ebpf version was not updated"
./scripts/dev/regenerate-ebpf-prebuilt.sh --check || error "the prebuilt lane is stale after the bump"
grep -q "TAG=${TAG}" README.md || error "README.md release examples do not mention TAG=${TAG}"
grep -q "TAG=${TAG}" docs/workflow/about-ci.md || error "docs/workflow/about-ci.md release examples do not mention TAG=${TAG}"
# The ledger line is verified like every other rewrite: the version
# sits as its own line under ## [Released].
grep -qxF "${TAG}" CHANGELOG.md || error "CHANGELOG.md ledger line for ${TAG} was not recorded"

echo "VERSION=${VERSION}"
echo "TAG=${TAG}"
echo "Updated Cargo.toml, Cargo.lock, ebpf/Cargo.toml, ebpf/Cargo.lock, ebpf-prebuilt/, README.md, docs/workflow/about-ci.md, and CHANGELOG.md"
