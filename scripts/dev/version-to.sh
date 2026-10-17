#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool.
# Single-crate repo note (sibling-manifest lineage): unlike the
# sibling project's ebpf/ package, zejtron has NO second Cargo.toml -
# verified live (a repo walk reports ./Cargo.toml as the only
# manifest). The root pair (Cargo.toml + Cargo.lock) is the complete
# cargo version surface, so no cross-manifest bump lane exists here.
# CHANGELOG.md earns its release line (sibling lineage: a bump is a
# release event - the ledger records it the same way the Cargo files
# do: a bare version line under "## [Released]", newest first,
# pre-release and stable alike, above "## [Unreleased]". Probed
# honestly: a missing file, a missing anchor, a version the ledger
# already carries, or a non-standard Released shape warns and writes
# nothing - never claim a write that did not happen, and a ledger
# this script did not create is not one it rewrites).

set -Eeuo pipefail

error() {
  echo "error: $*" >&2
  exit 1
}

if [[ $# -ne 1 ]]; then
  error "usage: ./scripts/dev/version-to.sh vX.Y.Z"
fi

input="$1"
if [[ "$input" =~ ^v?([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  VERSION="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}"
  TAG="v${VERSION}"
else
  error "version must be normal semver: vX.Y.Z or X.Y.Z"
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
      echo "  OK CHANGELOG.md        -> ${ver} (section created above ## [Unreleased])"
    else
      rm -f "${tmp}"
      echo "  ! CHANGELOG.md        -> no ## [Unreleased] anchor found - nothing to write"
    fi
  fi
}

echo "Updating zejtron to ${TAG}"

sed -i -E 's/^version = "[0-9]+\.[0-9]+\.[0-9]+"/version = "'"${VERSION}"'"/' Cargo.toml
cargo update -p zejtron

sed -i -E 's/^TAG=v[0-9]+\.[0-9]+\.[0-9]+/TAG='"${TAG}"'/' README.md docs/workflow/about-ci.md
sed -i -E 's#(zejtron-)v[0-9]+\.[0-9]+\.[0-9]+(-linux-)#\1'"${TAG}"'\2#g' README.md docs/workflow/about-ci.md
sed -i -E 's#(/download/)v[0-9]+\.[0-9]+\.[0-9]+/#\1'"${TAG}"'/#g' README.md docs/workflow/about-ci.md
sed -i -E 's#(git tag -a )v[0-9]+\.[0-9]+\.[0-9]+#\1'"${TAG}"'#g' docs/workflow/about-ci.md
sed -i -E 's#(git tag -a v[0-9]+\.[0-9]+\.[0-9]+ -m ")v[0-9]+\.[0-9]+\.[0-9]+(")#\1'"${TAG}"'\2#g' docs/workflow/about-ci.md
sed -i -E 's#(git push origin )v[0-9]+\.[0-9]+\.[0-9]+#\1'"${TAG}"'#g' docs/workflow/about-ci.md
sed -i -E 's#(git commit -m "chore: prepare )v[0-9]+\.[0-9]+\.[0-9]+( release")#\1'"${TAG}"'\2#g' docs/workflow/about-ci.md
sed -i -E 's#(./version-to\.sh )v[0-9]+\.[0-9]+\.[0-9]+#\1'"${TAG}"'#g' README.md docs/workflow/about-ci.md
sed -i -E 's#(img\.shields\.io/badge/version-)v[0-9]+\.[0-9]+\.[0-9]+-#\1'"${TAG}"'-#g' README.md
sed -i -E 's#(alt="Version )v[0-9]+\.[0-9]+\.[0-9]+(")#\1'"${TAG}"'\2#g' README.md

# --- Record the release in CHANGELOG.md (the release ledger line) ---
changelog_release "${VERSION}"

grep -q '^version = "'"${VERSION}"'"$' Cargo.toml || error "Cargo.toml version was not updated"
grep -A3 'name = "zejtron"' Cargo.lock | grep -q 'version = "'"${VERSION}"'"' || error "Cargo.lock zejtron version was not updated"
grep -q "TAG=${TAG}" README.md || error "README.md release examples do not mention TAG=${TAG}"
grep -q "TAG=${TAG}" docs/workflow/about-ci.md || error "docs/workflow/about-ci.md release examples do not mention TAG=${TAG}"
# The ledger line is verified like every other rewrite: the version
# sits as its own line under ## [Released].
grep -qxF "${TAG}" CHANGELOG.md || error "CHANGELOG.md ledger line for ${TAG} was not recorded"

echo "VERSION=${VERSION}"
echo "TAG=${TAG}"
echo "Updated Cargo.toml, Cargo.lock, README.md, docs/workflow/about-ci.md, and CHANGELOG.md"
