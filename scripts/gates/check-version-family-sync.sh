#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial
# OS: Linux only — zejtron is a Linux introspection tool.
# =============================================================================
# ZEJTRON VERSION FAMILY SYNC GUARD (night-cafe-mclaren-1, the zelynic
# lineage ported to zejtron's law)
# =============================================================================
# Fails when any versioned Cargo.toml in the tree - or any [[package]]
# entry a tracked-or-uncommitted Cargo.lock holds for a detected crate
# - carries a version the root manifest does not.
#
# The release lane's own parity tripwire (release.yml) validates the
# ROOT Cargo.toml against the tag before any compile time is spent;
# nothing held the SIBLINGS to the same number. The provenance hole
# night-cafe-mclaren-1 closed at bump time (zejtron-proofs once rode
# 0.1.0 and zejtron-fuzz rode 0.0.0 beside a release-version root -
# the zelynic night-bump-2 lesson) stays closed here at every push:
# a drifted sibling fails this gate with the heal recipe, instead of
# shipping a provenance disagreement into a release.
#
# zejtron's law is the superset of the zelynic family law (the owner's
# absolute rule for this repo): EVERY versioned manifest rides the
# root version - the root crate by definition, every zejtron-* family
# crate, and every fixture/sibling crate beside them (the
# test-fixtures/pidhide pair) - wherever the file lives. In practice
# the two laws coincide whenever every crate is brand-named (the
# zelynic case); here the fixture pair rides too, so a stranger class
# to accidentally forget cannot exist.
#
# Discovery law (the same one scripts/dev/version-to.sh rides): git
# enumerates the manifests and the locks - tracked files plus
# authored-but-uncommitted files (a new workspace joins the family
# the moment it exists on disk); gitignored trees (target/ output,
# vendored junk) never enter. The family is DETECTED, never listed -
# the prefix is the root [package] name, so a renamed root or a fifth
# workspace joins with zero edits here.
#
# A manifest with no versioned [package] (a virtual workspace root,
# or a version inherited through version.workspace) is reported
# informationally - no version surface this gate may assert, never
# silently lost.
#
# Usage: bash scripts/gates/check-version-family-sync.sh
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

# The [package] parsers (the structural law: the name and version
# surfaces live inside [package], whatever the file layout).
manifest_version_of() {
	awk '
		/^\[package\][[:space:]]*$/ { pkg = 1; next }
		/^\[/ { pkg = 0 }
		pkg && /^version = "[^"]+"/ {
			sub(/^version = "/, ""); sub(/".*$/, ""); print; exit
		}
	' "$1"
}

manifest_name_of() {
	awk '
		/^\[package\][[:space:]]*$/ { pkg = 1; next }
		/^\[/ { pkg = 0 }
		pkg && /^name = "[^"]+"/ {
			sub(/^name = "/, ""); sub(/".*$/, ""); print; exit
		}
	' "$1"
}

# The version walk (night-cafe-mclaren-1): tracked plus
# authored-but-uncommitted, deduplicated, sorted - the walk
# version-to.sh rides. The [.] form keeps the dot literal with no
# backslash-quoting dance.
version_walk() {
	{
		git ls-files | grep -E "(^|/)${1//./[.]}$" || true
		git ls-files --others --exclude-standard | grep -E "(^|/)${1//./[.]}$" || true
	} | sort -u
}

# The name<TAB>version rows a lock carries for an ERE of names (the
# lock's own top-level version line sits outside any [[package]]
# block and is never read).
lock_entry_versions() {
	awk -v re="^(${1})$" '
		/^\[\[package\]\]/ { inb = 1; hit = 0; next }
		inb && /^name = "[^"]*"/ {
			sub(/^name = "/, ""); sub(/".*$/, "")
			name = $0
			hit = (name ~ re) ? 1 : 0
			next
		}
		inb && hit && /^version = "[^"]*"/ {
			sub(/^version = "/, ""); sub(/".*$/, "")
			print name "\t" $0
		}
	' "$2"
}

ROOT_NAME="$(manifest_name_of Cargo.toml)"
ROOT_VERSION="$(manifest_version_of Cargo.toml)"
if [ -z "${ROOT_NAME}" ] || [ -z "${ROOT_VERSION}" ]; then
	echo "FAIL: the root Cargo.toml carries no [package] name/version - the family law has no anchor"
	exit 1
fi

DRIFT=0
SURFACES=0
ENTRIES=0

# Manifest lane: every versioned manifest in the walked tree must
# carry the root version (zejtron's superset law - root by
# definition, family and sibling/fixture crates alike). A manifest
# with no [package] version is reported and skipped.
while IFS= read -r f; do
	name="$(manifest_name_of "${f}")"
	ver="$(manifest_version_of "${f}")"
	if [ -z "${ver}" ]; then
		echo "! ${f} ${name:-"(no [package] block)"} carries no [package] version (a virtual or inherited manifest; no surface to assert)"
		continue
	fi
	SURFACES=$((SURFACES + 1))
	if [ "${ver}" != "${ROOT_VERSION}" ]; then
		echo "DRIFT: ${f} (${name}) carries v${ver}; the root carries v${ROOT_VERSION}"
		DRIFT=$((DRIFT + 1))
	fi
done < <(version_walk Cargo.toml)

# The names ERE, from the detected manifests - the same shape the
# lock lanes ride in version-to.sh.
names_regex=""
while IFS= read -r f; do
	name="$(manifest_name_of "${f}")"
	if [ -n "${name}" ]; then
		names_regex="${names_regex}${name}|"
	fi
done < <(version_walk Cargo.toml)
names_regex="${names_regex%|}"

# Lock lane: every detected crate's [[package]] entry must carry the
# root version (the crate's own workspace entry today, a path
# dependency's cross-entry the day one appears).
while IFS= read -r lockf; do
	while IFS=$'\t' read -r lname lver; do
		ENTRIES=$((ENTRIES + 1))
		if [ "${lver}" != "${ROOT_VERSION}" ]; then
			echo "DRIFT: ${lockf} [[package]] ${lname} carries v${lver}; the root carries v${ROOT_VERSION}"
			DRIFT=$((DRIFT + 1))
		fi
	done < <(lock_entry_versions "${names_regex}" "${lockf}")
done < <(version_walk Cargo.lock)

if [ "${DRIFT}" -ne 0 ]; then
	echo ""
	echo "FAIL: ${DRIFT} version drift(s) inside the detected ${ROOT_NAME} family (manifests: ${SURFACES}, lock entries: ${ENTRIES})"
	echo ""
	echo "Fix: one command heals every detected surface (it detects, never lists):"
	echo "  ./scripts/dev/version-to.sh v${ROOT_VERSION}"
	exit 1
fi
echo "OK: family sync - manifests: ${SURFACES}, lock [[package]] entries: ${ENTRIES}, all at v${ROOT_VERSION}, zero drift"
