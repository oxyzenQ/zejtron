#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial
# OS: Linux only — zejtron is a Linux introspection tool.
# The version walk (night-cafe-mclaren-1, the zelynic lineage ported
# to zejtron's law): the census is DETECTED, never listed. Every
# tracked Cargo.toml PLUS every authored-but-uncommitted one
# (git ls-files --others --exclude-standard) is enumerated wherever
# it lives; the [package] name and version are read structurally
# (inside the [package] block, not by file order), and the family
# prefix is the root crate's own name - derived, never a literal.
# zejtron's law is the superset of the zelynic family law (the
# owner's absolute rule for this repo): EVERY versioned manifest
# rides the release version - the root crate by definition, every
# zejtron-* family crate, and every fixture/sibling crate beside
# them (the test-fixtures/pidhide pair today) - wherever the file
# lives, and a manifest whose current version differs is HEALED to
# the release version, never skipped (a drifted proofs/ or fuzz/
# manifest is a provenance hole, not an independent crate). A
# manifest that carries no versioned package (a virtual workspace
# root, or a version inherited through version.workspace) is
# reported and left alone - never silently swept, never silently
# lost. Nothing is remembered by hand, so nothing goes stale: a new
# workspace joins the bump the moment it exists on disk, before its
# first git add, and gitignored trees (target/ output, vendored
# junk) can never enter. The sibling locks move the same detected
# way: every tracked-or-uncommitted Cargo.lock, every [[package]]
# entry whose name rides the bump set (the crate's own workspace
# entry today, a path dependency's cross-entry the day one appears),
# rewritten and verified in place.
# The bump then refreshes the prebuilt lane fail-closed through its
# one writer (the zylaxion night-dinner-8 shape): a version bump
# always stales the lane's pins (the ebpf/ tree hash covers
# ebpf/Cargo.toml and ebpf/Cargo.lock), so the bump invocation
# regenerates the lane instead of leaving the commit to fail the
# parity gate.
# The lock edits below remain name-anchored version moves, NEVER a
# cargo resolution (the 2026-11-23 lesson, the zelynic
# night-improve-67 shape). This step once ran `cargo update -p
# zejtron` and `cargo update -p zejtron-ebpf --offline`, and the
# weekly maintenance lane moved anyhow to 1.0.105 in ebpf/Cargo.lock
# while the local sparse-index cache still topped out at 1.0.104 -
# the offline re-resolution then refused the bump mid-flight
# ("failed to select a version for the requirement anyhow = ^1,
# candidate versions found which didn't match: 1.0.104"), leaving a
# half-bumped tree behind. A version bump is a text rewrite:
# dependency versions are the weekly lane's job, their bumps arrive
# in Cargo.lock as bytes cargo itself wrote, and running the
# resolver here adds a network and index-cache dependency to a step
# that needs none. The name-anchored rewrite moves exactly the lines
# cargo would move, it is idempotent over a half-bumped tree (a
# re-run heals the remaining surfaces and leaves the moved ones
# alone), and every rewrite verifies its write target before it
# lands - a write this script cannot verify is a write it does not
# keep.
# CHANGELOG.md earns its release line (sibling lineage: a bump is a
# release event - the ledger records it the same way the Cargo files
# do: a bare version line under "## [Released]", newest first,
# pre-release and stable alike, above "## [Unreleased]". The writer
# enforces the sibling's ledger laws (the owner's v80.0.x lesson):
# exactly one of each heading, Released above Unreleased (a pure
# Released block sitting below Unreleased relocates), the owner's
# pure shape inside Released, and a version line stranded outside
# Released is deleted and re-spliced inside - every write is
# verified after the fact, and a write that cannot verify restores
# the file. Probed honestly: a missing file, a missing anchor, a
# duplicate heading, or a non-standard Released shape refuses and
# writes nothing - never claim a write that did not happen, and a
# ledger this script did not create is not one it rewrites).
# The input gate carries the release lane's full tag contract
# (night-improve-9): release.yml validates a v-prefixed semver with an
# OPTIONAL pre-release suffix (vX.Y.Z or vX.Y.Z-prerelease - the
# '-' after the patch segment alone marks a pre-release; the
# previous-tag boundary and the --prerelease lane read the shape,
# never a suffix list), so the version manager accepts the same
# shape and
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

# The [package] block parsers (night-cafe-mclaren-1, the NIGHT-bump-2
# structural law): the version surface is located by structure, not
# by file order - the first name/version pair inside [package] is the
# crate's own, whatever the file's layout. An empty result means the
# manifest carries no versioned package (a virtual workspace root -
# no surface, no opinion) or inherits it (version.workspace).
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

# The version walk (night-cafe-mclaren-1): the tracked tree PLUS the
# authored-but-uncommitted tree, deduplicated, sorted - the one
# enumeration every manifest and lock lane rides. A new workspace
# joins the bump the moment it exists on disk, before its first git
# add; gitignored trees (target/ output, vendored junk) still can
# never enter (--exclude-standard). The [.] form keeps the dot
# literal with no backslash-quoting dance.
version_walk() {
	{
		git ls-files | grep -E "(^|/)${1//./[.]}$" || true
		git ls-files --others --exclude-standard | grep -E "(^|/)${1//./[.]}$" || true
	} | sort -u
}

# The name<TAB>version rows a Cargo.lock carries for an ERE of
# package names (the lock's own top-level version line sits outside
# any [[package]] block and is never touched).
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

# The family prefix is the root crate's own [package] name - DERIVED,
# never a literal (night-cafe-mclaren-1): a renamed root or a ported
# script would have left a hard-coded prefix stale, the exact disease
# the detected census cures. The family is whoever the root crate
# says it is; zejtron's bump law rides every versioned manifest, so
# the prefix names the FAMILY in the report lines (a fixture crate
# such as the pidhide pair is labeled a sibling, not swept silently).
FAMILY_PREFIX="$(manifest_name_of Cargo.toml)"
[[ -n "${FAMILY_PREFIX}" ]] || error "the root Cargo.toml carries no [package] name - the family law has no anchor"
OLD_VERSION="$(manifest_version_of Cargo.toml)"
[[ -n "${OLD_VERSION}" ]] || error "could not read the current version from Cargo.toml"

# The crate graph, detected every run (night-cafe-mclaren-1). Fills:
#   BUMP_PATHS[i] / BUMP_NAMES[i] / BUMP_OLDS[i] - every versioned
#   manifest in the walked tree: the root crate by definition, every
#   ${FAMILY_PREFIX}-* family crate, and every sibling/fixture crate
#   beside them (zejtron's superset law: ALL versioned manifests ride
#   the release version; a drifted one is healed, not skipped);
#   SKIP_REPORTS[] - the honest report lines for manifests left at
#   their own shape (a virtual workspace root, or a version inherited
#   through version.workspace - no [package] version surface this
#   script may rewrite, and one that is never silently lost).
BUMP_PATHS=()
BUMP_NAMES=()
BUMP_OLDS=()
SKIP_REPORTS=()
build_census() {
	local path name ver
	while IFS= read -r path; do
		name="$(manifest_name_of "${path}")"
		ver="$(manifest_version_of "${path}")"
		if [[ -z "${name}" && -z "${ver}" ]]; then
			SKIP_REPORTS+=("${path} (no [package] block - a virtual manifest; left alone)")
		elif [[ -z "${ver}" ]]; then
			SKIP_REPORTS+=("${path} ${name:-"(no name)"} (version inherited or absent; rides its workspace root)")
		else
			BUMP_PATHS+=("${path}")
			BUMP_NAMES+=("${name}")
			BUMP_OLDS+=("${ver}")
		fi
	done < <(version_walk Cargo.toml)
	if [[ "${#BUMP_PATHS[@]}" -eq 0 ]]; then
		error "no versioned Cargo.toml found in the tracked tree - the bump has no anchor"
	fi
}

# One manifest lane: rewrite the [package] version inside its own
# section (dependency version lines live in other sections and never
# move), verify the WRITE TARGET before it lands (the ledger's
# verification law, generalized: a write this script cannot verify is
# a write it does not keep), and only then commit the file.
# Returns 0 when the file changed, 1 when it already carried the
# target.
bump_manifest() {
	local path="$1" name="$2" old="$3" label tmp now
	label="$(printf '%-21s' "${path}")"
	if [[ "${old}" = "${VERSION}" ]]; then
		echo "  ! ${label} ${name} already at v${VERSION}"
		return 1
	fi
	tmp="$(mktemp)"
	awk -v new="${VERSION}" '
                /^\[package\][[:space:]]*$/ { pkg = 1; print; next }
                /^\[/ { pkg = 0; print; next }
                pkg && !done && /^version = "[^"]*"/ { sub(/"[^"]*"/, "\"" new "\""); done = 1 }
                { print }
        ' "${path}" >"${tmp}"
	now="$(manifest_version_of "${tmp}")"
	if [[ "${now}" != "${VERSION}" ]]; then
		rm -f "${tmp}"
		error "${label} the rewrite did not verify (expected ${VERSION}, read ${now:-nothing}) - the file was left as found, nothing kept"
	fi
	mv "${tmp}" "${path}"
	chmod 644 "${path}"
	echo "  OK ${label} ${name} ${old} -> ${VERSION}"
	return 0
}

# One lock lane: rewrite EVERY [[package]] entry whose name rides the
# bump set - the crate's own workspace entry today, a path
# dependency's cross-entry the day one appears - verify the WRITE
# TARGET first (the entry set must survive and every entry must read
# the target), and only then commit the file. Returns 0 when the lock
# changed, 1 when it did not.
bump_lock() {
	local lockf="$1" names_regex="$2" label tmp before after moved already
	label="$(printf '%-21s' "${lockf}")"
	before="$(lock_entry_versions "${names_regex}" "${lockf}")"
	if [[ -z "${before}" ]]; then
		echo "  ! ${label} no [[package]] entry rides the bump set here - nothing to rewrite"
		return 1
	fi
	tmp="$(mktemp)"
	awk -v re="^(${names_regex})$" -v new="${VERSION}" '
                /^\[\[package\]\]/ { inb = 1; hit = 0; print; next }
                inb && /^name = "[^"]*"/ {
                        print
                        sub(/^name = "/, ""); sub(/".*$/, "")
                        hit = ($0 ~ re) ? 1 : 0
                        next
                }
                inb && hit && /^version = "[^"]*"/ {
                        sub(/"[^"]*"/, "\"" new "\"")
                        print; next
                }
                { print }
        ' "${lockf}" >"${tmp}"
	after="$(lock_entry_versions "${names_regex}" "${tmp}")"
	if [[ "$(sort <<<"${before}" | cut -f1)" != "$(sort <<<"${after}" | cut -f1)" ]] ||
		[[ -n "$(awk -F'\t' -v want="${VERSION}" '$2 != want' <<<"${after}")" ]]; then
		rm -f "${tmp}"
		error "${label} the lock rewrite did not verify - the file was left as found, nothing kept"
	fi
	mv "${tmp}" "${lockf}"
	chmod 644 "${lockf}"
	moved="$(awk -F'\t' 'NR==FNR { b[$1] = $2; next } { if ($1 in b && b[$1] != $2) printf "%s ", $1 }' \
		<(printf '%s\n' "${before}") <(printf '%s\n' "${after}"))"
	already="$(awk -F'\t' 'NR==FNR { b[$1] = $2; next } { if ($1 in b && b[$1] == $2) printf "%s ", $1 }' \
		<(printf '%s\n' "${before}") <(printf '%s\n' "${after}"))"
	if [[ -n "${moved}" ]]; then
		echo "  OK ${label} ${moved% } -> ${VERSION}"
		return 0
	fi
	if [[ -n "${already}" ]]; then
		echo "  ! ${label} ${already% } already at v${VERSION}"
	fi
	return 1
}

# Record the release in CHANGELOG.md's ledger (## [Released], newest
# first). The probes mirror the sibling project's ledger writer, and
# the ledger laws are the sibling's night-bump-1 set: exactly one of
# each heading, Released above Unreleased, the owner's pure shape
# inside Released, and a version line stranded outside Released
# heals - deleted and re-spliced inside, the only state the final
# verify accepts. Every non-standard state refuses loudly instead of
# claiming a rewrite that did not happen.
changelog_release() {
	local ver="v$1" tmp backup
	if [[ ! -f CHANGELOG.md ]]; then
		echo "  ! CHANGELOG.md        -> file absent, nothing to write"
		return 0
	fi

	# Law 1a: exactly one of each heading. More than one is a shape
	# this script cannot parse and will not edit.
	local rcount ucount
	rcount="$(grep -c '^## \[Released\]$' CHANGELOG.md || true)"
	ucount="$(grep -c '^## \[Unreleased\]$' CHANGELOG.md || true)"
	if [[ "${rcount}" -gt 1 || "${ucount}" -gt 1 ]]; then
		error "CHANGELOG.md -> ${rcount} '## [Released]' heading(s) and ${ucount} '## [Unreleased]' heading(s), expected exactly one of each; repair the headings by hand, then re-run"
	fi

	# Law 1b: Released must PRECEDE Unreleased. The pure-block shape
	# below Unreleased relocates; anything richer refuses.
	if [[ "${rcount}" -eq 1 && "${ucount}" -eq 1 ]]; then
		local rline uline
		rline="$(grep -n '^## \[Released\]$' CHANGELOG.md | cut -d: -f1)"
		uline="$(grep -n '^## \[Unreleased\]$' CHANGELOG.md | cut -d: -f1)"
		if [[ "${rline}" -gt "${uline}" ]]; then
			ledger_relocate_released_block "${rline}"
		fi
	fi

	# Law 1c: the owner's pure shape inside Released - blank spacers
	# and bare version lines, nothing else. Its absence is hand-edit
	# drift - refused, never guessed around.
	if [[ "${rcount}" -eq 1 ]]; then
		local junk
		junk="$(awk '/^## \[Released\]$/{f=1;next} /^## \[Unreleased\]$/{f=0} f&&!/^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$/&&!/^$/' CHANGELOG.md | head -3 || true)"
		if [[ -n "${junk}" ]]; then
			printf '%s\n' "${junk}" >&2
			error "CHANGELOG.md -> foreign content inside ## [Released] (the owner's shape is blank spacers + bare version lines) - a ledger this script did not create is not one it rewrites; repair the shape by hand, then re-run"
		fi
		if [[ -n "$(sed -n '/^## \[Released\]$/{n;p;}' CHANGELOG.md)" ]]; then
			error "CHANGELOG.md -> the blank spacer under ## [Released] is gone (the owner shape is heading, blank line, version lines); restore the blank line, then re-run"
		fi
	fi

	# A version line never repeats - and a line stranded OUTSIDE
	# Released (the owner's broken state: the bare version line under
	# ## [Unreleased] while both headings look fine) heals in place:
	# delete the strays now, the verified splice below records the
	# line where it belongs.
	local total inside
	total="$(grep -cxF "${ver}" CHANGELOG.md || true)"
	inside="$(sed -n '/^## \[Released\]$/,/^## \[Unreleased\]$/p' CHANGELOG.md | grep -cxF "${ver}" || true)"
	if [[ "${total}" -gt 0 && "${inside}" -eq "${total}" ]]; then
		echo "  ! CHANGELOG.md        -> ${ver} already recorded in ## [Released], nothing to write"
		return 0
	fi
	if [[ "${total}" -gt 0 ]]; then
		tmp="$(mktemp)"
		grep -vxF "${ver}" CHANGELOG.md >"${tmp}"
		mv "${tmp}" CHANGELOG.md
		chmod 644 CHANGELOG.md
		echo "  ! CHANGELOG.md        -> ${ver} recorded OUTSIDE ## [Released] (${total} line(s), ${inside} inside) - deleted; the verified splice below records it properly"
	fi

	# The splice: write, then VERIFY - the version line must sit
	# inside ## [Released] exactly once with Released above
	# Unreleased; any other outcome restores the backup and fails the
	# run. A write this script cannot verify is a write it does not
	# keep.
	tmp="$(mktemp)"
	backup="$(mktemp)"
	cp CHANGELOG.md "${backup}"
	if [[ "${rcount}" -eq 1 ]]; then
		# The section exists with its verified spacer - splice the new
		# version in under it, above the current top line.
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
	elif [[ "${ucount}" -eq 1 ]]; then
		# No section yet - create it above "## [Unreleased]" (the
		# unreleased work keeps its own section below the ledger).
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
	else
		rm -f "${tmp}" "${backup}"
		echo "  ! CHANGELOG.md        -> no ## [Unreleased] anchor found - nothing to write"
		return 0
	fi
	total="$(grep -cxF "${ver}" CHANGELOG.md || true)"
	inside="$(sed -n '/^## \[Released\]$/,/^## \[Unreleased\]$/p' CHANGELOG.md | grep -cxF "${ver}" || true)"
	local order_ok=true
	if [[ "$(grep -c '^## \[Released\]$' CHANGELOG.md || true)" -eq 1 && "$(grep -c '^## \[Unreleased\]$' CHANGELOG.md || true)" -eq 1 ]]; then
		local rnow unow
		rnow="$(grep -n '^## \[Released\]$' CHANGELOG.md | cut -d: -f1)"
		unow="$(grep -n '^## \[Unreleased\]$' CHANGELOG.md | cut -d: -f1)"
		[[ "${rnow}" -lt "${unow}" ]] || order_ok=false
	else
		order_ok=false
	fi
	if [[ "${total}" -ne 1 || "${inside}" -ne 1 || "${order_ok}" != true ]]; then
		mv "${backup}" CHANGELOG.md
		chmod 644 CHANGELOG.md
		rm -f "${tmp}"
		error "CHANGELOG.md -> the ledger write did not verify (the version line must sit inside ## [Released] exactly once, with Released above Unreleased) - the file was restored, nothing kept"
	fi
	rm -f "${tmp}" "${backup}"
	if [[ "${rcount}" -eq 1 ]]; then
		echo "  OK CHANGELOG.md        -> ${ver} (## [Released], newest first)"
	else
		echo "  OK CHANGELOG.md        -> ${ver} (section created above ## [Unreleased])"
	fi
	return 0
}

ledger_relocate_released_block() {
	local rline="$1" block bad tmp rest want got rnew uline
	block="$(sed -n "${rline},\$p" CHANGELOG.md)"
	bad="$(printf '%s\n' "${block}" | grep -vE '^(## \[Released\]|v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?)$' | head -3 || true)"
	if [[ -n "${bad}" ]]; then
		printf '%s\n' "${bad}" >&2
		error "CHANGELOG.md -> ## [Released] sits below ## [Unreleased] AND carries foreign content - a ledger this script did not create is not one it rewrites; repair the shape by hand, then re-run"
	fi
	rest="$(sed -n "1,$((rline - 1))p" CHANGELOG.md)"
	tmp="$(mktemp)"
	awk -v blk="${block}" '
                        /^## \[Unreleased\]$/ && !done {
                                printf "%s\n\n", blk
                                done = 1
                        }
                        { print }
        ' <<<"${rest}" >"${tmp}"
	rnew="$(grep -n '^## \[Released\]$' "${tmp}" | cut -d: -f1 || true)"
	uline="$(grep -n '^## \[Unreleased\]$' "${tmp}" | cut -d: -f1 || true)"
	want="$(printf '%s\n' "${block}" | grep -cE '^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$' || true)"
	got="$(awk '/^## \[Released\]$/{f=1;next} /^## \[Unreleased\]$/{f=0} f&&/^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$/' "${tmp}" | wc -l)"
	if [[ -z "${rnew}" || -z "${uline}" || "${rnew}" -ge "${uline}" || "${want}" -ne "${got}" ]]; then
		rm -f "${tmp}"
		error "CHANGELOG.md -> the relocation did not verify (## [Released] above ## [Unreleased] with every version line intact) - the file was left as found"
	fi
	mv "${tmp}" CHANGELOG.md
	chmod 644 CHANGELOG.md
	echo "  OK CHANGELOG.md        -> ## [Released] relocated above ## [Unreleased] (the owner shape restored)"
}

# Detect the crate graph BEFORE anything mutates - the bump set, the
# drift verdict and the skip reports all come from this pass.
build_census
# The bump set as one ERE of crate names - the lock graph walks it.
names_regex="$(printf '%s|' "${BUMP_NAMES[@]}")"
names_regex="${names_regex%|}"

# The stranger report (night-cafe-mclaren-1): a manifest with no
# versioned [package] is visible on every run - never silently swept,
# never silently lost. It is NOT a failure: a virtual workspace root
# carries no version surface to rewrite.
if [[ "${#SKIP_REPORTS[@]}" -gt 0 ]]; then
	echo "  ! version surfaces without a rewritable [package] version (left alone, reported):"
	for line in "${SKIP_REPORTS[@]}"; do
		echo "      ${line}"
	done
	echo ""
fi

# The reconcile gate: the early exit fires only when EVERY detected
# surface already carries the target - every versioned manifest, every
# riding [[package]] entry in every walked lock, both release-example
# doc surfaces, the ledger line, and the prebuilt lane's pins. A
# partial match proceeds and the drifted surfaces heal below; a re-run
# at an already-bumped root must still reach the workspaces the old
# remembered list never knew about.
ALL_AT_TARGET=true
for old in "${BUMP_OLDS[@]}"; do
	if [[ "${old}" != "${VERSION}" ]]; then
		ALL_AT_TARGET=false
		break
	fi
done
if [[ "${ALL_AT_TARGET}" = true ]]; then
	while IFS= read -r lockf; do
		if [[ -n "$(lock_entry_versions "${names_regex}" "${lockf}" | awk -F'\t' -v want="${VERSION}" '$2 != want')" ]]; then
			ALL_AT_TARGET=false
			break
		fi
	done < <(version_walk Cargo.lock)
fi
if [[ "${ALL_AT_TARGET}" = true ]] &&
	grep -q "TAG=${TAG}" README.md &&
	grep -q "TAG=${TAG}" docs/workflow/about-ci.md &&
	grep -qxF "${TAG}" CHANGELOG.md &&
	./scripts/dev/regenerate-ebpf-prebuilt.sh --check >/dev/null 2>&1; then
	echo "zejtron is already at ${TAG} across every detected surface - nothing to change"
	exit 0
fi

echo "Updating zejtron to ${TAG}"

# The manifest lanes (night-cafe-mclaren-1): every detected surface
# rides; each rewrite is verified by reading the write target back
# before it lands. Dependency version lines live in their own sections
# and never move (those are the job of `cargo update`, not a version
# bump). The ebpf/ churn THIS run creates is what the prebuilt lane
# below answers for.
bumped_surfaces=""
EBPF_CHANGED=false
for i in "${!BUMP_PATHS[@]}"; do
	if bump_manifest "${BUMP_PATHS[$i]}" "${BUMP_NAMES[$i]}" "${BUMP_OLDS[$i]}"; then
		bumped_surfaces+="${BUMP_PATHS[$i]} "
		case "${BUMP_PATHS[$i]}" in
		ebpf/*) EBPF_CHANGED=true ;;
		esac
	fi
done

# The lock lanes (night-cafe-mclaren-1): every walked Cargo.lock,
# every [[package]] entry whose name rides the bump set. Dependency
# versions (the whole rest of the lock) are the job of `cargo update`,
# not a version bump.
echo ""
while IFS= read -r lockf; do
	if bump_lock "${lockf}" "${names_regex}"; then
		bumped_surfaces+="${lockf} "
	fi
done < <(version_walk Cargo.lock)

# The prebuilt lane (the zelynic night-improve-70 shape, adapted to
# the one writer): the lane's tree pin covers ebpf/ only, so the
# writer runs when THIS run changed an ebpf/ surface - one command
# leaves a committable tree. A run that touched no ebpf/ surface does
# not invoke the writer (a no-op regen would only churn the
# manifest's generated stamp); the read-only verdict runs instead and
# a lane stale for reasons THIS run did not create keeps the honest
# manual verdict - fail closed, name the writer, never silently heal
# a pre-existing staleness as a bump side effect.
if [[ "${EBPF_CHANGED}" = true ]]; then
	./scripts/dev/regenerate-ebpf-prebuilt.sh
else
	./scripts/dev/regenerate-ebpf-prebuilt.sh --check >/dev/null || error "the prebuilt lane is stale for reasons this run did not create - run ./scripts/dev/regenerate-ebpf-prebuilt.sh and commit ebpf/ + ebpf-prebuilt/ together"
fi

# The release-example census: every tracked markdown surface whose
# TAG= pin still carries the OLD tag rides the same anchored rewrite
# shapes as before (TAG=, the download URL, the tag/push/commit
# examples, the version-to invocation, the shields badge), wherever
# they live. The changelog ledger is owned by changelog_release and
# is never swept here.
doc_targets="$({
	printf '%s\n' README.md docs/workflow/about-ci.md
	git grep -l "TAG=v${OLD_VERSION}" -- '*.md' || true
} | sort -u | grep -v '^CHANGELOG.md$' || true)"
doc_list=""
while IFS= read -r doc; do
	[[ -f "${doc}" ]] || continue
	doc_list+="${doc} "
	sed -i -E 's/^TAG=v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?/TAG='"${TAG}"'/' "${doc}"
	sed -i -E 's#(zejtron-)v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?(-linux-)#\1'"${TAG}"'\3#g' "${doc}"
	sed -i -E 's#(/download/)v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?/#\1'"${TAG}"'/#g' "${doc}"
	sed -i -E 's#(git tag -a )v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?#\1'"${TAG}"'#g' "${doc}"
	sed -i -E 's#(git tag -a v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)? -m ")v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?(")#\1'"${TAG}"'\4#g' "${doc}"
	sed -i -E 's#(git push origin )v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?#\1'"${TAG}"'#g' "${doc}"
	sed -i -E 's#(git commit -m "chore: prepare )v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?( release")#\1'"${TAG}"'\3#g' "${doc}"
	sed -i -E 's#(./version-to\.sh )v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?#\1'"${TAG}"'#g' "${doc}"
	sed -i -E 's#(img\.shields\.io/badge/version-)v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?-#\1'"${TAG}"'-#g' "${doc}"
	sed -i -E 's#(alt="Version )v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?(")#\1'"${TAG}"'\3#g' "${doc}"
done <<<"${doc_targets}"

# --- Record the release in CHANGELOG.md (the release ledger line) ---
changelog_release "${VERSION}"

# The verify rows: every surface the census bumped asserts the NEW
# version - the detected law holds over whatever the tree carried,
# not over a remembered list.
while IFS= read -r manifest; do
	[[ "$(manifest_version_of "${manifest}")" = "${VERSION}" ]] || error "${manifest} version was not updated"
done < <(version_walk Cargo.toml)
while IFS= read -r lockf; do
	if [[ -n "$(lock_entry_versions "${names_regex}" "${lockf}" | awk -F'\t' -v want="${VERSION}" '$2 != want')" ]]; then
		error "${lockf}: a [[package]] entry riding the bump set was not rewritten"
	fi
done < <(version_walk Cargo.lock)
./scripts/dev/regenerate-ebpf-prebuilt.sh --check || error "the prebuilt lane is stale after the bump"
grep -q "TAG=${TAG}" README.md || error "README.md release examples do not mention TAG=${TAG}"
grep -q "TAG=${TAG}" docs/workflow/about-ci.md || error "docs/workflow/about-ci.md release examples do not mention TAG=${TAG}"
# The ledger line is verified like every other rewrite: the version
# sits as its own line under ## [Released].
grep -qxF "${TAG}" CHANGELOG.md || error "CHANGELOG.md ledger line for ${TAG} was not recorded"

echo "VERSION=${VERSION}"
echo "TAG=${TAG}"
echo "Updated ${bumped_surfaces}ebpf-prebuilt/, ${doc_list}and CHANGELOG.md (the version walk re-read the tree: ${#BUMP_PATHS[@]} manifest surfaces detected, every one riding v${VERSION})"
