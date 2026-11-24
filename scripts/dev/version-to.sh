#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial
# OS: Linux only — zejtron is a Linux introspection tool.
# The mirror census (the autodetect law, retargeted by
# night-depth-cleanup-1B-1 from the sibling-manifest lineage): the
# OLD version is read from the root manifest, and every TRACKED
# Cargo.toml carrying that exact version is a mirror member - bumped
# here whatever its path, with its sibling lock moved the same
# name-anchored way (the root pair, the detached ebpf/ workspace,
# and the test-fixtures/pidhide pair today). A crate that joins the
# mirror by carrying the release version rides every future bump;
# a crate that declares its own independent version stays
# independent; nothing is remembered by hand, so nothing goes
# stale. The bump then refreshes the prebuilt lane fail-closed
# through its one writer - the zylaxion night-dinner-8 shape: a
# version bump always stales the lane's pins (the ebpf/ tree
# hash covers ebpf/Cargo.toml and ebpf/Cargo.lock), so the bump
# invocation regenerates the lane instead of leaving the commit to
# fail the parity gate.
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

# ledger_relocate_released_block LINE - the sibling's law 1b heal
# (the shape the owner hit on the v80.0.x line): a "## [Released]"
# block sitting BELOW "## [Unreleased]" reads as released work under
# Unreleased, and every reader lands on the wrong section. Only the
# owner's pure shape relocates - heading, blank spacers, bare
# version lines, nothing else (the block runs to end of file, so
# foreign content in it means the shape is not this script's to
# heal). The block moves above "## [Unreleased]", and the move
# verifies on the temp copy before it lands - never trusted blind.
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

echo "Updating zejtron to ${TAG}"

# The lock edits below are name-anchored version moves, NEVER a cargo
# resolution (the 2026-11-23 lesson, the zelynic night-improve-67
# shape). This step once ran `cargo update -p zejtron` and
# `cargo update -p zejtron-ebpf --offline`, and the weekly maintenance
# lane moved anyhow to 1.0.105 in ebpf/Cargo.lock while the local
# sparse-index cache still topped out at 1.0.104 - the offline
# re-resolution then refused the bump mid-flight ("failed to select a
# version for the requirement anyhow = ^1, candidate versions found
# which didn't match: 1.0.104"), leaving a half-bumped tree behind.
# A version bump is a text rewrite: dependency versions are the
# weekly lane's job, their bumps arrive in Cargo.lock as bytes cargo
# itself wrote, and running the resolver here adds a network and
# index-cache dependency to a step that needs none. The name-anchored
# sed moves exactly the one line `cargo update -p` moves (verified:
# the update rewrites only the version line after the package name),
# it is idempotent over a half-bumped tree (a re-run after a failed
# bump heals the remaining surfaces), and the verify rows below fail
# loudly if the lock shape is not this script's to edit.
# The mirror census: the OLD version is read from the root manifest
# first, then the tree is re-read for every tracked manifest riding
# it. The rewrite anchors the OLD version exactly (idempotent over a
# half-bumped tree: a re-run heals the remaining OLD surfaces and
# leaves the NEW ones alone), and every manifest's sibling lock moves
# the name-anchored way - the 2026-11-23 lesson above, a text
# rewrite, never a resolver run.
OLD_VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)"
[[ -n "${OLD_VERSION}" ]] || error "could not read the current version from Cargo.toml"
mirror_manifests="$(git ls-files -- '*Cargo.toml' | while IFS= read -r manifest; do
	manifest_version="$(sed -n 's/^version = "\(.*\)"$/\1/p' "${manifest}" | head -1)"
	if [[ "${manifest_version}" == "${OLD_VERSION}" ]]; then
		printf '%s\n' "${manifest}"
	fi
done)"
[[ -n "${mirror_manifests}" ]] || error "no tracked manifest carries version ${OLD_VERSION} - the mirror census found nothing to bump"

bumped_surfaces=""
doc_list=""
while IFS= read -r manifest; do
	# The manifest: every column-0 version line carrying the OLD
	# version moves ([package] today, [workspace.package] if a
	# manifest ever grows one - matching the release version is the
	# definition of a mirror member).
	sed -i -E 's/^version = "'"${OLD_VERSION}"'"/version = "'"${VERSION}"'"/' "${manifest}"
	package_name="$(sed -n 's/^name = "\(.*\)"$/\1/p' "${manifest}" | head -1)"
	[[ -n "${package_name}" ]] || error "${manifest}: no package name - the census needs it for the lock move"
	bumped_surfaces+="${manifest} "
	# The sibling lock, moved the name-anchored way and verified in
	# the same breath as the old hardcoded rows were.
	lock="$(dirname "${manifest}")/Cargo.lock"
	if [[ -f "${lock}" ]]; then
		sed -i -E "/^name = \"${package_name}\"\$/{n;s/^version = \"[^\"]*\"/version = \"${VERSION}\"/;}" "${lock}"
		grep -A3 "name = \"${package_name}\"" "${lock}" | grep -q 'version = "'"${VERSION}"'"' ||
			error "${lock}: ${package_name} entry was not rewritten - the lock shape is not this script's to edit"
		bumped_surfaces+="${lock#./} "
	fi
done <<<"${mirror_manifests}"

./scripts/dev/regenerate-ebpf-prebuilt.sh

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
# version - the mirror law holds over whatever the tree carried, not
# over a remembered list.
while IFS= read -r manifest; do
	grep -q '^version = "'"${VERSION}"'"$' "${manifest}" || error "${manifest} version was not updated"
	package_name="$(sed -n 's/^name = "\(.*\)"$/\1/p' "${manifest}" | head -1)"
	lock="$(dirname "${manifest}")/Cargo.lock"
	if [[ -f "${lock}" ]]; then
		grep -A3 "name = \"${package_name}\"" "${lock}" | grep -q 'version = "'"${VERSION}"'"' || error "${lock}: ${package_name} version was not updated"
	fi
done <<<"${mirror_manifests}"
./scripts/dev/regenerate-ebpf-prebuilt.sh --check || error "the prebuilt lane is stale after the bump"
grep -q "TAG=${TAG}" README.md || error "README.md release examples do not mention TAG=${TAG}"
grep -q "TAG=${TAG}" docs/workflow/about-ci.md || error "docs/workflow/about-ci.md release examples do not mention TAG=${TAG}"
# The ledger line is verified like every other rewrite: the version
# sits as its own line under ## [Released].
grep -qxF "${TAG}" CHANGELOG.md || error "CHANGELOG.md ledger line for ${TAG} was not recorded"

echo "VERSION=${VERSION}"
echo "TAG=${TAG}"
echo "Updated ${bumped_surfaces}ebpf-prebuilt/, ${doc_list}and CHANGELOG.md (the mirror census re-read the tree: $(printf '%s' "${bumped_surfaces}" | wc -w) manifest surfaces bumped)"
