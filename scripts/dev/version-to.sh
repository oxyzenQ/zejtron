#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
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
