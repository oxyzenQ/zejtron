#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# ZEJTRON ACTIONS-PIN HEALTH CHECK (sibling-project lineage:
# zelynic's scripts/gates/check-actions-pins.sh +
# scripts/ci/actions-version-sweep.sh pair, collapsed into the one
# gate zejtron's smaller estate needs).
#
# The contract: every `uses:` reference in the CI estate stays on
# the freshest version the upstream publishes, so the workflows
# never rot on stale pins. Two seats, one engine:
#   - on-demand read:   ./scripts/gates/check-actions-pins.sh
#   - maintainer heal:  ./scripts/gates/check-actions-pins.sh --apply
#       (the healed pins are committed like any other change)
#
# Advisory by default, and that is a design decision, not softness
# (the sibling's rule): pin freshness is a REMOTE fact that needs
# the network and GitHub's answer right now. zejtron's commit gate
# (scripts/build.sh check-all) is deliberately offline, so this
# check is never wired into it - a gate that blocks a contributor's
# commit on facts it cannot reach would be a dishonest gate. Run it
# before a commit that touches workflows; pass --strict to fail on
# a KNOWN-stale verdict (every skip reason stays a skip, never a
# block: offline, quota low, branch pin, SHA pin).
#
# The sweep contract, per uses: reference:
#   - a tag pin (@vN) behind the latest stable release's major heals
#     to that major's moving tag (the moving major tag already
#     carries minor/patch; the release's major is the truth).
#   - a tag pin already on the latest major is CURRENT.
#   - a branch pin (dtolnay/rust-toolchain @stable): not a version
#     pin - reported as SKIP, healed by a human decision, never by
#     a guess.
#   - a SHA pin: the pin's identity is the commit; without the
#     sibling's version-comment contract zejtron carries no SHA
#     pins, and one appearing is reported as SKIP for a human call.
#   - local (./...) and docker:// refs: out of scope by
#     construction.
#   - a pin AHEAD of the latest release: a deliberate pin wins over
#     the sweep (reported, left alone).
#
# Version truth: GitHub releases/latest (stable releases only, no
# prereleases) with a /tags fallback for release-less repos; a repo
# with neither reports SKIP honestly. Failure modes stay honest
# separately: an unreachable API and a low quota are SKIP reasons of
# their own - never a fake "no versions upstream". Set GITHUB_TOKEN
# (standard GitHub tooling convention; CI provides it natively) to
# lift the unauthenticated IP quota - the token is sent as a Bearer
# header and never written anywhere by this script. One API call per
# unique repo per run (responses memoized), well inside the
# authenticated quota for this estate's size.
#
# The diff guard: --apply may only change files under
# .github/workflows/ - anything else fails the heal before the
# tree can be committed.
#
# Usage:
#   ./scripts/gates/check-actions-pins.sh            # report only
#   ./scripts/gates/check-actions-pins.sh --strict   # exit 1 on stale
#   ./scripts/gates/check-actions-pins.sh --apply    # heal tag pins
#   ./scripts/gates/check-actions-pins.sh --apply --strict
#
# Exit codes: 0 current (or advisory skips only); 1 stale verdict
# under --strict; 2 usage error, API contract failure under
# --strict, or a diff-guard violation under --apply.

set -Eeuo pipefail

usage() {
  echo "usage: ./scripts/gates/check-actions-pins.sh [--apply] [--strict]"
  exit 2
}

APPLY=false
STRICT=false
for arg in "$@"; do
  case "${arg}" in
    --apply) APPLY=true ;;
    --strict) STRICT=true ;;
    *) usage ;;
  esac
done

repo_root="$(git rev-parse --show-toplevel)"
cd "${repo_root}"

[[ -d .github/workflows ]] || { echo "no .github/workflows directory - nothing to check"; exit 0; }
command -v curl >/dev/null 2>&1 || { echo "error: curl is required to read upstream version truth" >&2; exit 2; }

workflow_files="$(find .github/workflows -type f \( -name '*.yml' -o -name '*.yaml' \) | sort)"
[[ -n "${workflow_files}" ]] || { echo "no workflow files - nothing to check"; exit 0; }

# Memoized upstream latest-major lookup: one API call per repo per
# run. Sets LATEST_MAJOR[slug] to the major number (or empty when
# version truth is unavailable) and SKIP_REASON to the honest
# reason (quota / unreachable / no-versions) - a skip that cannot
# say why is a guess. Globals by design: command substitution would
# run this in a subshell and silently lose every assignment.
declare -A LATEST_MAJOR
declare -A LATEST_TAG
declare -A LATEST_REASON
SKIP_REASON=""
latest_major() {
  local slug="$1"
  if [[ -n "${LATEST_MAJOR[${slug}]+x}" ]]; then
    # Memoized: the stored reason travels with the verdict - an
    # unreachable or quota-limited lookup is never re-reported as
    # "no versions upstream".
    SKIP_REASON="${LATEST_REASON[${slug}]}"
    return 0
  fi
  SKIP_REASON=""
  local auth=()
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  fi
  local body="" tag="" major=""
  if ! body="$(curl -fsS -m 15 --retry 2 --retry-delay 1 --retry-all-errors \
    -H "Accept: application/vnd.github+json" -H "User-Agent: zejtron-pins-gate" \
    "${auth[@]}" \
    "https://api.github.com/repos/${slug}/releases/latest" 2>/dev/null)"; then
    # Distinguish the failure mode: quota (403/429) vs unreachable.
    local code
    code="$(curl -sS -o /dev/null -m 15 "${auth[@]}" -w '%{http_code}' \
      -H "Accept: application/vnd.github+json" -H "User-Agent: zejtron-pins-gate" \
      "https://api.github.com/repos/${slug}/releases/latest" 2>/dev/null || true)"
    if [[ "${code}" == "403" || "${code}" == "429" ]]; then
      SKIP_REASON="API quota low (HTTP ${code}): skip, retry later or set GITHUB_TOKEN"
    else
      SKIP_REASON="API unreachable (HTTP ${code:-000}): skip"
    fi
    LATEST_MAJOR["${slug}"]=""
    LATEST_TAG["${slug}"]=""
    LATEST_REASON["${slug}"]="${SKIP_REASON}"
    return 0
  fi
  tag="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' <<<"${body}" | head -1)"
  if [[ -z "${tag}" ]]; then
    # Fallback: the repo's semver tags, highest first. A repo with
    # neither a release nor semver tags reports nothing - the honest
    # skip, never a guess.
    tag="$(curl -fsS -m 15 -H "Accept: application/vnd.github+json" -H "User-Agent: zejtron-pins-gate" \
      "${auth[@]}" \
      "https://api.github.com/repos/${slug}/tags?per_page=100" 2>/dev/null \
      | sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\(v[0-9][^"]*\)".*/\1/p' | head -1 || true)"
  fi
  if [[ "${tag}" =~ ^v([0-9]+) ]]; then
    major="${BASH_REMATCH[1]}"
  else
    major=""
    SKIP_REASON="no upstream release or semver tags: human decision"
  fi
  LATEST_MAJOR["${slug}"]="${major}"
  LATEST_TAG["${slug}"]="${tag}"
  LATEST_REASON["${slug}"]="${SKIP_REASON}"
}

stale_count=0
skip_count=0
heal_count=0

classify_pin() {
  # $1 file, $2 line number, $3 uses ref (org/repo@ref, no comment)
  local file="$1" lineno="$2" ref="$3"
  local slug="${ref%%@*}"
  local pin="${ref##*@}"
  local verdict=""

  case "${pin}" in
    \./.*|\./*)
      echo "SKIP      ${file}:${lineno}  ${ref} (local action, out of scope)"
      return 0 ;;
    "")
      echo "SKIP      ${file}:${lineno}  ${ref} (empty ref)"
      return 0 ;;
  esac
  if [[ "${ref}" == docker://* ]]; then
    echo "SKIP      ${file}:${lineno}  ${ref} (docker ref, out of scope)"
    return 0
  fi
  if [[ "${pin}" =~ ^[0-9a-f]{40}$ ]]; then
    skip_count=$((skip_count + 1))
    echo "SKIP      ${file}:${lineno}  ${ref} (SHA pin: human decision, no version-comment contract)"
    return 0
  fi
  if [[ ! "${pin}" =~ ^v[0-9]+$ ]]; then
    skip_count=$((skip_count + 1))
    echo "SKIP      ${file}:${lineno}  ${ref} (branch pin: not a version pin)"
    return 0
  fi

  latest_major "${slug}"
  local major="${LATEST_MAJOR[${slug}]}"
  if [[ -z "${major}" ]]; then
    skip_count=$((skip_count + 1))
    echo "SKIP      ${file}:${lineno}  ${ref} (${SKIP_REASON})"
    return 0
  fi

  local pin_major="${pin#v}"
  if (( pin_major < major )); then
    verdict="STALE"
  elif (( pin_major > major )); then
    skip_count=$((skip_count + 1))
    echo "AHEAD     ${file}:${lineno}  ${ref} (deliberate pin wins: upstream latest major is v${major})"
    return 0
  else
    verdict="CURRENT"
  fi

  if [[ "${verdict}" == "CURRENT" ]]; then
    echo "CURRENT   ${file}:${lineno}  ${ref}"
    return 0
  fi

  # Stale tag pin.
  stale_count=$((stale_count + 1))
  if [[ "${APPLY}" == true ]]; then
    sed -i "s|uses:[[:space:]]*${slug}@${pin}\([[:space:]]*$\)|uses: ${slug}@v${major}\1|" "${file}"
    if grep -q "uses: ${slug}@v${major}" "${file}"; then
      heal_count=$((heal_count + 1))
      echo "HEAL      ${file}:${lineno}  ${ref} -> ${slug}@v${major} (upstream ${LATEST_TAG[${slug}]})"
    else
      echo "FAILED    ${file}:${lineno}  ${ref} -> heal did not land (pattern mismatch; fix by hand)"
    fi
  else
    echo "STALE     ${file}:${lineno}  ${ref} -> v${major} available (upstream ${LATEST_TAG[${slug}]}; run with --apply to heal)"
  fi
}

echo "zejtron actions-pin health check (apply=${APPLY}, strict=${STRICT})"
echo ""

while IFS= read -r file; do
  while IFS=: read -r lineno line; do
    # The uses ref up to any trailing comment; whitespace- and
    # quote-tolerant (YAML allows quoted scalars and indented keys,
    # so both ends are trimmed - a leading space would ride the
    # slug straight into the API URL).
    ref="$(sed -E 's/#.*$//; s/^[[:space:]]+//; s/[[:space:]]+$//' <<<"${line#*uses:}")"
    ref="${ref//\"/}"
    ref="${ref//\'}"
    [[ -z "${ref}" ]] && continue
    classify_pin "${file}" "${lineno}" "${ref}"
  done < <(grep -n "uses:" "${file}")
done <<<"${workflow_files}"

echo ""

if [[ "${APPLY}" == true ]]; then
  # The diff guard: the heal may only touch the workflows tree.
  local_diff="$(git diff --name-only | grep -v '^\.github/workflows/' || true)"
  if [[ -n "${local_diff}" ]]; then
    echo "DIFF GUARD: non-workflow files changed by the heal - failing closed:" >&2
    echo "${local_diff}" >&2
    exit 2
  fi
  if (( heal_count > 0 )); then
    echo "sweep verdict: ${heal_count} healed, ${stale_count} seen stale, ${skip_count} skipped"
    echo "healed pins are working-tree changes - review git diff and commit them like any other change"
  else
    echo "sweep verdict: 0 healed, ${stale_count} seen stale, ${skip_count} skipped"
  fi
else
  echo "sweep verdict: ${stale_count} stale, ${skip_count} skipped (apply=${APPLY})"
fi

if [[ "${STRICT}" == true && "${stale_count}" -gt 0 ]]; then
  echo "strict: KNOWN-stale pins present - failing" >&2
  exit 1
fi
exit 0
