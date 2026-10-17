#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool.
# Copyright (C) 2026 rezky_nightky (oxyzenQ)
#
# Uninstall script for zejtron (night-improve-27: the path law).
# The install path is /usr/bin - removed here. A legacy ~/.local/bin
# copy (from the retired --user install era) is swept too, so old
# setups do not strand a stale binary on the PATH. Sudo is used ONLY
# for system paths. Run WITHOUT sudo.

set -uo pipefail

zejtron="zejtron"
REPO_URL="https://github.com/oxyzenQ/zejtron"

usage() {
    cat <<EOF
Usage: $0

  Removes ${zejtron} from /usr/bin (the one install path) and sweeps
  a legacy ~/.local/bin copy if the retired --user install era left
  one. Sudo only for system paths.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1 - this script takes no options" >&2; usage; exit 2 ;;
    esac
done

SYSTEM_PATH="/usr/bin"
LEGACY_USER_PATH="${HOME}/.local/bin"
removed=0

remove_at() {
    local target="$1"
    local need_sudo="$2"
    if [[ -f "${target}" ]]; then
        if [[ "${need_sudo}" == "yes" ]]; then
            sudo rm -f "${target}"
        else
            rm -f "${target}"
        fi
        echo "   removed: ${target}"
        removed=$((removed+1))
    fi
}

echo ">> Uninstalling ${zejtron}"

remove_at "${SYSTEM_PATH}/${zejtron}" yes
# The retired --user era's leftover - swept, never installed here again.
remove_at "${LEGACY_USER_PATH}/${zejtron}" no

if [[ ${removed} -eq 0 ]]; then
    echo "   (nothing found to remove)"
    exit 0
fi

echo ">> Done. Removed ${removed} copy/copies."
echo "   Docs: ${REPO_URL}#readme"
