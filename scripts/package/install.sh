#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool.
# Copyright (C) 2026 rezky_nightky (oxyzenQ)
#
# Install script for zejtron (night-improve-27: the path law).
# ONE install path: /usr/bin - the default by law, not a flag; there
# is no --system/--user option to choose. The build step (cargo
# build --release --locked) ALWAYS runs as the current user; the
# script escalates via sudo ONLY for the /usr/bin install step.
# For the fast CPU-detected setup on your own machine, see
# install-on-my-machine.sh (builds the v3/v4 release tier).

set -euo pipefail

zejtron="zejtron"
REPO_URL="https://github.com/oxyzenQ/zejtron"
INSTALL_PATH="/usr/bin/${zejtron}"

usage() {
	cat <<EOF
Usage: $0

  Builds ${zejtron} (release, locked) and installs it to /usr/bin/${zejtron}.

  Takes no options - /usr/bin is the install path by law.
  Run WITHOUT sudo: the script escalates via sudo ONLY for the
  /usr/bin install step (a root cargo build corrupts target/).

  Service note: ${zejtron} is read-only by design - there is no
  critical service unit to install. If one ever lands, the
  convention is /etc/systemd/system/.
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "error: unknown argument: $1 - this script takes no options" >&2
		usage
		exit 2
		;;
	esac
done

# Refuse to run as root — cargo build must run as the current user.
# If run with sudo, cargo build would create root-owned files in target/,
# breaking future `cargo clean` / `cargo build` for the normal user.
# The script uses sudo internally only for the /usr/bin install step.
if [[ $EUID -eq 0 ]]; then
	echo "error: do not run this script with sudo." >&2
	echo "  cargo build would run as root, corrupting target/ ownership." >&2
	echo "  Run: $0   (sudo is used internally only for the /usr/bin install step)" >&2
	exit 1
fi

if [[ ! -f Cargo.toml ]]; then
	echo "error: Cargo.toml not found. Run this script from the repo root." >&2
	exit 1
fi

echo ">> [1/3] Building ${zejtron} (release, locked)"
cargo build --release --locked

BINARY="target/release/${zejtron}"
if [[ ! -f "${BINARY}" ]]; then
	echo "error: build produced no binary at ${BINARY}" >&2
	exit 1
fi

echo ">> [2/3] Installing ${zejtron} to ${INSTALL_PATH} (sudo for this step only)"
sudo install -Dm755 "${BINARY}" "${INSTALL_PATH}"
echo "   installed: ${INSTALL_PATH}"

echo ">> [3/3] Done."
echo
echo "Next steps:"
echo "  - Run: ${zejtron} --help"
echo "  - Service: none (read-only by design; if one lands: /etc/systemd/system/)"
echo "  - Docs: ${REPO_URL}#readme"
