#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: MIT

set -euo pipefail

PROJECT_NAME="zejtron"
PREFIX="${PREFIX:-${HOME}/.local}"
BINDIR="${DESTDIR:-}${PREFIX}/bin"

rm -f "${BINDIR}/${PROJECT_NAME}"
echo "${PROJECT_NAME} removed from ${BINDIR}/${PROJECT_NAME}"
