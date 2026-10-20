#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool.
#
# The LOW leg: a 2 vCPU / 4 GiB class host, 60s wall budget. The leg
# runs the FULL suite - the same surface list, the same check depth
# as the best-spec leg; only the time budget differs. Best is faster,
# never deeper.
#
#   ./scripts/supermassive/legs/low.sh [extra runner options]
set -Eeuo pipefail
SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$SUITE_DIR/supermassive.sh" --leg low "$@"
