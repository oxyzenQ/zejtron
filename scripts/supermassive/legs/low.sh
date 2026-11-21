#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial
# OS: Linux only — zejtron is a Linux introspection tool.
#
# The LOW leg: a 2 vCPU / 4 GiB class host, 85s wall budget (the
# cost contract's own growth, night-frontier-Z4 - see supermassive.sh).
# runs the FULL suite - the same surface list, the same check depth
# as the best-spec leg; only the time budget differs. Best is faster,
# never deeper.
#
#   ./scripts/supermassive/legs/low.sh [extra runner options]
set -Eeuo pipefail
SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$SUITE_DIR/supermassive.sh" --leg low "$@"
