#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool.
#
# The BEST leg: a many-core / high-RAM host, 300s wall budget. The
# leg runs the FULL suite - the identical surface list and check
# depth as the low-spec leg; the budget only buys headroom, never
# extra depth and never a reduced depth on the small leg.
#
#   ./scripts/supermassive/legs/best.sh [extra runner options]
set -Eeuo pipefail
SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$SUITE_DIR/supermassive.sh" --leg best "$@"
