#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool.
#
# determinism-certificate.sh (night-frontier-Z2, E1) — the "two
# conformant runs diff to empty" law as a LIVING PROOF. The test
# suite's determinism_evidence pins prove renders are pure functions
# of their fixtures; this script proves the same claim across two
# INDEPENDENT PROCESS INVOCATIONS: render the canonical fixtures
# twice, each run into its own directory, then diff the two
# directories. An empty diff is the certificate; any difference is a
# broken determinism claim, and the leg fails.
#
# The fixtures and their hermeticity contract live in
# test/evidence/certificate_tests.rs (the module doc names what may
# and may not consult the host). This script owns only the protocol:
# two invocations, one diff, one verdict, one summary line.
#
# Usage:
#   ./scripts/ci/determinism-certificate.sh [workdir]
#
# Exit codes: 0 certificate issued (empty diff); 1 the renders
# differed (the law is broken); 2 usage/prerequisite failure.

set -Eeuo pipefail
cd "$(dirname "$0")/../.." # repo root

WORK="${1:-target/determinism-certificate}"
mkdir -p "$WORK"
RUN1="$WORK/run-1"
RUN2="$WORK/run-2"
rm -rf "$RUN1" "$RUN2"

# Two independent invocations: each loads the binary fresh, renders
# the fixtures, writes them under its own directory. The test filter
# pins the certificate module (the rest of the suite runs in the
# ordinary gates).
ZEJTRON_CERT_OUT="$RUN1" cargo test --bin zejtron the_certificate_
ZEJTRON_CERT_OUT="$RUN2" cargo test --bin zejtron the_certificate_

# The verdict: the two directories must be byte-identical, manifest
# included.
if diff -r "$RUN1" "$RUN2" > "$WORK/diff.txt" 2>&1; then
	CERT_SHA=$(b3sum "$RUN1"/*.txt | b3sum | awk '{print $1}')
	SHA=$(git rev-parse HEAD)
	{
		echo "## Determinism certificate (night-frontier-Z2, E1)"
		echo ""
		echo "- fixtures rendered: $(ls "$RUN1"/*.txt | grep -cv manifest) + manifest"
		echo "- invocations: 2 independent cargo test processes"
		echo "- byte diff between invocations: EMPTY (diff -r exit 0)"
		echo "- certificate digest (blake3 over the rendered bytes): $CERT_SHA"
		echo "- commit: $SHA"
	} | tee "$WORK/certificate.txt"
	echo "CERTIFICATE: the two conformant runs diff to empty - the claim is live."
	exit 0
else
	echo "CERTIFICATE REFUSED: the two invocations differed - the determinism \
		law is broken. The diff rides $WORK/diff.txt:" >&2
	cat "$WORK/diff.txt" >&2
	exit 1
fi
