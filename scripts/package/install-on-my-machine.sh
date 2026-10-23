#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool.
# Copyright (C) 2026 rezky_nightky (oxyzenQ)
#
# INSTALL-ON-MY-MACHINE (night-improve-27): the one-command fast
# setup for the owner's own box. Detects the CPU's x86-64 microarch
# level, builds the release-tier binary with the exact alias the
# release matrix is parity-gated against, and installs it to
# /usr/bin — the one install path, by default, with no flags.
#
# The contract:
#   1. Linux only, amd64 only (the only shapes zejtron ships).
#   2. CPU detect: x86-64-v4 if the core carries the AVX-512 baseline,
#      else x86-64-v3 if it carries the AVX2 baseline, else refuse —
#      v3/v4 are the only shapes the release matrix builds, and a
#      v1/v2 core gets the honest pointer to the native dev build.
#   3. Build: cargo pro-linux-amd64-v{3,4}-musl - the arch-baseline
#      alias whose rustflags check-release-parity.sh pins equal to
#      the release matrix, so what lands on this machine is the
#      shipped optimization tier, bit-for-bit. The build is fully
#      static musl (the only libc shape) and runs as the
#      current user (a root build corrupts target/ ownership).
#   4. Install: /usr/bin/zejtron. ONE path, the default, no
#      --system/--user option to choose - the script escalates sudo
#      for the install step ONLY.
#   5. Service: zejtron is read-only by design - there is NO critical
#      service unit to install. If the project ever grows one, the
#      convention is /etc/systemd/system/ (documented here so the
#      future lane lands consistent).

set -euo pipefail

zejtron="zejtron"
REPO_URL="https://github.com/oxyzenQ/zejtron"

usage() {
	cat <<EOF
Usage: $0

  Fast setup for this machine: detect the CPU's x86-64 level
  (v3/v4), build the release-tier binary, install to /usr/bin/${zejtron}.

  Takes no options - the install path is /usr/bin by law, not a flag.
  Run as your normal user; sudo is escalated internally for the
  /usr/bin install step only.

  Requires: rust (the pinned toolchain via rust-toolchain.toml), the
  musl rust-std target (added automatically), and a Linux on x86-64
  (the build is fully static musl).
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

# 1. Platform gates: Linux, x86-64, repo root.
if [[ "$(uname -s)" != "Linux" ]]; then
	echo "error: $(uname -s) is not Linux - zejtron is a Linux tool." >&2
	exit 1
fi
if [[ "$(uname -m)" != "x86_64" ]]; then
	echo "error: $(uname -m) is not amd64 - the release shapes are x86-64-v3/v4 only." >&2
	exit 1
fi
if [[ ! -f Cargo.toml || ! -f .cargo/config.toml ]]; then
	echo "error: run this script from the zejtron repo root." >&2
	exit 1
fi

# Refuse to run as root - the build step must run as the current user
# (a root build creates root-owned files in target/, breaking every
# future cargo clean/build for the normal user). sudo is escalated
# internally for the /usr/bin install step only.
if [[ $EUID -eq 0 ]]; then
	echo "error: do not run this script with sudo." >&2
	echo "  the build step would run as root, corrupting target/ ownership." >&2
	echo "  Run: $0   (sudo is used internally only for /usr/bin)" >&2
	exit 1
fi

# 2. CPU detect: the x86-64 microarch level from /proc/cpuinfo flags.
flags="$(grep -m1 '^flags' /proc/cpuinfo)"
detect_level() {
	# v4 baseline: AVX-512 Foundation + BW + CD + DQ + VL.
	if [[ "$flags" =~ avx512f ]] && [[ "$flags" =~ avx512bw ]] &&
		[[ "$flags" =~ avx512cd ]] && [[ "$flags" =~ avx512dq ]] &&
		[[ "$flags" =~ avx512vl ]]; then
		echo "v4"
		return 0
	fi
	# v3 baseline: AVX2 + BMI2 + FMA (the load-bearing trio), plus
	# the rest of the level's required surface where present.
	if [[ "$flags" =~ avx2 ]] && [[ "$flags" =~ bmi2 ]] &&
		[[ "$flags" =~ fma ]] && [[ "$flags" =~ sse4_2 ]] &&
		[[ "$flags" =~ ssse3 ]] && [[ "$flags" =~ avx ]] &&
		[[ "$flags" =~ bmi1 ]] && [[ "$flags" =~ movbe ]]; then
		echo "v3"
		return 0
	fi
	return 1
}
LEVEL="$(detect_level)" || {
	echo "error: this core is below the x86-64-v3 baseline." >&2
	echo "  the release shapes are v3/v4 only - on a v1/v2 machine build" >&2
	echo "  the native dev tier instead: cargo install --path ." >&2
	exit 1
}
echo ">> [1/4] CPU level detected: x86-64-${LEVEL}"

ALIAS="pro-linux-amd64-${LEVEL}-musl"

# The alias builds for the musl triple: its rust-std target must be
# installed (idempotent; the alias links through rust-lld, so the
# target is the only prerequisite - see .cargo/config.toml).
if ! rustup target list --installed 2>/dev/null | grep -q '^x86_64-unknown-linux-musl$'; then
	echo ">> Adding the musl rust-std target (rustup target add)"
	rustup target add x86_64-unknown-linux-musl
fi

# 3. Build: the release-tier alias (parity-gated against the matrix).
echo ">> [2/4] Building the release tier: cargo ${ALIAS}"
cargo "${ALIAS}"
BINARY="target/x86_64-unknown-linux-musl/${ALIAS}/${zejtron}"
if [[ ! -f "${BINARY}" ]]; then
	# The musl alias builds into target/x86_64-unknown-linux-musl/<profile>/;
	# fall back to a find so a profile rename upstream cannot strand
	# the installer.
	BINARY="$(find target -maxdepth 3 -type f -name "${zejtron}" -perm -u+x | head -1 || true)"
fi
if [[ -z "${BINARY}" || ! -f "${BINARY}" ]]; then
	echo "error: build produced no ${zejtron} binary under target/." >&2
	exit 1
fi
echo "   built: ${BINARY}"

# 4. Install: /usr/bin - the one path, by default, no flag.
echo ">> [3/4] Installing to /usr/bin/${zejtron} (sudo for this step only)"
sudo install -Dm755 "${BINARY}" "/usr/bin/${zejtron}"
echo "   installed: /usr/bin/${zejtron}"

# 5. Verify: the version report from the installed path.
echo ">> [4/4] Verify"
/usr/bin/"${zejtron}" -V
if ! command -v "${zejtron}" >/dev/null 2>&1; then
	echo "note: /usr/bin is not on this shell's PATH yet - open a new shell." >&2
fi
echo
echo "Service: none - ${zejtron} is read-only by design; there is no"
echo "  critical service unit to install. If one ever lands, the"
echo "  convention is /etc/systemd/system/."
echo
echo "Next: ${zejtron} --help   |   Docs: ${REPO_URL}#readme"
