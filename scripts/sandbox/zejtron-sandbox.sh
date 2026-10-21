#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool.
#
# zejtron kernel-floor sandbox (night-improve-43) — the local KVM
# micro-VM that boots the REAL documented floor kernel and runs the
# supermassive suite inside it, as root: the jammy GA 5.15.0 kernel
# (linux-image-unsigned-5.15.0-25-generic, the exact minimum the
# README promises), a rootless-built initramfs (scripts/sandbox/
# rootfs-pack.py: ubuntu 22.04 base + iproute2 by real dependency
# resolution + the repo checkout + the payload binary; no docker, no
# host root, no install into the host). The floor kernel is the one
# no stock GitHub runner ships — this script makes the floor a LOCAL
# instrument, and the CI twin (.github/workflows/
# supermassive-kernel-floor.yml) proves the same lane on a hosted
# runner with KVM.
#
# --kernel PATH opens the arbitrary lane: any vmlinuz the operator
# wants zejtron proven on, booted under the same micro-VM shape.
# The init reports the floor direction of the booted release
# instead of gating the identity, the suite adapts by its own
# capability computation, and the payload's exit code is the
# verdict - the floor lane stays strict by construction (a marker
# at .sandbox/lane, packed only when --kernel takes a witness name
# or a PATH, never on the floor preset).
#
# The witness presets name the GA suites (the owner's ask): focal,
# jammy, noble - each resolves that Ubuntu suite's GA release-day
# kernel from the LIVE archive's main pocket through the packer's
# own suite table (the same discipline the floor kernel rides: the
# GA suite frozen by archive policy, the weekly ABI bumps
# deliberately not configured). focal is the below-floor witness
# (5.4 GA, no BTF vmlinux on GA: the attach specs run the refusal
# direction), jammy is the floor kernel ridden on the report lane,
# and noble is the above-floor witness (6.8 GA, BTF readable: the
# attach lifecycle in the success direction on a second kernel
# generation).
#
# Usage:
#   scripts/sandbox/zejtron-sandbox.sh --battery      # the supermassive low leg, root, in the VM
#   scripts/sandbox/zejtron-sandbox.sh --run <cmd...> # any root-requiring command, in the VM
#   scripts/sandbox/zejtron-sandbox.sh --shell        # interactive root bash on the VM console
#   scripts/sandbox/zejtron-sandbox.sh --self-test    # rootless preflight + packer self-test
#
# Options:
#   --kernel floor|focal|jammy|noble|PATH
#                           floor = the jammy GA 5.15.0 kernel on
#                           the strict identity lane (the default,
#                           the lane's point). A witness name
#                           (focal, jammy, noble) resolves that
#                           Ubuntu suite's GA kernel from the LIVE
#                           archive's main pocket; PATH is any local
#                           vmlinuz. Both ride the report lane: the
#                           init reports the floor direction instead
#                           of gating the identity, the suite adapts
#                           by its own capability computation, and
#                           the payload's exit code is the verdict
#   --binary PATH           the zejtron payload binary (default: the
#                           newest repo build — every cargo alias
#                           output is a candidate; without /dev/kvm
#                           the static musl builds win instead, the
#                           safest under TCG emulation)
#   --envelope low|best     low = quarter cores / eighth RAM
#                           (default, the low-spec leg's math);
#                           best = every core / three quarters
#   --net                   user-mode networking (default OFF — the
#                           suite is loopback-only, the VM contract)
#   --timeout SECONDS       outer VM budget (default 1800)
#   --keep                  keep the boot log at $CACHE/vm.log
#
# Requirements: qemu-system-x86_64, python3, git. /dev/kvm is
# OPTIONAL: without it the VM boots under TCG software emulation
# (-cpu max) with a loud warning — slower, and the low leg's 60s
# wall budget may breach under emulation (the budget is a real-
# hardware contract; CI's KVM leg holds it), but every check still
# runs and reports. The binary probe prefers a static musl build
# under TCG (arch-baseline gnu builds run too; the native-CPU and
# v3/v4 gnu shapes may SIGILL under emulation's -cpu max).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CACHE="${ZEJTRON_SANDBOX_CACHE:-${HOME}/.cache/zejtron-sandbox}"

KERNEL="floor"
BINARY=""
ENVELOPE="low"
NET=0
TIMEOUT=1800
KEEP=0
MODE=""

note() { echo "[sandbox] $*"; }
die() {
        echo "[sandbox] FAIL: $*" >&2
        exit 1
}

usage() {
        # The usage block only — the copyright and design notes above
        # it are not CLI help, and the Requirements paragraph below
        # the option table is not either. The end marker owns the
        # slice (the NIGHT-blade-10 lesson, retired whole: a fixed
        # head-N sliced the option table whenever the header grew,
        # and the old head-30 was already leaking Requirements lines
        # into the help - the block now ends where its own marker
        # says it ends).
        sed -n 's/^# //p' "${BASH_SOURCE[0]}" \
                | sed -n '/^Usage:/,/^Requirements:/p' \
                | sed '/^Requirements:/d' \
                | sed '/^$/d'
        exit "${1:-0}"
}

# ── arguments ───────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
        case "$1" in
        --battery)
                MODE="battery"
                shift
                ;;
        --shell)
                MODE="shell"
                shift
                ;;
        --run)
                MODE="run"
                shift
                break
                ;;
        --kernel)
                KERNEL="${2:?}"
                shift 2
                ;;
        --binary)
                BINARY="${2:?}"
                shift 2
                ;;
        --envelope)
                ENVELOPE="${2:?}"
                shift 2
                ;;
        --net)
                NET=1
                shift
                ;;
        --timeout)
                TIMEOUT="${2:?}"
                shift 2
                ;;
        --keep)
                KEEP=1
                shift
                ;;
        --self-test)
                MODE="selftest"
                shift
                ;;
        -h | --help) usage 0 ;;
        *)
                echo "unknown flag: $1" >&2
                usage 2
                ;;
        esac
done

# --run owns the rest of argv as ONE command line (an empty --run
# would pack a payload that ran nothing and still reported PASS —
# the sibling's NIGHT-blade-10 lesson).
if [ "${MODE}" = "run" ] && [ $# -eq 0 ]; then
        die "--run needs a command (e.g. --run ./zejtron doctor)"
fi

# ── self-test: rootless, no VM, no boot ─────────────────────────────────
if [ "$MODE" = "selftest" ]; then
        note "self-test (rootless: syntax, packer units, tool presence — no VM boot)"
        if bash -n "${BASH_SOURCE[0]}"; then
                note "entrypoint bash syntax" OK
        else
                die "entrypoint bash syntax"
        fi
        if bash -n "${SCRIPT_DIR}/sandbox-init.sh"; then
                note "init bash syntax" OK
        else
                die "init bash syntax"
        fi
        python3 "${SCRIPT_DIR}/rootfs-pack.py" self-test || die "packer self-test"
        for tool in qemu-system-x86_64 python3 git; do
                if command -v "$tool" >/dev/null 2>&1; then
                        note "tool $tool present (OK)"
                else
                        note "tool $tool MISSING — needed to boot (install qemu-system-x86 etc.)"
                fi
        done
        if [ -w /dev/kvm ]; then
                note "/dev/kvm usable — KVM acceleration"
        else
                note "/dev/kvm absent — TCG software emulation (slower; prefer the musl binary)"
        fi
        note "self-test done (all checks above are advisory; the packer units are the verdict)"
        exit 0
fi

# ── preflight ───────────────────────────────────────────────────────────
[ "$MODE" = "run" ] || [ "$MODE" = "shell" ] || [ "$MODE" = "battery" ] || usage 2

command -v qemu-system-x86_64 >/dev/null 2>&1 ||
        die "qemu-system-x86_64 not found — install it (Debian/Ubuntu: apt install qemu-system-x86)"
command -v python3 >/dev/null 2>&1 || die "python3 not found"
command -v git >/dev/null 2>&1 || die "git not found"

mkdir -p "${CACHE}"

# Acceleration: KVM host-passthrough when available (the CI contract
# — "native" is honest under -cpu host), else TCG with -cpu max and a
# loud warning (native-CPU and v3/v4 gnu binaries may SIGILL under
# emulation; the binary probe prefers a static build for this reason).
ACCEL_FLAGS=(-machine "q35,accel=kvm" -cpu host)
if [ ! -w /dev/kvm ]; then
        note "WARNING: /dev/kvm not usable — falling back to TCG software emulation."
        note "         Slower (the low leg's 60s wall budget may breach), and the"
        note "         native/v3/v4 gnu builds may SIGILL; the binary probe prefers"
        note "         a static musl build for this reason."
        ACCEL_FLAGS=(-machine "q35,accel=tcg" -cpu max)
fi

# ── the binary payload ──────────────────────────────────────────────────
# The probe speaks the repo's build-alias discipline: every cargo
# alias output (.cargo/config.toml) is a candidate and among the ones
# that exist the NEWEST mtime wins ("pack what was just built").
# One launcher doctrine survives from the sibling: under TCG the
# STATIC group outranks the dynamic gnu group (-cpu max emulates the
# ISA, not the host — the SIGILL warning above), so TCG packs the
# newest musl build and only falls back to a gnu build when no
# static one exists; under KVM the newest build wins outright
# (host-passthrough runs every shape). The plain musl release (the
# no-alias cargo build --release --target x86_64-unknown-linux-musl
# output) stays a candidate in both groups — the arch-baseline
# static shape, the safest under emulation.
newest_binary() {
        local best="" cand
        for cand in "$@"; do
                if [ -x "${cand}" ] && { [ -z "${best}" ] || [ "${cand}" -nt "${best}" ]; }; then
                        best="${cand}"
                fi
        done
        if [ -n "${best}" ]; then
                printf '%s\n' "${best}"
        fi
}

if [ -z "${BINARY}" ]; then
        MUSL_DIR="${REPO_ROOT}/target/x86_64-unknown-linux-musl"
        if [ -w /dev/kvm ]; then
                BINARY="$(newest_binary \
                        "${REPO_ROOT}/target/release/zejtron" \
                        "${REPO_ROOT}/target/pro-native-gnu/zejtron" \
                        "${MUSL_DIR}/pro-native-musl/zejtron" \
                        "${REPO_ROOT}/target/pro-linux-amd64-v3-gnu/zejtron" \
                        "${REPO_ROOT}/target/pro-linux-amd64-v4-gnu/zejtron" \
                        "${MUSL_DIR}/pro-linux-amd64-v3-musl/zejtron" \
                        "${MUSL_DIR}/pro-linux-amd64-v4-musl/zejtron" \
                        "${MUSL_DIR}/release/zejtron")"
        else
                BINARY="$(newest_binary \
                        "${MUSL_DIR}/pro-native-musl/zejtron" \
                        "${MUSL_DIR}/pro-linux-amd64-v3-musl/zejtron" \
                        "${MUSL_DIR}/pro-linux-amd64-v4-musl/zejtron" \
                        "${MUSL_DIR}/release/zejtron")"
                if [ -z "${BINARY}" ]; then
                        BINARY="$(newest_binary \
                                "${REPO_ROOT}/target/release/zejtron" \
                                "${REPO_ROOT}/target/pro-native-gnu/zejtron" \
                                "${REPO_ROOT}/target/pro-linux-amd64-v3-gnu/zejtron" \
                                "${REPO_ROOT}/target/pro-linux-amd64-v4-gnu/zejtron")"
                fi
        fi
fi
if [ -n "${BINARY}" ] && [ -x "${BINARY}" ]; then
        # Under TCG the gnu builds may SIGILL (-cpu max emulates the ISA,
        # not the host's speed); a STATIC binary never draws the warning
        # — ldd fails on static-pie, which is exactly the tell.
        if [ ! -w /dev/kvm ]; then
                case "${BINARY}" in
                *musl*) ;;
                *)
                        if ldd "${BINARY}" >/dev/null 2>&1; then
                                note "WARNING: ${BINARY} is a dynamic glibc build — under TCG the native/v3/v4 shapes may SIGILL"
                        fi
                        ;;
                esac
        fi
else
        die "no zejtron binary — build one (cargo build --release --locked) or pass --binary PATH"
fi
note "binary: ${BINARY}"

# ── the kernel ──────────────────────────────────────────────────────────
# The lane rides the kernel choice: floor resolves the documented
# floor kernel (the strict identity lane); a witness name resolves
# that suite's GA kernel and a PATH is any local vmlinuz - both are
# the report lane, the init reporting the floor direction instead
# of gating the identity. One table in the packer owns every
# resolution; the strict lane refuses a wrong kernel by name.
LANE="floor"
case "${KERNEL}" in
floor)
        VMLINUZ="$(python3 "${SCRIPT_DIR}/rootfs-pack.py" kernel --suite floor --cache "${CACHE}")" ||
                die "kernel resolution failed"
        ;;
focal | jammy | noble)
        VMLINUZ="$(python3 "${SCRIPT_DIR}/rootfs-pack.py" kernel --suite "${KERNEL}" --cache "${CACHE}")" ||
                die "kernel resolution failed"
        LANE="arbitrary"
        ;;
*)
        VMLINUZ="${KERNEL}"
        LANE="arbitrary"
        ;;
esac
[ -f "${VMLINUZ}" ] || die "kernel not found: ${VMLINUZ}"
note "kernel: ${VMLINUZ} (lane: ${LANE})"

# ── the payload script (packed into the image; the init runs it) ────────
PAYLOAD="$(mktemp "${CACHE}/payload.XXXXXX.sh")"
trap 'rm -f "${PAYLOAD}"' EXIT
case "${MODE}" in
battery)
        cat >"${PAYLOAD}" <<'EOF'
#!/usr/bin/env bash
# The canonical low leg, root, inside the micro-VM: the FULL
# supermassive suite (every surface, every flag, every error path)
# against the packed binary, on the booted kernel (the floor lane:
# the exact documented 5.15.0; the report lane: whatever --kernel
# named - a witness preset or a PATH). Each leg's exit code is a
# verdict row; the init relays the final one.
set -u
cd /opt/zejtron
bash scripts/supermassive/legs/low.sh --bin /opt/zejtron/zejtron
rc=$?
if [ "$rc" -eq 0 ]; then
        verdict=PASS
else
        verdict=FAIL
fi
echo "SANDBOX-RESULT: supermassive low leg (full suite, root, booted kernel) - $verdict"
[ "$rc" -eq 0 ]
EOF
        ;;
shell)
        cat >"${PAYLOAD}" <<'EOF'
#!/usr/bin/env bash
# Interactive root shell on the serial console; exit to end the VM.
export TERM=linux
cd /opt/zejtron
echo "zejtron kernel-floor sandbox — root shell in a throwaway kernel ($(uname -r))"
echo "repo at /opt/zejtron, binary at /opt/zejtron/zejtron — exit ends the VM."
bash -i
EOF
        ;;
run)
        {
                echo '#!/usr/bin/env bash'
                echo 'set -u'
                echo 'cd /opt/zejtron'
                # shellcheck disable=SC2016  # the payload expands TERM at ITS runtime
                echo 'export TERM=${TERM:-dumb}'
                # Each argument quoted verbatim — no eval, no shell parsing.
                quote() { printf '%q ' "$1"; }
                { printf 'bash -c %s' "$(quote "$*")"; }
                echo
        } >"${PAYLOAD}"
        ;;
esac
chmod +x "${PAYLOAD}"

# ── the initramfs (rootless build, cached debs make re-runs fast) ───────
INITRD="${CACHE}/initrd.gz"
note "building the initramfs (first run downloads ~100 MiB, cached afterwards)..."
python3 "${SCRIPT_DIR}/rootfs-pack.py" initrd \
        --cache "${CACHE}" \
        --repo "${REPO_ROOT}" \
        --binary "${BINARY}" \
        --init "${SCRIPT_DIR}/sandbox-init.sh" \
        --payload "${PAYLOAD}" \
        --lane "${LANE}" || die "initramfs build failed"
[ "${KEEP}" -eq 1 ] || rm -f "${PAYLOAD}"
trap - EXIT
note "initramfs: ${INITRD}"

# ── the envelope (the low leg's math, the CI twin's shape) ──────────────
CORES="$(nproc)"
TOTAL_MB="$(free -m | awk '/^Mem:/{print $2}')"
case "${ENVELOPE}" in
low)
        SMP=$((CORES / 4))
        [ "$SMP" -lt 1 ] && SMP=1
        MEM=$((TOTAL_MB / 8))
        [ "$MEM" -lt 1024 ] && MEM=1024
        ;;
best)
        SMP="$CORES"
        MEM=$((TOTAL_MB * 3 / 4))
        ;;
*)
        die "unknown envelope: ${ENVELOPE} (low|best)"
        ;;
esac
note "envelope: ${SMP} vCPU / ${MEM} MB (${ENVELOPE}, of ${CORES} cores / ${TOTAL_MB} MB)"

# ── boot ────────────────────────────────────────────────────────────────
NET_FLAGS=()
if [ "$NET" -eq 1 ]; then
        NET_FLAGS=(-netdev "user,id=n0" -device "virtio-net-pci,netdev=n0")
        note "user-mode networking ON (egress through the host)"
fi
VM_LOG="${CACHE}/vm.log"
note "booting the ${LANE}-lane micro-VM (timeout ${TIMEOUT}s; serial console follows)..."
set +e
timeout "${TIMEOUT}" qemu-system-x86_64 \
        "${ACCEL_FLAGS[@]}" \
        -m "${MEM}" -smp "${SMP}" \
        -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
        -kernel "${VMLINUZ}" \
        -initrd "${INITRD}" \
        -append "console=ttyS0 panic=-1" \
        "${NET_FLAGS[@]}" \
        -nographic -no-reboot 2>&1 | tee "${VM_LOG}"
QEMU_RC=${PIPESTATUS[0]}
set -e

# rc 0 = a natural poweroff; rc 1 = the guest's deliberate
# isa-debug-exit (the verdict rides the SANDBOX-* sentinel lines).
# Anything else — the timeout (124), a KVM init failure — fails HERE.
if [ "$QEMU_RC" -ne 0 ] && [ "$QEMU_RC" -ne 1 ]; then
        echo "[sandbox] FAIL: qemu exited ${QEMU_RC} — log tail:"
        tail -40 "${VM_LOG}"
        exit 1
fi

# ── the verdict (the sentinel lines are the contract) ───────────────────
echo "── sandbox verdicts ──"
grep -E '^SANDBOX-(RESULT|VERDICT)' "${VM_LOG}" || true
if grep -q '^SANDBOX-VERDICT: PASS' "${VM_LOG}"; then
        echo "[sandbox] OK: the payload ran green inside the ${LANE}-lane micro-VM"
        exit 0
fi
echo "[sandbox] FAIL: the VM did not report PASS (log: ${VM_LOG})"
exit 1
