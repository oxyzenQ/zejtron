#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — the extraction walks kernel image formats.
#
# corpus-extract-dialect.sh — the kernel dialect extraction instrument
# (night-frontier-Z3): ONE implementation, TWO seats.
#
#   Seat 1 (the corpus): the maintainer runs it against a real kernel
#   package to produce the frozen .BTF blob committed under corpus/btf/
#   (the provenance law lives in corpus/README.md).
#
#   Seat 2 (the CI echo): the kernel-witness lane runs it against the
#   SAME package the sandbox just booted, prints the digest into the
#   step summary, uploads the blob as a run artifact, and — where the
#   suite's package is archive-frozen — asserts the digest equals the
#   corpus pin, so a frozen dialect's live bytes are re-proven against
#   the frozen bytes on every push.
#
# The instrument extracts the `.BTF` section from the compressed
# kernel payload: the input's kernel image is located, the compressed
# vmlinux inside it is unwrapped (the gzip/xz/zstd/lz4/lzma magics the
# kernel's own extract-vmlinux walk covers), and the .BTF section is
# copied out with objcopy. Nothing is synthesized: the bytes written
# are the kernel build's own BTF, verbatim.
#
# Refusal law: an input whose payload carries no .BTF section (a
# pre-BTF kernel — the focal GA 5.4 line) refuses BY NAME with exit 1
# and a "no .BTF section" verdict on stdout. The absence is a dialect
# fact like any other - the witness lane asserts that refusal
# direction, the corpus records the absence as provenance.
#
# Usage:
#   corpus-extract-dialect.sh <input> <output.btf>
#
#   <input>  a kernel package (a linux-image .deb, a cachyos
#            .pkg.tar.zst) or a bare kernel image (vmlinuz/bzImage)
#   <output.btf>  where the raw .BTF section bytes land
#
# On success the script prints a report block: the resolved kernel
# image, the kernel version string read out of the payload, the .BTF
# size, and the sha256 of the emitted bytes (the CI echo's digest).
# The corpus test pins the tree's own blake3; the derivation harness
# (`cargo test the_btf_corpus -- --nocapture`) prints that one.

set -Eeuo pipefail

usage() {
	echo "usage: $0 <input: .deb | .pkg.tar.zst | vmlinuz> <output.btf>" >&2
	exit 2
}

die() {
	echo "FAIL: $1" >&2
	exit 1
}

need() {
	command -v "$1" >/dev/null 2>&1 || die "required tool '$1' not found on PATH"
}

[[ $# -eq 2 ]] || usage
INPUT=$1
OUTPUT=$2
[[ -f "$INPUT" ]] || die "input '$INPUT' is not a file"
need objcopy

WORK=$(mktemp -d "${TMPDIR:-/tmp}/zejtron-btf-extract.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# ── zstd: the binary, or the python shim ────────────────────────────
# The CI runner image ships zstd; a minimal instrument box may not.
# The shim decompresses a single-member stream from stdin to stdout
# through the python-zstandard module - the same frames, no drift.
zstd_stream() {
	if command -v zstd >/dev/null 2>&1; then
		zstd -d -c
	else
		python3 -c '
import sys, zstandard
dctx = zstandard.ZstdDecompressor()
writer = sys.stdout.buffer
with dctx.stream_reader(sys.stdin.buffer) as reader:
    while True:
        chunk = reader.read(1 << 20)
        if not chunk:
            break
        writer.write(chunk)
    writer.flush()
'
	fi
}

# ── locate the kernel image inside the input ────────────────────────
KERNEL_IMG="$WORK/kernel.img"
case "$INPUT" in
*.deb)
	need dpkg-deb
	dpkg-deb -x "$INPUT" "$WORK/pkg" || die "cannot unpack the deb '$INPUT'"
	# Ubuntu/Debian linux-image packages carry the compressed kernel
	# at ./boot/vmlinuz-<version> (some layouts ride
	# ./usr/lib/modules/<version>/vmlinuz).
	KIMG=$(find "$WORK/pkg" -type f \( -path '*/boot/vmlinuz*' -o -path '*/usr/lib/modules/*/vmlinuz' \) | head -n 1)
	[[ -n "$KIMG" ]] || die "the deb carries no vmlinuz (layout drifted?)"
	cp "$KIMG" "$KERNEL_IMG"
	;;
*.pkg.tar.zst)
	# The arch package layout: usr/lib/modules/<version>/vmlinuz.
	zstd_stream <"$INPUT" >"$WORK/pkg.tar" || die "cannot decompress the arch package '$INPUT'"
	tar -xf "$WORK/pkg.tar" -C "$WORK" ./usr/lib/modules 2>/dev/null ||
		tar -xf "$WORK/pkg.tar" -C "$WORK" ||
		die "cannot unpack the arch package tarball"
	KIMG=$(find "$WORK" -type f -path '*/usr/lib/modules/*/vmlinuz' | head -n 1)
	[[ -n "$KIMG" ]] || die "the arch package carries no vmlinuz (layout drifted?)"
	cp "$KIMG" "$KERNEL_IMG"
	;;
*)
	# A bare kernel image: used as-is.
	cp "$INPUT" "$KERNEL_IMG"
	;;
esac

# ── unwrap the compressed vmlinux payload ───────────────────────────
# The bzImage layout: a setup header, then the compressed payload.
# The walk finds the first decompressor magic that decompresses into
# an ELF image - the kernel's own extract-vmlinux order, one truth.
# The walk rides an embedded python block: the xz magic ends in a NUL
# byte no shell variable can carry, a slice beats a byte-at-a-time
# skip on a hundred-megabyte image, and decompressor magics have
# false positives INSIDE compressed payloads - every occurrence is
# tried, not just the first (the first-run finding this instrument
# fixed the same night). zstd and lz4 fall back to the python
# modules when their binaries are absent (the shim seat).
VMLINUX="$WORK/vmlinux"
python3 - "$KERNEL_IMG" "$VMLINUX" <<'PYWALK' || die "cannot unwrap the compressed vmlinux payload of '$INPUT' (no known decompressor magic matched an ELF image)"
import io
import os
import subprocess
import sys

kernel_img, vmlinux_out = sys.argv[1], sys.argv[2]

MAGICS = [
    (b"\x1f\x8b\x08", ["gzip", "-d", "-c"]),
    (b"\xfd7zXZ\x00", ["xz", "-d", "-c"]),
    (b"\x02!L\x18", ["lz4", "-d", "-c"]),
    (b"\x28\xb5\x2f\xfd", ["zstd", "-d", "-c"]),
    (b"\x5d\x00\x00", ["lzma", "-d", "-c"]),
]


def module_zstd(data):
    import zstandard

    dctx = zstandard.ZstdDecompressor().decompressobj()
    out = io.BytesIO()
    for start in range(0, len(data), 1 << 20):
        out.write(dctx.decompress(data[start : start + (1 << 20)]))
    return out.getvalue()


def module_lz4(data):
    """The kernel's CONFIG_KERNEL_LZ4 piggyback rides the LEGACY lz4
    container (0x184C2102) - python-lz4 only speaks the frame format,
    so the legacy walk rides here: [magic][u32 csize][block] repeating,
    fixed 8MB chunks, NO end marker (the walk stops at the first block
    that does not decode - the bytes past the last block are the
    image's own padding). Frame-format payloads ride lz4.frame."""
    if data[:4] == b"\x02!L\x18":
        import struct

        def block_decode(blk):
            out = bytearray()
            j = 0
            n = len(blk)
            while j < n:
                token = blk[j]
                j += 1
                lit_len = token >> 4
                if lit_len == 15:
                    while True:
                        b = blk[j]
                        j += 1
                        lit_len += b
                        if b != 255:
                            break
                out += blk[j : j + lit_len]
                j += lit_len
                if j >= n:
                    break
                offset = blk[j] | (blk[j + 1] << 8)
                j += 2
                match_len = (token & 0xF) + 4
                if (token & 0xF) == 15:
                    while True:
                        b = blk[j]
                        j += 1
                        match_len += b
                        if b != 255:
                            break
                start = len(out) - offset
                if offset == 0 or start < 0:
                    raise ValueError("bad offset")
                for k in range(match_len):
                    out.append(out[start + k])
            return bytes(out)

        out = bytearray()
        i = 4
        while i + 4 <= len(data):
            (csize,) = struct.unpack_from("<I", data, i)
            i += 4
            if csize == 0 or csize > len(data) - i:
                break
            try:
                out += block_decode(data[i : i + csize])
            except (ValueError, IndexError):
                break
            i += csize
        return bytes(out)
    import lz4.frame

    return lz4.frame.decompress(data)


def try_tool(tool, data):
    """The binary first; the python shim when the binary is absent.
    The exit code is NOT the verdict: a decompressor can emit the
    full payload and still exit nonzero on the image's trailing
    padding (the bookworm xz stream, the first-run finding this
    instrument fixed the same night) - the ELF check below owns the
    verdict, exactly the kernel's own extract-vmlinux contract."""
    try:
        proc = subprocess.run(tool, input=data, stdout=subprocess.PIPE)
        if proc.returncode == 0 or proc.stdout:
            return proc.stdout or None
    except OSError:
        pass
    try:
        if tool[0] == "zstd":
            return module_zstd(data)
        if tool[0] == "lz4":
            return module_lz4(data)
    except Exception:
        return None
    return None


with open(kernel_img, "rb") as fh:
    image = fh.read()

for magic, tool in MAGICS:
    # Every occurrence: a magic inside compressed data is noise, the
    # payload's own magic is the signal - one failure is not a verdict.
    offsets = []
    at = image.find(magic)
    while at >= 0 and len(offsets) < 16:
        offsets.append(at)
        at = image.find(magic, at + 1)
    for offset in offsets:
        out = try_tool(tool, image[offset:])
        if out and out[:4] == b"\x7fELF":
            with open(vmlinux_out, "wb") as out_fh:
                out_fh.write(out)
            sys.exit(0)
sys.exit(1)
PYWALK

# ── the kernel version, read out of the payload ─────────────────────
KVER=$(strings "$VMLINUX" | grep -m1 -E '^Linux version [0-9]' | cut -d' ' -f3 || true)

# ── the .BTF section ────────────────────────────────────────────────
objcopy -O binary -j .BTF "$VMLINUX" "$OUTPUT" 2>/dev/null ||
	die "objcopy could not copy the .BTF section of the unwrapped payload"
SIZE=$(wc -c <"$OUTPUT")
if [[ ! -s "$OUTPUT" ]]; then
	# The named absence: a pre-BTF kernel (the focal GA 5.4 line).
	# The refusal IS the verdict the witness lane asserts.
	echo "no .BTF section in the unwrapped payload${KVER:+ (kernel $KVER)} - this kernel dialect carries no BTF (pre-5.2 build or CONFIG_DEBUG_INFO_BTF unset)"
	exit 1
fi

SHA=$(sha256sum "$OUTPUT" | cut -d' ' -f1)
echo "kernel image: $(basename "$KIMG")"
echo "kernel version: ${KVER:-unknown}"
echo "btf size: $SIZE bytes"
echo "btf sha256: $SHA"
echo "wrote: $OUTPUT"
