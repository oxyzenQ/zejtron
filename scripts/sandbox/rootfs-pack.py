#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
"""zejtron sandbox provisioner (night-improve-43, the kernel-floor
lane) - the rootless builder for the local KVM micro-VM that boots
the REAL documented floor kernel and runs the supermassive suite
inside it, as root, on the exact 5.15.0 the README promises.

The CI twin (.github/workflows/supermassive-kernel-floor.yml) proves
the same floor on a hosted runner with docker; this provisioner
builds the SAME image on a developer box or agent sandbox with
NOTHING but python3 and git - no docker, no host root:

  * kernel: the jammy GA floor kernel, linux-image-unsigned-
    5.15.0-25-generic, resolved from the LIVE archive's jammy main
    pocket (the release-day suite, frozen by archive policy - the
    weekly ABI bumps live in jammy-updates and are deliberately NOT
    configured). 5.15.0 is the documented floor (KERNEL_FLOOR in
    src/ebpf/mod.rs, the README's "kernel >= 5.15"), so the GA deb
    IS the floor made bootable: the exact oldest kernel zejtron
    promises to run on, the kernel no stock GitHub runner ships
    (the ubuntu images ride 6.x HWE kernels). The vmlinuz is
    extracted from the .deb with a pure-python ar reader - no
    binutils, no root. The SUITE_TABLE below extends the same
    discipline to the witness presets (focal, jammy, noble): each
    name resolves that Ubuntu suite's GA release-day kernel from
    its own main pocket - the report lane's ready-made witnesses.
  * rootfs: the ubuntu:22.04 base tarball (glibc 2.35, the suite
    jammy itself shipped - the same userland the floor kernel
    natively booted) plus iproute2 and jq provisioned by REAL dependency
    resolution against the jammy Packages index (the one index
    serves the kernel resolution and the package closure both) -
    every closure .deb downloaded and data.tar extracted rootless.
    The suite itself is bash + coreutils + jq by design and needs
    nothing else (jq rides as the typed JSON law's harness dependency).
  * initramfs: packed as a newc cpio by this file itself, with the
    device nodes a non-root packer cannot mknod (console, null,
    tty, ttyS0) synthesized directly into the archive stream, the
    repo checkout (git archive HEAD) at /opt/zejtron, the payload
    binary beside it, and sandbox-init.sh as /init.

The 644/755 permission discipline is enforced at pack time: every
regular file lands 0644 unless executable (0755), every directory
0755 - the image inherits the repo's own rule.

The newc writer carries the sibling's (zelynic's) load-bearing
lessons verbatim: the 4-byte header+name alignment (modern kernels
6.12+ fail the unpack on the old padding), and the usr-merge
symlink-to-directory rule (a walk that ships /lib64 as an empty
directory deletes the dynamic linker from the image).

Usage (the bash entrypoint scripts/sandbox/zejtron-sandbox.sh owns
the orchestration; these subcommands are its legs):
  python3 scripts/sandbox/rootfs-pack.py kernel --suite SUITE --cache DIR
      (SUITE = floor, the jammy GA 5.15.0 floor kernel; a GA witness name
      - focal, jammy, noble; or cachyos, the moving-latest witness)
  python3 scripts/sandbox/rootfs-pack.py initrd --cache DIR --repo DIR \
      --binary PATH --init PATH [--payload PATH] [--lane floor|arbitrary]
  python3 scripts/sandbox/rootfs-pack.py self-test
"""

import argparse
import gzip
import io
import lzma
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

UBUNTU_BASE_URL = "http://cdimage.ubuntu.com/ubuntu-base/releases/22.04/release/"
UBUNTU_BASE_PINNED = "ubuntu-base-22.04.5-base-amd64.tar.gz"
ARCHIVE_POOL = "http://archive.ubuntu.com/ubuntu/"
ARCHIVE_DIST = "http://archive.ubuntu.com/ubuntu/dists/"

# The suite table (the witness presets): every Ubuntu LTS GA suite,
# resolvable by NAME on the same discipline the floor rides. Each
# entry: the LIVE archive main pocket (the GA suite, frozen by
# archive policy - the weekly ABI bumps live in <suite>-updates and
# are deliberately NOT configured; main carries exactly ONE generic
# image per major.minor, the release-day kernel), the regex pinning
# that major.minor (an archive that stops carrying the suite's GA
# image fails the lane loudly instead of silently booting a
# different kernel under the suite's name), the version prefix the
# resolved deb must carry, and the cache file the vmlinuz lands in.
# floor == jammy's kernel (the documented 5.15.0 floor); focal is
# the below-floor witness (5.4 GA - verified live: 5.4.0-26.30);
# jammy as a named witness is the floor kernel ridden on the report
# lane; noble is the above-floor witness (6.8 GA - verified live:
# 6.8.0-31.31).
SUITE_TABLE = {
    "floor": {
        "pocket": "jammy",
        "kernel_re": re.compile(r"^linux-image-unsigned-5\.15\.0-([0-9]+)-generic$"),
        "version_prefix": "5.15.0",
        "out": "vmlinuz-floor",
    },
    "focal": {
        "pocket": "focal",
        "kernel_re": re.compile(r"^linux-image-unsigned-5\.4\.0-([0-9]+)-generic$"),
        "version_prefix": "5.4.0",
        "out": "vmlinuz-focal",
    },
    "jammy": {
        "pocket": "jammy",
        "kernel_re": re.compile(r"^linux-image-unsigned-5\.15\.0-([0-9]+)-generic$"),
        "version_prefix": "5.15.0",
        "out": "vmlinuz-jammy",
    },
    "noble": {
        "pocket": "noble",
        "kernel_re": re.compile(r"^linux-image-unsigned-6\.8\.0-([0-9]+)-generic$"),
        "version_prefix": "6.8.0",
        "out": "vmlinuz-noble",
    },
    # The moving-latest witness (night-improve-53): the owner's own
    # distro line, unpinned - the resolver takes the repo's CURRENT
    # flagship package; the .ver sidecar decides cache reuse.
    "cachyos": {
        "kind": "archpkg",
        "repo_index": "https://mirror.cachyos.org/repo/x86_64/cachyos/",
        "pkg_re": re.compile(
            r'href="(?P<pkg>linux-cachyos-(?P<ver>[0-9][0-9a-zA-Z._-]*?)-x86_64\.pkg\.tar\.zst)"'
        ),
        "out": "vmlinuz-cachyos",
    },
}


def suite_packages_url(pocket):
    return f"{ARCHIVE_DIST}{pocket}/main/binary-amd64/Packages.gz"

# iproute2 for the loopback bring-up, jq for the typed JSON law (night-dragon-4).
ROOT_PACKAGES = ["iproute2", "jq"]


def http_get(url, timeout=120):
    # The UA matters: the cachyos CDN refuses the bare `Python-urllib`.
    req = urllib.request.Request(url, headers={"User-Agent": "zejtron-sandbox/1.0 (+zejtron kernel-witness)"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def http_get_text(url, timeout=120):
    return http_get(url, timeout).decode("utf-8", "replace")


def download_atomic(url, dest, timeout=600):
    """Fetch url into dest ATOMICALLY: the bytes land in a .part twin
    and only a completed transfer renames over dest - an interrupted
    run (Ctrl-C, a killed agent shell, a full disk) can never leave a
    partial file behind (the sibling's NIGHT-harness-1 lesson: a
    killed first run left a 0-byte deb every warm-cache retry then
    treated as complete and died on mid-extraction)."""
    part = f"{dest}.part"
    with open(part, "wb") as fh:
        fh.write(http_get(url, timeout=timeout))
    os.replace(part, dest)
    return dest


def _intact_deb(path):
    """The ar magic is the cheapest possible integrity gate: a cached
    .deb whose first 8 bytes are not the ar magic is a truncated or
    empty leftover and gets re-fetched instead of trusted."""
    try:
        with open(path, "rb") as fh:
            return fh.read(8) == b"!<arch>\n"
    except OSError:
        return False


def say(msg):
    # Progress notes ride STDERR: the entrypoint captures this
    # script's stdout in a command substitution to get the vmlinuz /
    # initrd PATH - a note on stdout pollutes the capture and the
    # [ -f "$path" ] check dies on a multi-line string (the
    # sibling's NIGHT-blade-10 lesson).
    print(f"[sandbox-pack] {msg}", file=sys.stderr, flush=True)


# -- ar archive reader (an ar file is a flat sequence of 60-byte
#    headers after the 8-byte "!<arch>\n" magic - a .deb is an ar
#    whose data.tar member is the filesystem payload).


def ar_members(deb_bytes):
    """Yield (name, payload_bytes) for every member of an ar archive."""
    if deb_bytes[:8] != b"!<arch>\n":
        raise ValueError("not an ar archive (bad magic)")
    off = 8
    while off + 60 <= len(deb_bytes):
        hdr = deb_bytes[off : off + 60]
        name = hdr[0:16].decode("ascii", "replace").rstrip()
        size = int(hdr[48:58].decode("ascii").strip())
        off += 60
        payload = deb_bytes[off : off + size]
        off += size
        if off % 2:  # members are 2-byte aligned
            off += 1
        yield name, payload


def _zstd_decompress(data):
    """Layered zstd decompression (Ubuntu ships kernel debs as
    data.tar.zst - streaming frames, often without a content size in
    the frame header, so the STREAMING reader is mandatory): the
    python 3.14+ stdlib module first, then the zstandard pip module,
    then the zstd CLI - and a clear error naming the fix when none is
    present."""
    try:
        import compression.zstd as _z  # python 3.14+: stdlib

        return _z.ZstdDecompressor().stream_reader(io.BytesIO(data)).read()
    except ImportError:
        pass
    try:
        import zstandard as _zstd  # pip install zstandard

        return _zstd.ZstdDecompressor().stream_reader(io.BytesIO(data)).read()
    except ImportError:
        pass
    for cmd in ("unzstd", "zstd"):
        if shutil.which(cmd):
            return subprocess.run(
                [cmd, "-dc"], input=data, stdout=subprocess.PIPE, check=True
            ).stdout
    raise SystemExit(
        "this .deb's data.tar.zst needs a zstd decompressor: python 3.14+ "
        "(compression.zstd), `pip install zstandard`, or the zstd CLI"
    )


def deb_data_tar(deb_bytes):
    """The data.tar.* member of a .deb, decompressed to bytes."""
    for name, payload in ar_members(deb_bytes):
        if name.startswith("data.tar"):
            if name.endswith(".xz"):
                return lzma.decompress(payload)
            if name.endswith(".gz"):
                return gzip.decompress(payload)
            if name.endswith(".zst"):
                return _zstd_decompress(payload)
            if name.endswith(".tar"):
                return payload
            raise ValueError(f"unsupported data.tar compression: {name}")
    raise ValueError("no data.tar member in deb")


def extract_tar_bytes_into(data, rootfs):
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        try:
            tar.extractall(rootfs, filter="fully_trusted")
        except TypeError:  # python < 3.12: no filter kwarg
            tar.extractall(rootfs)


def extract_deb_into(deb_path, rootfs):
    """Extract a .deb's data.tar into rootfs/ (rootless; the content is
    the Ubuntu archive's own, addressed by the Packages index)."""
    with open(deb_path, "rb") as fh:
        data = deb_data_tar(fh.read())
    extract_tar_bytes_into(data, rootfs)


# -- newc cpio writer ------------------------------------------------
#
# The newc format per entry: 110-byte ASCII header (magic 070701 + 13
# eight-digit hex fields), NUL-terminated name padded to a 4-byte
# boundary, then the file data (also padded). The archive ends with a
# TRAILER!!! entry. Device nodes ride as mode S_IFCHR with rdev
# major/minor - the one thing a rootless filesystem walk cannot
# produce, which is exactly why this packer exists.


def _newc_header(ino, mode, filesize, rdevmajor, rdevminor, namesize):
    def h(v):
        return f"{v:08X}"

    return (
        b"070701"
        + h(ino).encode()
        + h(mode).encode()
        + h(0).encode()  # uid: root
        + h(0).encode()  # gid: root
        + h(1).encode()  # nlink
        + h(0).encode()  # mtime: 0 for deterministic images
        + h(filesize).encode()
        + h(0).encode()  # devmajor
        + h(0).encode()  # devminor
        + h(rdevmajor).encode()
        + h(rdevminor).encode()
        + h(namesize).encode()
        + h(0).encode()  # check: 0 = no checksum
    )


def _newc_entry(out, ino, name, mode, data, rdevmajor=0, rdevminor=0):
    """name is the archive path WITHOUT leading slash ('dev/console').

    Alignment law (the sibling's NIGHT-blade-10 fix, kept verbatim):
    the newc spec pads the (header + name) span to a 4-byte boundary
    - and the header is 110 bytes, 110 % 4 == 2, so the name padding
    must absorb the header's own 2-byte remainder. Padding the name
    alone ships broken padding on some name lengths: old kernels
    (the 5.15 floor included) tolerate it, but modern kernels (6.12+
    strictness) FAIL the unpack - "Initramfs unpacking failed: broken
    padding", PID 1 never runs. The data padding is correct as-is:
    with the span aligned, the data starts 4-aligned."""
    raw = name.encode() + b"\x00"
    out.write(_newc_header(ino, mode, len(data), rdevmajor, rdevminor, len(raw)))
    out.write(raw)
    out.write(b"\x00" * ((-(110 + len(raw))) % 4))
    if data:
        out.write(data)
        out.write(b"\x00" * ((-len(data)) % 4))


def _newc_trailer(out):
    _newc_entry(out, 0, "TRAILER!!!", 0o100644, b"")
    out.write(b"\x00" * ((-out.tell()) % 4))


# The device nodes a direct-boot guest needs before devtmpfs mounts:
# the kernel opens /dev/console for PID 1's stdio, and a handful of
# classics keep early init simple (devtmpfs populates the rest).
SYNTH_DEVICES = {
    "dev/console": (5, 1),
    "dev/null": (1, 3),
    "dev/tty": (5, 0),
    "dev/ttyS0": (4, 64),
}


def pack_initramfs(rootfs, out_path):
    """Walk rootfs/ and emit the gzipped newc cpio. Dirs 0755, files
    0644 (0755 when any exec bit is set), symlinks 120777, synthesized
    char devices for SYNTH_DEVICES - the 644/755 discipline, enforced."""
    ino = 1
    buffer = io.BytesIO()
    emitted = set()
    # The root itself first (cpio archives begin with ".").
    _newc_entry(buffer, ino, ".", 0o040755, b"")
    ino += 1
    for dirpath, dirnames, filenames in os.walk(rootfs, followlinks=False):
        dirnames.sort()
        rel_dir = os.path.relpath(dirpath, rootfs)
        for name in sorted(dirnames):
            rel = name if rel_dir == "." else f"{rel_dir}/{name}"
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                # os.walk classifies a symlink-TO-A-DIRECTORY as a
                # dirname, and emitting it as 040755 ships an EMPTY
                # directory - the usr-merge layout (/bin -> usr/bin,
                # /lib -> usr/lib, /lib64 -> usr/lib64 in every
                # modern ubuntu base) would be deleted from the
                # image, the dynamic linker would vanish with
                # /lib64, and PID 1 would die "Failed to execute
                # /init (error -2)". The link itself is the entry;
                # followlinks=False guarantees the target tree walks
                # exactly once through its real parent.
                _newc_entry(buffer, ino, rel, 0o120777, os.readlink(full).encode())
            else:
                _newc_entry(buffer, ino, rel, 0o040755, b"")
            emitted.add(rel)
            ino += 1
        for name in sorted(filenames):
            rel = name if rel_dir == "." else f"{rel_dir}/{name}"
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                _newc_entry(buffer, ino, rel, 0o120777, os.readlink(full).encode())
                emitted.add(rel)
                ino += 1
                continue
            if rel in SYNTH_DEVICES:
                major, minor = SYNTH_DEVICES[rel]
                _newc_entry(buffer, ino, rel, 0o020600, b"", major, minor)
                emitted.add(rel)
                ino += 1
                continue
            # A non-root tar extraction degrades device nodes to empty
            # placeholder files under /dev - the synthesized set above
            # carries the real nodes, so the placeholders are dropped.
            if rel.startswith("dev/") and os.path.getsize(full) == 0:
                continue
            mode = 0o100755 if os.access(full, os.X_OK) else 0o100644
            with open(full, "rb") as fh:
                data = fh.read()
            _newc_entry(buffer, ino, rel, mode, data)
            emitted.add(rel)
            ino += 1
    # The synthesized device set is guaranteed COMPLETE regardless of
    # what the base tarball shipped or degraded: any SYNTH_DEVICES
    # path the walk did not emit lands here (the base image carries
    # no dev/console entry at all - a rootless extract could never
    # mknod one).
    for rel in sorted(SYNTH_DEVICES):
        if rel in emitted:
            continue
        major, minor = SYNTH_DEVICES[rel]
        _newc_entry(buffer, ino, rel, 0o020600, b"", major, minor)
        ino += 1
    _newc_trailer(buffer)
    with gzip.GzipFile(out_path, "wb", mtime=0) as gz:
        gz.write(buffer.getvalue())


# -- dependency resolution (the jammy Packages index is the truth) ---


def parse_packages(gz_bytes):
    """Packages.gz -> {name: {"version":, "depends": [...], "filename":}}."""
    text = gzip.decompress(gz_bytes).decode("utf-8", "replace")
    index = {}
    for stanza in re.split(r"\n\n+", text):
        name = version = filename = None
        depends = []
        for line in stanza.splitlines():
            if line.startswith("Package: "):
                name = line[9:].strip()
            elif line.startswith("Version: "):
                version = line[9:].strip()
            elif line.startswith("Filename: "):
                filename = line[10:].strip()
            elif line.startswith(("Depends: ", "Pre-Depends: ")):
                depends.append(line.split(": ", 1)[1])
        if name and filename:
            index[name] = {"version": version, "filename": filename, "depends": depends}
    return index


def dep_names(depends_lines):
    """First alternative of every dependency clause, versions stripped."""
    names = []
    for line in depends_lines:
        for clause in line.split(","):
            clause = clause.strip()
            if not clause:
                continue
            first = clause.split("|")[0].strip()
            name = first.split(" ")[0].split(":")[0]
            if name:
                names.append(name)
    return names


def resolve_closure(index, roots):
    """Every package the roots need, transitively (first-alternative
    policy - the conservative choice for a pinned archive)."""
    seen, ordered, queue = set(), [], list(roots)
    while queue:
        name = queue.pop(0)
        if name in seen or name not in index:
            continue
        seen.add(name)
        ordered.append(name)
        queue.extend(dep_names(index[name]["depends"]))
    return ordered


# -- the suite kernels (the lane's whole point) --------------------


def suite_index(cache, suite):
    """The suite's main-pocket Packages index, cached. The floor/jammy
    pocket shares this cache file with the iproute2 closure resolution
    in build_initrd - one download serves the kernel resolution AND
    the package closure on that pocket."""
    entry = SUITE_TABLE[suite]
    pkg_path = os.path.join(cache, f"{entry['pocket']}-Packages.gz")
    if not os.path.exists(pkg_path):
        say(f"fetching the {entry['pocket']} main-pocket Packages index...")
        download_atomic(suite_packages_url(entry["pocket"]), pkg_path, timeout=600)
    with open(pkg_path, "rb") as fh:
        return parse_packages(fh.read())


def fetch_suite_kernel(cache, suite):
    """Resolve + download + extract the vmlinuz of a suite's GA
    kernel. floor == jammy's 5.15.0 (the documented floor, the exact
    oldest kernel zejtron promises to run on); the witnesses resolve
    their own GA release-day kernels the same way. The version
    prefix is the identity guard: an index that stops carrying the
    suite's GA image fails loudly instead of booting a different
    kernel under the suite's name."""
    if SUITE_TABLE[suite].get("kind") == "archpkg":
        return fetch_arch_pkg_kernel(cache, suite)
    entry = SUITE_TABLE[suite]
    out = os.path.join(cache, entry["out"])
    if os.path.exists(out):
        return out
    index = suite_index(cache, suite)
    cands = []
    for name, meta in index.items():
        match = entry["kernel_re"].match(name)
        if match and meta["version"].startswith(entry["version_prefix"]):
            cands.append((int(match.group(1)), name, meta))
    if not cands:
        raise SystemExit(
            f"no {entry['kernel_re'].pattern} package in the {entry['pocket']} main pocket - "
            "the archive moved; the lane refuses to boot a different kernel "
            "under the suite's name"
        )
    cands.sort()
    abi, name, meta = cands[-1]
    say(f"{suite} kernel: {name} ({meta['version']}, the {entry['pocket']} GA release-day kernel)")
    deb_path = os.path.join(cache, f"{name}.deb")
    if not _intact_deb(deb_path):
        say(f"downloading {os.path.basename(meta['filename'])}...")
        download_atomic(ARCHIVE_POOL + meta["filename"], deb_path, timeout=900)
    with open(deb_path, "rb") as fh:
        data = deb_data_tar(fh.read())
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        member = next(
            (
                m
                for m in tar.getmembers()
                if m.name.startswith("./boot/vmlinuz-") or m.name.startswith("boot/vmlinuz-")
            ),
            None,
        )
        if member is None:
            raise SystemExit(f"no vmlinuz inside the {suite}-kernel deb")
        with open(out, "wb") as fh:
            fh.write(tar.extractfile(member).read())
    os.chmod(out, 0o644)
    say(f"kernel: {out} ({os.path.getsize(out) // 1024} KiB)")
    return out


def _intact_zst(path):
    """The zstd frame magic gates the cached arch package (the
    ar-magic twin): a truncated leftover gets re-fetched."""
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x28\xb5\x2f\xfd"
    except OSError:
        return False


def _pkg_ver_key(ver):
    """Numeric-aware compare ("7.2.11-1" > "7.2.7-1" digit-wise; non-numeric parts after numbers)."""
    return tuple((0, int(p)) if p.isdigit() else (1, p) for p in re.split(r"[.\-]", ver))


def fetch_arch_pkg_kernel(cache, suite):
    """The moving-latest witness (night-improve-53): the repo index is
    consulted on EVERY call - the .ver sidecar beside the cached
    vmlinuz names its version, a moved repo re-resolves, so the
    witness can never boot a stale "latest" (the frozen GA pockets
    keep the ubuntu entries' existence shortcut)."""
    entry = SUITE_TABLE[suite]
    out = os.path.join(cache, entry["out"])
    ver_file = out + ".ver"
    listing = http_get_text(entry["repo_index"], timeout=120)
    cands = [(m.group("ver"), m.group("pkg")) for m in entry["pkg_re"].finditer(listing)]
    if not cands:
        raise SystemExit(
            f"no linux-cachyos package in {entry['repo_index']} - the repo moved; "
            "the witness refuses to boot a different kernel under the suite's name"
        )
    ver, pkg = max(cands, key=lambda c: _pkg_ver_key(c[0]))
    if os.path.exists(out) and os.path.exists(ver_file):
        with open(ver_file, "r", encoding="utf-8") as fh:
            if fh.read().strip() == ver:
                say(f"{suite} kernel: {out} ({ver}, still the repo's newest)")
                return out
    pkg_path = os.path.join(cache, pkg)
    if not _intact_zst(pkg_path):
        say(f"downloading {pkg} ({ver}, the {suite} repo's current kernel)...")
        download_atomic(entry["repo_index"] + pkg, pkg_path, timeout=900)
    with open(pkg_path, "rb") as fh:
        data = _zstd_decompress(fh.read())
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        # The arch kernel-package layout law: the vmlinuz rides at
        # usr/lib/modules/<version>/vmlinuz - exactly one (the /boot
        # symlinks are installed by the distro's hooks, not shipped).
        hits = [
            m for m in tar.getmembers()
            if m.name.startswith("usr/lib/modules/") and m.name.endswith("/vmlinuz")
        ]
        if len(hits) != 1:
            raise SystemExit(f"expected one usr/lib/modules/*/vmlinuz, found {len(hits)}")
        payload = tar.extractfile(hits[0]).read()
    tmp = out + ".part"
    with open(tmp, "wb") as fh:
        fh.write(payload)
    os.replace(tmp, out)
    os.chmod(out, 0o644)
    with open(ver_file, "w", encoding="utf-8") as fh:
        fh.write(ver)
    say(f"kernel: {out} ({os.path.getsize(out) // 1024} KiB, {ver})")
    return out


# -- initrd assembly -------------------------------------------------


def ensure_ubuntu_base(cache):
    """The newest 22.04 point release tarball, pinned-name fallback."""
    out = os.path.join(cache, "ubuntu-base.tar.gz")
    if os.path.exists(out):
        return out
    say("resolving the ubuntu:22.04 base tarball...")
    name = UBUNTU_BASE_PINNED
    try:
        hrefs = http_get_text(UBUNTU_BASE_URL, timeout=60)
        cands = sorted(set(re.findall(r"ubuntu-base-22\.04\.[0-9]+-base-amd64\.tar\.gz", hrefs)))
        if cands:
            name = cands[-1]
    except Exception as e:  # noqa: BLE001 - pinned fallback on listing failure
        say(f"listing failed ({e}); falling back to the pinned {name}")
    say(f"downloading {name}...")
    download_atomic(UBUNTU_BASE_URL + name, out, timeout=900)
    say(f"base tarball: {out} ({os.path.getsize(out) // (1024 * 1024)} MiB)")
    return out


def git_archive_into(repo, dest):
    """git archive HEAD (tracked files only, the CI VM contract)
    extracted into dest/."""
    proc = subprocess.run(
        ["git", "-C", repo, "archive", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"git archive HEAD failed ({proc.returncode}): "
            f"{proc.stderr.decode('utf-8', 'replace')[:200]}"
        )
    extract_tar_bytes_into(proc.stdout, dest)


def build_initrd(cache, repo, binary, init, payload, lane=None):
    rootfs = tempfile.mkdtemp(prefix="zejtron-sandbox-rootfs-")
    try:
        # 1. the base userland (the suite the floor kernel shipped with)
        say("extracting the ubuntu:22.04 base...")
        with tarfile.open(ensure_ubuntu_base(cache)) as tar:
            try:
                tar.extractall(rootfs, filter="fully_trusted")
            except TypeError:
                tar.extractall(rootfs)
        # 2. iproute2 by real dependency resolution (the init's
        #    loopback bring-up; the suite itself is bash + coreutils
        #    and rides the base as-is). The userland is held constant
        #    on jammy whatever kernel the lane boots - the lane's only
        #    variable is the KERNEL, the CI twin's own law - and the
        #    same index file serves the floor/jammy kernel resolution.
        index = suite_index(cache, "jammy")
        say("resolving iproute2 against the jammy index...")
        debs_dir = os.path.join(cache, "debs")
        os.makedirs(debs_dir, exist_ok=True)
        for name in resolve_closure(index, ROOT_PACKAGES):
            meta = index[name]
            deb_path = os.path.join(debs_dir, f"{name}.deb")
            if not _intact_deb(deb_path):
                say(f"  fetching {name}...")
                download_atomic(f"{ARCHIVE_POOL}{meta['filename']}", deb_path, timeout=600)
            say(f"  {name} {meta['version']}")
            extract_deb_into(deb_path, rootfs)
        # 3. the payload, the init, the repo, the binary
        say("overlaying the repo checkout, binary, init, payload...")
        zdir = os.path.join(rootfs, "opt", "zejtron")
        os.makedirs(zdir, exist_ok=True)
        git_archive_into(repo, zdir)
        shutil.copy2(binary, os.path.join(zdir, "zejtron"))
        os.chmod(os.path.join(zdir, "zejtron"), 0o755)
        sbx = os.path.join(zdir, ".sandbox")
        os.makedirs(sbx, exist_ok=True)
        if payload:
            shutil.copy2(payload, os.path.join(sbx, "payload.sh"))
            os.chmod(os.path.join(sbx, "payload.sh"), 0o755)
        if lane:
            # The lane marker /init (sandbox-init.sh) reads: floor = the
            # strict identity gate; arbitrary = report mode. Absent = floor,
            # so the CI twin (which packs no lane file) is unchanged by
            # construction.
            lane_path = os.path.join(sbx, "lane")
            with open(lane_path, "w", encoding="utf-8") as fh:
                fh.write(lane + "\n")
            os.chmod(lane_path, 0o644)
        shutil.copy2(init, os.path.join(rootfs, "init"))
        os.chmod(os.path.join(rootfs, "init"), 0o755)
        # 4. pack (degraded /dev placeholders are dropped inside; the
        # synthesized device set carries the real nodes)
        out = os.path.join(cache, "initrd.gz")
        say("packing the newc initramfs...")
        pack_initramfs(rootfs, out)
        os.chmod(out, 0o644)
        say(f"initramfs: {out} ({os.path.getsize(out) // (1024 * 1024)} MiB)")
        return out
    finally:
        shutil.rmtree(rootfs, ignore_errors=True)


# -- self-test (rootless, no network assertions) ---------------------


def parse_newc_for_test(data):
    """A minimal newc reader for the self-test round-trip."""
    entries, off = [], 0
    while off < len(data):
        if off % 4:
            # The kernel's strict unpacker (6.12+) rejects exactly
            # this - the round-trip parser must too, or a padding
            # regression hides behind tolerant parsing.
            raise ValueError(f"entry at offset {off} is not 4-aligned")
        hdr = data[off : off + 110]
        if hdr[:6] != b"070701":
            raise ValueError("bad magic")
        fields = [int(hdr[6 + i * 8 : 14 + i * 8], 16) for i in range(13)]
        mode, filesize = fields[1], fields[6]
        rdevmajor, rdevminor = fields[9], fields[10]
        namesize = fields[11]
        name = data[off + 110 : off + 110 + namesize - 1].decode()
        off += 110 + namesize + ((-(110 + namesize)) % 4)
        filedata = data[off : off + filesize]
        off += filesize + ((-filesize) % 4)
        if name == "TRAILER!!!":
            break
        entries.append((name, mode, filedata, rdevmajor, rdevminor))
    return entries


def self_test():
    """Unit-verify the pure pieces: the ar reader, the dependency
    resolver, the floor-kernel regex, the moving-latest witness
    regex and version key, the newc writer, and the atomic cache
    discipline (a tree with a file, a dir, a symlink, and a
    synthesized device node parses back with the exact fields).
    Network reachability is NOT asserted - the entrypoint reports it
    as a preflight note instead."""
    failures = 0

    def check(name, ok, detail=""):
        nonlocal failures
        print(f"  {'OK ' if ok else 'X  '}{name}" + (f" - {detail}" if detail else ""))
        if not ok:
            failures += 1

    # ar: a synthetic two-member archive parses back.
    def ar_member(name, data):
        hdr = f"{name.decode():<16}{0:<12}{0:<6}{0:<6}{0o100644:<8o}{len(data):<10}".encode()
        return hdr + b"`\n" + data + (b"\n" if len(data) % 2 else b"")

    ar = b"!<arch>\n" + ar_member(b"debian-binary", b"2.0\n")
    ar += ar_member(b"data.tar.xz", lzma.compress(b""))
    members = dict(ar_members(ar))
    check("ar reader parses members", set(members) == {"debian-binary", "data.tar.xz"})
    check("ar reader round-trips bytes", members["debian-binary"] == b"2.0\n")

    # cache discipline: an interrupted download must never poison the
    # warm cache - bytes land in a .part twin that is renamed into
    # place only on completion, and a cached deb that lost its ar
    # magic is re-fetched instead of trusted.
    with tempfile.TemporaryDirectory() as td:
        empty = os.path.join(td, "empty.deb")
        open(empty, "wb").close()
        valid = os.path.join(td, "valid.deb")
        with open(valid, "wb") as fh:
            fh.write(b"!<arch>\n" + ar_member(b"debian-binary", b"2.0\n"))
        check(
            "ar magic gates the deb cache (empty fails, intact passes)",
            _intact_deb(empty) is False and _intact_deb(valid) is True,
        )
        atomic = os.path.join(td, "atomic.deb")
        download_atomic("data:application/octet-stream,hi", atomic, timeout=5)
        with open(atomic, "rb") as fh:
            landed = fh.read()
        check(
            "downloads land atomically (no .part twin survives)",
            landed == b"hi" and not os.path.exists(atomic + ".part"),
        )

    # resolver: a synthetic index walks a transitive chain and takes
    # the first alternative of every clause.
    index = {
        "root": {"version": "1", "filename": "r.deb", "depends": ["dep1 | dep2, dep1b"]},
        "dep1": {"version": "1", "filename": "d1.deb", "depends": []},
        "dep1b": {"version": "1", "filename": "d1b.deb", "depends": []},
        "dep2": {"version": "1", "filename": "d2.deb", "depends": []},
    }
    check(
        "resolver walks first alternatives only",
        resolve_closure(index, ["root"]) == ["root", "dep1", "dep1b"],
    )
    check("resolver tolerates unknown deps", resolve_closure(index, ["ghost"]) == [])

    # the suite table: every suite's regex matches its own GA name
    # with the ABI captured, and near-miss names never match (a
    # neighbor minor, a signed image, or a filename with the version
    # suffix attached must never ride a lane's name). The GA names
    # are the archive's own, verified live against the main pockets
    # (focal 5.4.0-26.30, noble 6.8.0-31.31; jammy's GA is the floor
    # kernel the lane already documents).
    ga_names = {
        "floor": ("linux-image-unsigned-5.15.0-25-generic", "25"),
        "focal": ("linux-image-unsigned-5.4.0-26-generic", "26"),
        "jammy": ("linux-image-unsigned-5.15.0-25-generic", "25"),
        "noble": ("linux-image-unsigned-6.8.0-31-generic", "31"),
    }
    for suite, (ga_name, ga_abi) in ga_names.items():
        m = SUITE_TABLE[suite]["kernel_re"].match(ga_name)
        check(
            f"{suite} regex matches its GA kernel",
            bool(m) and m.group(1) == ga_abi,
        )
    check(
        "suite regexes reject neighbor kernels and suffixed names",
        not SUITE_TABLE["floor"]["kernel_re"].match(
            "linux-image-unsigned-5.15.0-131-generic_5.15.0-131.141_amd64.deb"
        )
        and not SUITE_TABLE["floor"]["kernel_re"].match("linux-image-unsigned-5.16.0-25-generic")
        and not SUITE_TABLE["floor"]["kernel_re"].match("linux-image-5.15.0-25-generic")
        and not SUITE_TABLE["focal"]["kernel_re"].match("linux-image-unsigned-5.5.0-26-generic")
        and not SUITE_TABLE["noble"]["kernel_re"].match("linux-image-unsigned-6.9.0-31-generic"),
    )
    check(
        "the suite table is complete and shaped",
        set(SUITE_TABLE) == {"floor", "focal", "jammy", "noble", "cachyos"}
        and SUITE_TABLE["floor"]["pocket"] == "jammy"
        and SUITE_TABLE["jammy"]["pocket"] == "jammy"
        and len({e["out"] for e in SUITE_TABLE.values()}) == 5,
        "floor and jammy share the pocket; each suite owns its vmlinuz cache file",
    )

    # the moving-latest witness (night-improve-53): the cachyos regex
    # pins the flagship package alone (variants, headers twins, and
    # signatures never match); the version key compares numerically.
    cachyos = SUITE_TABLE["cachyos"]
    flagship = cachyos["pkg_re"].search('href="linux-cachyos-7.2.7-1-x86_64.pkg.tar.zst"')
    check(
        "cachyos regex matches the flagship package",
        bool(flagship) and flagship.group("ver") == "7.2.7-1",
    )
    check(
        "cachyos regex rejects variant flavors, twins, and sigs",
        not any(
            cachyos["pkg_re"].search(line)
            for line in (
                'href="linux-cachyos-7.2.7-1-x86_64.pkg.tar.zst.sig"',
                'href="linux-cachyos-bore-7.2.7-1-x86_64.pkg.tar.zst"',
                'href="linux-cachyos-headers-7.2.7-1-x86_64.pkg.tar.zst"',
                'href="linux-cachyos-bmq-7.0.11-1-x86_64.pkg.tar.zst"',
            )
        ),
    )
    check(
        "the arch version key compares numerically",
        _pkg_ver_key("7.2.11-1") > _pkg_ver_key("7.2.7-1")
        and _pkg_ver_key("7.2.7-2") > _pkg_ver_key("7.2.7-1"),
    )
    with tempfile.TemporaryDirectory() as td:
        zst = os.path.join(td, "pkg.tar.zst")
        with open(zst, "wb") as fh:
            fh.write(b"\x28\xb5\x2f\xfd")
        check(
            "zstd magic gates the arch package cache",
            _intact_zst(zst) is True and _intact_zst(zst + ".missing") is False,
        )

    # newc: pack entries, parse them back, verify every field.
    buf = io.BytesIO()
    _newc_entry(buf, 1, ".", 0o040755, b"")
    _newc_entry(buf, 2, "dir", 0o040755, b"")
    _newc_entry(buf, 3, "file.txt", 0o100644, b"payload")
    _newc_entry(buf, 4, "link", 0o120777, b"file.txt")
    _newc_entry(buf, 5, "dev/console", 0o020600, b"", 5, 1)
    _newc_trailer(buf)
    try:
        entries = parse_newc_for_test(buf.getvalue())
        by_name = {e[0]: e for e in entries}
        check(
            "newc writer emits the full entry set",
            set(by_name) == {".", "dir", "file.txt", "link", "dev/console"},
        )
        check(
            "newc modes round-trip (dir/file/symlink)",
            by_name["dir"][1] == 0o040755
            and by_name["file.txt"][1] == 0o100644
            and by_name["link"][1] == 0o120777,
        )
        check(
            "newc data round-trips (payload + symlink target)",
            by_name["file.txt"][2] == b"payload" and by_name["link"][2] == b"file.txt",
        )
        check(
            "newc synthesized device carries rdev 5:1",
            by_name["dev/console"][3] == 5 and by_name["dev/console"][4] == 1,
        )
    except ValueError as e:
        check("newc output parses", False, str(e))

    # The tree walker on disk: same discipline through pack_initramfs.
    tree = tempfile.mkdtemp(prefix="zejtron-pack-selftest-")
    try:
        os.makedirs(os.path.join(tree, "dir"))
        os.makedirs(os.path.join(tree, "emptydev"), exist_ok=True)
        # A usr-merge-shaped pair: mergedbin is a symlink TO a
        # directory (os.walk files link-dirs under dirnames; the
        # walker must emit the SYMLINK, never an empty directory, or
        # the image loses its dynamic-linker path).
        os.makedirs(os.path.join(tree, "usrbin"), exist_ok=True)
        with open(os.path.join(tree, "usrbin", "prog"), "w") as fh:
            fh.write("x")
        os.symlink("usrbin", os.path.join(tree, "mergedbin"))
        with open(os.path.join(tree, "file.txt"), "w") as fh:
            fh.write("payload")
        os.symlink("file.txt", os.path.join(tree, "link"))
        out_gz = os.path.join(tree, "test-initrd.gz")
        pack_initramfs(tree, out_gz)
        with gzip.open(out_gz, "rb") as fh:
            entries = parse_newc_for_test(fh.read())
        names = {e[0] for e in entries}
        by_name = {e[0]: e for e in entries}
        dev = {e[0]: e for e in entries if e[0].startswith("dev/")}
        check(
            "symlinked directory rides as a symlink (usr-merge)",
            by_name.get("mergedbin", (None, None, None))[1] == 0o120777
            and by_name["mergedbin"][2] == b"usrbin"
            and "usrbin/prog" in names,
            "an empty dir here deleted /lib64 from real images",
        )
        check(
            "pack_initramfs walks the tree into the archive",
            {"dir", "file.txt", "link"} <= names,
        )
        check(
            "pack_initramfs synthesizes device nodes the tree lacks",
            "dev/console" in dev
            and dev["dev/console"][1] == 0o020600
            and dev["dev/console"][3] == 5
            and dev["dev/console"][4] == 1
            and "dev/null" in dev
            and "dev/tty" in dev
            and "dev/ttyS0" in dev,
            "the emptydev/ tree carries no device nodes at all",
        )
    except ValueError as e:
        check("pack_initramfs output parses", False, str(e))
    finally:
        shutil.rmtree(tree, ignore_errors=True)

    print()
    if failures:
        print(f"self-test: {failures} FAILED")
        return 1
    print("self-test: all green")
    return 0


def main():
    ap = argparse.ArgumentParser(
        prog="rootfs-pack", description="the zejtron kernel-floor sandbox provisioner"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser(
        "kernel",
        help="resolve + fetch a suite's GA vmlinuz into the cache",
    )
    k.add_argument(
        "--suite",
        choices=sorted(SUITE_TABLE),
        default="floor",
        help="floor = the jammy GA 5.15.0 kernel; a GA witness name (focal, "
        "jammy, noble) resolves that suite's GA kernel; cachyos resolves "
        "the repo's current flagship kernel (the moving-latest witness)",
    )
    k.add_argument("--cache", required=True)
    i = sub.add_parser("initrd", help="build the gzipped newc initramfs")
    i.add_argument("--cache", required=True)
    i.add_argument("--repo", required=True)
    i.add_argument("--binary", required=True)
    i.add_argument("--init", required=True)
    i.add_argument("--payload", default=None)
    i.add_argument(
        "--lane", choices=["floor", "arbitrary"], default=None,
        help="the lane marker packed at .sandbox/lane (absent = floor)",
    )
    sub.add_parser("self-test", help="rootless unit checks, no network")
    args = ap.parse_args()

    if args.cmd == "self-test":
        return self_test()
    os.makedirs(args.cache, exist_ok=True)
    if args.cmd == "kernel":
        print(fetch_suite_kernel(args.cache, args.suite))
        return 0
    build_initrd(args.cache, args.repo, args.binary, args.init, args.payload, args.lane)
    return 0


if __name__ == "__main__":
    sys.exit(main())
