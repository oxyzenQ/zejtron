// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial
//
// The camera object's build-time digest stamp (night-frontier-Z5),
// split out of build/ebpf.rs per the 600-LOC no-mercy cap (the
// btf_decode.rs precedent: the concern gets its own module, a pure
// move, gates green in between). BOTH staging lanes call this the
// moment the object lands in OUT_DIR, so the digest always
// describes the exact bytes the host crate embeds - one stamp site
// per lane, one writer of the env.

use std::path::Path;

use crate::prebuilt::STAGED_OBJECT_NAME;

/// BLAKE3 over the staged object bytes, stamped
/// `ZEJTRON_CAMERA_OBJECT_B3` so the runtime can re-hash what it
/// embedded and refuse a patched camera (the sig surface's D4 row -
/// the eBPF object is the one artifact that executes at ring 0, so
/// it belongs inside the self-verification circle, not only inside
/// the release checksum files). The same std-only BLAKE3 the
/// prebuilt lane's manifest verification rides - one implementation,
/// build side and registry side.
pub(super) fn stamp_camera_digest(out_dir: &Path) {
    let staged = out_dir.join(STAGED_OBJECT_NAME);
    let data = std::fs::read(&staged).unwrap_or_else(|e| {
        panic!(
            "failed to read the staged {} for the camera digest: {e}",
            staged.display()
        )
    });
    println!(
        "cargo:rustc-env=ZEJTRON_CAMERA_OBJECT_B3={}",
        crate::blake3::blake3_hex(&data)
    );
}
