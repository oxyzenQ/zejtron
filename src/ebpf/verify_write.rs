// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The write probe's attach-time self-verification (night-improve-59):
//! the last door the silent-anchor class can never pass.
//!
//! The night this pass closed had three write-probe generations: the
//! vfs_write kprobe (dead on the -O3 distro builds that inline it
//! into the syscall stub), the stub kprobe (attachable, pinned, and
//! absolutely silent - the drop census proved the program never
//! ran, while ftrace probes at the same name and the same raw
//! kallsyms address fired beside it), and the sys_enter tracepoint
//! that finally records. Two of the three were SILENT ANCHORS - a
//! class of failure where the attach succeeds, the pins exist, and
//! no event ever lands. The offsets law (refuse without a BTF-verified
//! set) and the writev symbol law (refuse without a shape-vouched
//! symbol) never covered it: both verify the PARSE, not the RECORD.
//!
//! This module extends the doctrine to record-verify: after the
//! whole estate is planted, attach tracks a scratch file, pushes one
//! write through the probe, drains the ring, and demands the scratch's
//! own (inode, device, op) back. Found: attach proceeds. Not found:
//! the attach REFUSES - loudly, with the scratch's facts in the
//! message - and the pins come down (the caller detaches first), so
//! a probe that cannot record one byte can never claim to be live.
//!
//! The scratch rides a process-named temp directory and is removed
//! unconditionally; the tracked key is untracked on both legs of
//! every retry (the fail protocol: no window ends with a leaked
//! key). The drain consumes by contract (the ring reader's own
//! law), so each retry writes fresh bytes before draining again.

use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

use super::events::FILE_OP_WRITE;
use super::ringbuf::drain_file_events;
use super::tracked::{track_file, untrack_file};
use crate::commands::lane::device_token_from_stat;

/// Demand one recorded write through the freshly planted probe.
pub fn verify_write_probe() -> Result<(), String> {
    let dir = std::env::temp_dir().join(format!("zejtron-verify-write-{}", std::process::id()));
    let probe = dir.join("probe");
    let result = verify_once(&dir, &probe);
    let _ = fs::remove_dir_all(&dir);
    result
}

/// One verification attempt: create the scratch, track it, push
/// writes, and drain with a bounded retry (the ring delivery is
/// synchronous with the syscall - the retries only guard against a
/// host whose reader position races the very first record).
fn verify_once(dir: &Path, probe: &Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("the write verification scratch {dir:?}: {e}"))?;
    fs::write(probe, b"first").map_err(|e| format!("the write verification scratch: {e}"))?;
    let meta = fs::metadata(probe).map_err(|e| format!("the write verification scratch: {e}"))?;
    let inode = meta.ino();
    let device = device_token_from_stat(meta.dev());

    let deadline = Instant::now() + Duration::from_millis(300);
    loop {
        track_file(inode, device)?;
        push_write(probe)?;
        let drained = match drain_file_events() {
            Ok(events) => events,
            Err(e) => {
                let _ = untrack_file(inode, device);
                return Err(format!(
                    "attach refused: the write verification drain failed: {e}"
                ));
            }
        };
        if drained
            .iter()
            .any(|e| e.inode == inode && e.device == device && e.op == FILE_OP_WRITE)
        {
            let _ = untrack_file(inode, device);
            return Ok(());
        }
        if Instant::now() > deadline {
            let _ = untrack_file(inode, device);
            return Err(format!(
                "attach refused: the write probe stayed silent for its own \
                 verification write (inode {inode:#x} tracked, no op={FILE_OP_WRITE} \
                 record drained) - a probe that cannot record a single write must \
                 not claim to be live"
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// One plain append through the probe - write(2), the syscall the
/// sys_enter anchor rides.
fn push_write(probe: &Path) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(probe)
        .map_err(|e| format!("the write verification scratch: {e}"))?;
    file.write_all(b"through")
        .map_err(|e| format!("the write verification append: {e}"))?;
    Ok(())
}
