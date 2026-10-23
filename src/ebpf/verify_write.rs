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
use super::readback::{read_fd_walk_offsets, read_write_census};
use super::ringbuf::drain_file_events;
use super::tracked::{track_file, untrack_file};
use crate::commands::lane::device_token_from_stat;

/// The write probe's drop-census stage meanings (the stage numbers
/// ebpf/src/write.rs's zjw_drop carries): the kernel-side census
/// names the furthest hop the walk reached and dropped at, and this
/// table turns the number into the hop's full name - the exact step
/// a silent verification failed, never a mute refusal.
fn stage_meaning(stage: u64) -> &'static str {
    match stage {
        1 => "the offsets map was unreadable (the walk never started)",
        3 => "task->files unreadable or null",
        4 => "files->fdt unreadable or null (the fd-table indirection hop)",
        5 => "fdt->max_fds unreadable",
        6 => "fd out of the table's range (fd >= max_fds)",
        7 => "fdt->fd array pointer unreadable or null",
        8 => "fd[fd] unreadable or null (no struct file behind the descriptor)",
        9 => "file->f_inode unreadable",
        10 => "inode->i_ino unreadable",
        11 => "file->f_path.mnt unreadable",
        12 => "mnt->mnt_sb unreadable",
        13 => "sb->s_dev unreadable",
        14 => "the tracked_inodes filter missed (the walked identity did not match)",
        _ => "unnamed stage",
    }
}

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
            let census_note = match read_write_census() {
                Ok(census) if census.drops == 0 && census.walked == 0 => {
                    "no census activity at all - the probe never executed its \
                     walk for the verification write (the sys_enter anchor \
                     itself never fired)"
                        .to_owned()
                }
                Ok(census) => match census.furthest {
                    Some((stage, count)) => {
                        // The planted numbers beside the hop: the
                        // fd-walk offsets the map actually held at
                        // refusal time - a zero slot (the
                        // night-hunter-3 plant bug) is visible in the
                        // message itself, never guessed at.
                        let planted = read_fd_walk_offsets()
                            .map(|o| format!("{o:?}"))
                            .unwrap_or_else(|e| format!("unreadable: {e}"));
                        format!(
                            "{} drop(s), {} completed walk(s), furthest drop at stage {}: \
                             {} ({} drop(s) there); planted fd-walk offsets \
                             [files, fdt, max_fds, fd]: {planted}",
                            census.drops,
                            census.walked,
                            stage,
                            stage_meaning(stage),
                            count
                        )
                    }
                    None => format!(
                        "{} drop(s), {} completed walk(s), but no per-stage count \
                         survived - the stage counters were wiped mid-verify",
                        census.drops, census.walked
                    ),
                },
                Err(e) => format!("the census could not be read ({e})"),
            };
            return Err(format!(
                "attach refused: the write probe stayed silent for its own \
                 verification write (inode {inode:#x} tracked, no op={FILE_OP_WRITE} \
                 record drained; the kernel-side census: {census_note}) - a probe \
                 that cannot record a single write must not claim to be live"
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
