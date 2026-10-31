// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The fd walk (night-dragon-lts-4, split from memory.rs at the LOC
//! cap - a pure move plus the identity accounting the split rode
//! in with): the per-pid /proc/<pid>/fd sweep that attributes the
//! rare shapes the memory ledger names as their own sections -
//! deleted-but-open files, memfd files - and feeds the tmpfs holder
//! index its pids.
//!
//! Identity honesty (night-dragon-lts-4): the magic link's stat
//! yields the file's kernel identity (dev, ino) alongside the size,
//! and that identity is the difference between a fact and an
//! inflated number. One file held through N fds or N processes is
//! ONE file: rows dedupe per (pid, file) so a dup(2) pair never
//! renders twice, and the verdict's deleted total counts each file
//! once - the pre-fix total summed one row per holder, so a 40 MiB
//! memfd shared by three pulseaudio processes rendered as 120 MiB
//! of deleted-but-open pressure it never was.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use super::{MemorySample, TmpfsFile, comm_of};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeletedOpenFile {
    pub pid: u32,
    pub name: String,
    pub path: String,
    /// None when the magic-link stat was refused (permission) - the
    /// row still renders; the size renders as unknown.
    pub size_bytes: Option<u64>,
    /// The file's kernel identity (dev, ino) from the same stat the
    /// size rode on - the dedupe key for rows and totals alike. Two
    /// pids holding one memfd share it; one pid holding a file
    /// through two dup(2) fds shares it with itself. None when the
    /// stat was refused: identity-refused rows ride the walk
    /// undeduped rather than guessed at.
    pub identity: Option<(u64, u64)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MemfdFile {
    pub pid: u32,
    pub name: String,
    pub target: String,
    /// None when the magic-link stat was refused (permission) - the
    /// row still renders; the size renders as unknown.
    pub size_bytes: Option<u64>,
    /// The (dev, ino) pair, same source and same purpose as
    /// [`DeletedOpenFile::identity`] - the memfd lane dedupes on it
    /// too.
    pub identity: Option<(u64, u64)>,
}

/// The fd-walk rows' shared identity surface: one trait, two row
/// shapes (deleted and memfd), so the per-(pid, file) dedupe speaks
/// both lanes through one law.
pub(crate) trait FdRow {
    fn holder_pid(&self) -> u32;
    fn file_identity(&self) -> Option<(u64, u64)>;
}

impl FdRow for DeletedOpenFile {
    fn holder_pid(&self) -> u32 {
        self.pid
    }
    fn file_identity(&self) -> Option<(u64, u64)> {
        self.identity
    }
}

impl FdRow for MemfdFile {
    fn holder_pid(&self) -> u32 {
        self.pid
    }
    fn file_identity(&self) -> Option<(u64, u64)> {
        self.identity
    }
}

/// The memfd classifier (night-dragon-lts-4): the kernel renders a
/// memfd's fd target as "/memfd:<name> (deleted)" - leading slash and
/// deleted suffix are both unconditional (proven live on 5.10 and
/// 6.12 hosts) - so the test strips one leading slash before the
/// "memfd:" prefix match. It must run BEFORE the deleted-suffix test:
/// every memfd in the wild carries the suffix too, and the pre-fix
/// walk filed them all as deleted files while the memfd section
/// rendered "(none observed)" on every host.
pub(crate) fn is_memfd_target(target: &str) -> bool {
    let rest = target.strip_prefix('/').unwrap_or(target);
    rest.starts_with("memfd:")
}

/// The fd walk's rare-shape accumulator: the deleted and memfd lists
/// ride one borrow bundle with the per-pid comm cache, so the walk
/// pays one /proc/<pid>/comm read per pid that needs a name - not
/// one per qualifying fd - and attribute_fd_target stays under the
/// argument-count law.
struct FdShapes<'a> {
    deleted: &'a mut Vec<DeletedOpenFile>,
    memfds: &'a mut Vec<MemfdFile>,
    comm: Option<String>,
}

impl FdShapes<'_> {
    /// The pid's comm, read at most once per pid for the whole walk.
    fn comm(&mut self, pid: u32) -> String {
        self.comm.get_or_insert_with(|| comm_of(pid)).clone()
    }
}

/// Attribute one fd link target: deleted files, memfd files, and
/// tmpfs holders. The magic link's stat follows to the underlying
/// file even when the directory entry is gone - the only size source
/// for a deleted-but-open file, and (night-dragon-lts-4) the only
/// identity source for the dedupe laws. night-dragon-1: the stat
/// used to run for EVERY fd target although only the deleted and
/// memfd branches read it; it now runs inside those branches, and
/// the tmpfs holder lookup is the caller's path index, same push
/// rule, same rows.
fn attribute_fd_target(
    pid: u32,
    target: &str,
    fd_path: &Path,
    shapes: &mut FdShapes<'_>,
    tmpfs_index: &HashMap<String, Vec<usize>>,
    tmpfs_files: &mut [TmpfsFile],
) {
    // Memfd first: its target carries the deleted suffix too
    // (night-dragon-lts-4), and the deleted branch below would eat
    // every memfd before the memfd test could fire.
    if is_memfd_target(target) {
        let meta = fs::metadata(fd_path).ok();
        let name = shapes.comm(pid);
        shapes.memfds.push(MemfdFile {
            pid,
            name,
            target: target.to_owned(),
            size_bytes: meta.as_ref().map(|m| m.len()),
            identity: meta.as_ref().map(|m| (m.dev(), m.ino())),
        });
        return;
    }
    if target.ends_with(" (deleted)") {
        let meta = fs::metadata(fd_path).ok();
        // The comm rides the pid, not the fd: this branch fires per
        // deleted fd, and a Chromium-style process holds hundreds -
        // the bundle's cache reads /proc/<pid>/comm once.
        let name = shapes.comm(pid);
        shapes.deleted.push(DeletedOpenFile {
            pid,
            name,
            path: target.to_owned(),
            size_bytes: meta.as_ref().map(|m| m.len()),
            identity: meta.as_ref().map(|m| (m.dev(), m.ino())),
        });
        return;
    }
    // The index maps each path to every list position carrying it
    // (duplicates are real: overlapping tmpfs mounts), so the lookup
    // reproduces the old find's first-missing-holder rule.
    if let Some(indices) = tmpfs_index.get(target) {
        for &index in indices {
            let file = &mut tmpfs_files[index];
            if !file.holders.contains(&pid) {
                file.holders.push(pid);
                break;
            }
        }
    }
}

/// One row per (pid, file): the same file held open twice by one
/// process - dup(2), an fd re-received over SCM_RIGHTS, two plain
/// opens of one inode - renders as one row; the fd count is not the
/// fact, the holder and the file are. Rows whose stat was refused
/// carry no identity and all ride through: the walk cannot know
/// whether they are the same file, and a guessed dedupe would be a
/// silently dropped row.
pub(crate) fn dedupe_by_pid_file<Row: FdRow>(rows: Vec<Row>) -> Vec<Row> {
    let mut seen: HashSet<(u32, u64, u64)> = HashSet::new();
    rows.into_iter()
        .filter(|row| match row.file_identity() {
            Some((dev, ino)) => seen.insert((row.holder_pid(), dev, ino)),
            None => true,
        })
        .collect()
}

/// The deleted view's unique-file accounting: the count and byte
/// total of the DISTINCT files (dev, ino) behind the rows. The
/// verdict's deleted total and the JSON's deleted_open_unique_bytes
/// speak this pair, never the per-row sum: a shared deleted file or
/// memfd riding N holders was counted once per holder before
/// (night-dragon-lts-4), inflating the number the verdict leans on -
/// a 40 MiB memfd held by three processes is 40 MiB of page cache,
/// not 120. Size-refused rows contribute nothing (an unknown size
/// was never added before either); identity-refused rows cannot be
/// matched and stay out rather than guessed in.
pub(crate) fn deleted_unique(rows: &[DeletedOpenFile]) -> (usize, u64) {
    let mut unique: HashMap<(u64, u64), u64> = HashMap::new();
    for row in rows {
        if let (Some(identity), Some(size)) = (row.identity, row.size_bytes) {
            unique.insert(identity, size);
        }
    }
    (unique.len(), unique.values().sum())
}

pub(crate) fn collect_fds(pids: &[u32], sample: &mut MemorySample) {
    let mut deleted = Vec::new();
    let mut memfds = Vec::new();
    // night-dragon-1: the tmpfs file list indexed once per scan; the
    // old form re-scanned it linearly per matching fd (and allocated
    // a mount-prefix string per fd per mount). Owned keys, so the
    // index does not borrow its slice.
    let mut tmpfs_index: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, file) in sample.tmpfs_files.iter().enumerate() {
        tmpfs_index
            .entry(file.path.clone())
            .or_default()
            .push(index);
    }
    for pid in pids {
        let fd_dir = PathBuf::from(format!("/proc/{pid}/fd"));
        let entries = match fs::read_dir(&fd_dir) {
            Ok(entries) => entries,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    sample.fd_permission_refused += 1;
                }
                continue;
            }
        };
        // The per-pid accumulator bundle (night-dragon-lts-1): the
        // comm read stays lazy - exactly one /proc/<pid>/comm open
        // per pid that needs it, instead of one per qualifying fd.
        let mut shapes = FdShapes {
            deleted: &mut deleted,
            memfds: &mut memfds,
            comm: None,
        };
        for entry in entries.flatten() {
            let Ok(target) = fs::read_link(entry.path()) else {
                continue;
            };
            let target = target.to_string_lossy().to_string();
            attribute_fd_target(
                *pid,
                &target,
                &entry.path(),
                &mut shapes,
                &tmpfs_index,
                &mut sample.tmpfs_files,
            );
        }
    }
    // One row per (pid, file) (night-dragon-lts-4): the walk pushes
    // per fd, the render speaks per holder per file.
    deleted.sort_by(|left, right| {
        right
            .size_bytes
            .unwrap_or(0)
            .cmp(&left.size_bytes.unwrap_or(0))
            .then(left.pid.cmp(&right.pid))
            .then(left.path.cmp(&right.path))
    });
    memfds.sort_by(|left, right| {
        right
            .size_bytes
            .unwrap_or(0)
            .cmp(&left.size_bytes.unwrap_or(0))
            .then(left.pid.cmp(&right.pid))
            .then(left.target.cmp(&right.target))
    });
    sample.deleted = dedupe_by_pid_file(deleted);
    sample.memfds = dedupe_by_pid_file(memfds);
}

#[cfg(test)]
#[path = "../../../../test/commands/doctor/memory_fds_tests.rs"]
mod tests;
