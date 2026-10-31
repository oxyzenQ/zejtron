// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The RAM symptom's tmpfs lane (night-dragon-lts-1, the LOC-cap
//! split of doctor/memory.rs): the /proc/mounts reader, the bounded
//! mount walker, and the holders label - the file-shaped view of
//! memory that lives in RAM (tmpfs files, their sizes, and the
//! processes holding them). A pure move from the parent module; the
//! parent re-exports the lane's surface, so every consumer's import
//! path is unchanged.

use std::fs;
use std::path::Path;

use super::MemorySample;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TmpfsFile {
    pub path: String,
    pub size_bytes: u64,
    /// The pids whose /proc/*/fd points here, ascending.
    pub holders: Vec<u32>,
}

/// The tmpfs mount points, from /proc/mounts (field 2, mount point;
/// field 3, filesystem type).
pub(crate) fn parse_tmpfs_mounts(contents: &str) -> Vec<String> {
    let mut mounts = Vec::new();
    for line in contents.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[2] == "tmpfs" {
            // The kernel's mangle() escapes the four bytes a
            // mount point cannot carry verbatim in the whitespace-
            // separated /proc/mounts grammar: space, tab, newline,
            // and backslash as \040/\011/\012/\134. The decode
            // keeps mount points comparable with fd link targets;
            // night-dragon-lts-1 adds the missing \012 arm - a tmpfs
            // mounted at a path containing a newline kept the escape
            // verbatim, the follow-up read_dir missed, and the
            // mount's files silently dropped out of the report.
            let point = fields[1]
                .replace("\\040", " ")
                .replace("\\011", "\t")
                .replace("\\012", "\n")
                .replace("\\134", "\\");
            mounts.push(point);
        }
    }
    mounts.sort();
    mounts.dedup();
    mounts
}

/// The verbatim /proc/mounts lines whose filesystem type is tmpfs -
/// the --raw drill-down shows the mount facts as the kernel stated
/// them, not as the parser decoded them.
pub(crate) fn parse_tmpfs_mounts_entries(contents: &str) -> Vec<String> {
    contents
        .lines()
        .filter(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            fields.len() >= 3 && fields[2] == "tmpfs"
        })
        .map(str::to_owned)
        .collect()
}

/// Walk one tmpfs mount's files, bounded at three directory levels -
/// enough for `/run/user/<uid>/...` shapes, shallow enough that a
/// pathological tree cannot turn a symptom into a full filesystem
/// scan. Symlinks are skipped (a symlink's st_size says nothing
/// about RAM); sockets and fifos ride (their st_size is 0 and they
/// fall out of the top list naturally).
fn walk_tmpfs_dir(
    dir: &Path,
    mount: &str,
    depth: usize,
    files: &mut Vec<TmpfsFile>,
    unreadable: &mut usize,
) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => {
            *unreadable += 1;
            return;
        }
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if file_type.is_dir() {
            if depth < 3 {
                walk_tmpfs_dir(&path, mount, depth + 1, files, unreadable);
            }
            continue;
        }
        if file_type.is_symlink() {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let path_string = path.to_string_lossy().to_string();
        if !path_string.starts_with(mount) {
            // A mount point that is itself a symlink target (e.g.
            // /dev/shm reached through /dev); the walk keys on the
            // string the operator would see.
            continue;
        }
        files.push(TmpfsFile {
            path: path_string,
            size_bytes: meta.len(),
            holders: Vec::new(),
        });
    }
}

pub(super) fn collect_tmpfs(sample: &mut MemorySample) {
    let Ok(mounts_raw) = fs::read_to_string("/proc/mounts") else {
        return;
    };
    let mounts = parse_tmpfs_mounts(&mounts_raw);
    sample.tmpfs_mounts = mounts.clone();
    let mut files: Vec<TmpfsFile> = Vec::new();
    let mut unreadable = 0;
    for mount in &mounts {
        walk_tmpfs_dir(Path::new(mount), mount, 0, &mut files, &mut unreadable);
    }
    sample.tmpfs_unreadable_dirs = unreadable;
    files.sort_by(|left, right| {
        right
            .size_bytes
            .cmp(&left.size_bytes)
            .then(left.path.cmp(&right.path))
    });
    sample.tmpfs_files = files;
}

/// The deterministic holders label for a tmpfs file: the pids with
/// their comms, or the namespace-boundary honesty.
pub(crate) fn holders_label(file: &TmpfsFile) -> String {
    if file.holders.is_empty() {
        return "held by no process in this namespace".to_owned();
    }
    let named: Vec<String> = file
        .holders
        .iter()
        .take(3)
        .map(|pid| format!("{pid} ({})", super::comm_of(*pid)))
        .collect();
    if file.holders.len() > 3 {
        return format!(
            "held by PIDs {} and {} more",
            named.join(", "),
            file.holders.len() - 3
        );
    }
    format!("held by PID {}", named.join(", "))
}
