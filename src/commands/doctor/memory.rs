// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The memory symptom's /proc readers (night-improve-4, Part B):
//! "RAM is at X percent used; who is using it?" answered from the
//! kernel's own tables, with no capabilities beyond what the
//! invoking user already has. night-improve-47 adds the one eBPF
//! read the symptom can make without becoming a monitor: when the
//! probe is attached, the post-mortem exit lane (exits.rs) drains
//! the last five seconds of process exits from the pinned
//! proc_events ring - the fact no /proc read can recover, named
//! [observed] in its own section. Every read is a metadata read -
//! paths, sizes, PIDs, names; no file content is ever opened (the
//! zero-leakage posture holds).
//!
//! The attribution categories, each rendered as its own Evidence
//! Ledger section:
//!
//! 1. per-process PSS (/proc/*/smaps_rollup - proportional set size,
//!    the shared-page truth RSS overstates);
//! 2. tmpfs files (mounts from /proc/mounts, files by readdir,
//!    holders by /proc/*/fd link targets - the view htop cannot
//!    produce);
//! 3. deleted-but-open files (/proc/*/fd targets ending " (deleted)"
//!    - page cache and swap pinned by a dead directory entry);
//! 4. memfd files (/proc/*/fd targets starting "memfd:" - in-memory
//!    files a process created);
//! 5. page cache, buffers, shmem (/proc/meminfo - reclaimable on
//!    demand, named so the operator knows what is not a leak);
//! 6. slab (top caches by num_objs * objsize from /proc/slabinfo;
//!    the reclaimable/unreclaimable totals ride meminfo, which stays
//!    readable when slabinfo is root-only);
//! 7. the residual - used minus the kernel-level buckets minus the
//!    readable PSS sum - named unaccounted.
//!
//! And when the probe is attached, the post-mortem exit lane
//! (exits.rs) rides along - not an attribution bucket but a
//! named-fact section: the processes that exited inside the last
//! five seconds, named [observed], to qualify the residual's
//! biggest blind spot.
//!
//! Permission honesty: every read another user's process refuses is
//! COUNTED, never silently dropped - the counters ride the
//! Unaccounted block by name. Where two categories overlap (a tmpfs
//! file's pages are Shmem; a memfd's mapped pages ride the holder's
//! PSS), the residual math uses the kernel-level buckets exactly
//! once and the report says so - a residual computed from
//! double-counted sums would be a lie with a number on it.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) mod exits;
pub(crate) mod ledger;
pub(crate) mod verdict;

pub(crate) use exits::ExitLane;

/// One byte of the report: the collected sample plus the render.
/// `raw` appends the verbatim /proc reads for drill-down.
pub fn report(raw: bool) -> String {
    let sample = collect();
    ledger::render(&sample, raw)
}

// ── The sample ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MemInfo {
    pub total_kib: u64,
    pub free_kib: u64,
    pub available_kib: u64,
    pub cached_kib: u64,
    pub buffers_kib: u64,
    pub shmem_kib: u64,
    pub s_reclaimable_kib: u64,
    pub s_unreclaim_kib: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessPss {
    pub pid: u32,
    pub name: String,
    pub pss_kib: u64,
    pub anon_kib: u64,
    pub file_kib: u64,
    pub shmem_kib: u64,
    pub rss_kib: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TmpfsFile {
    pub path: String,
    pub size_bytes: u64,
    /// The pids whose /proc/*/fd points here, ascending.
    pub holders: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeletedOpenFile {
    pub pid: u32,
    pub name: String,
    pub path: String,
    /// None when the magic-link stat was refused (permission) - the
    /// row still renders; the size renders as unknown.
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MemfdFile {
    pub pid: u32,
    pub name: String,
    pub target: String,
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SlabRow {
    pub cache: String,
    pub size_kib: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MemorySample {
    pub meminfo: Option<MemInfo>,
    /// Every readable process, PSS descending (the ledger takes the
    /// top 10; the residual math sums them all).
    pub pss: Vec<ProcessPss>,
    /// /proc pid dirs whose smaps_rollup was permission-refused.
    pub pss_permission_refused: usize,
    /// Pid dirs that vanished or parsed empty mid-scan (a read that
    /// succeeded on non-empty bytes but no longer parses - the
    /// exiting-process truncation race).
    pub pss_vanished: usize,
    /// Pid dirs whose smaps_rollup read back EMPTY: kernel threads
    /// and zombies, which carry no mm and therefore no user memory
    /// to attribute (night-dragon-lts-1: these were counted as
    /// vanished, printing a false "exited or emptied mid-scan" claim
    /// on every host with visible kthreads - a steady-state class,
    /// not a scan race).
    pub pss_kernel_threads: usize,
    pub tmpfs_files: Vec<TmpfsFile>,
    /// Tmpfs mount points (or their subdirs) readdir refused to read.
    pub tmpfs_unreadable_dirs: usize,
    pub tmpfs_mounts: Vec<String>,
    pub deleted: Vec<DeletedOpenFile>,
    pub memfds: Vec<MemfdFile>,
    /// /proc pid dirs whose fd table was permission-refused.
    pub fd_permission_refused: usize,
    pub slab: Vec<SlabRow>,
    /// False when /proc/slabinfo was unreadable (root-only on
    /// hardened hosts) - the section renders the named absence.
    pub slab_readable: bool,
    /// The post-mortem exit lane's state (night-improve-47): the
    /// drains and verdicts the exits section and the Unaccounted
    /// block render from. Defaults to not-attached - the honest
    /// shape of a sample nobody filled.
    pub exit_lane: ExitLane,
}

// ── The /proc walkers ───────────────────────────────────────────────

/// The numeric /proc pid directory listing, ascending - the one
/// walker every symptom lane samples from (night-improve-48 makes
/// it shared: the delta symptoms speak it from here, one source
/// for the whole doctor).
pub(crate) fn pid_dirs(proc_root: &Path) -> Vec<u32> {
    let mut pids = Vec::new();
    let Ok(entries) = fs::read_dir(proc_root) else {
        return pids;
    };
    for entry in entries.flatten() {
        if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    pids
}

/// The process name, from the same task->comm string the status Name
/// field renders. night-dragon-1: /proc/<pid>/comm replaces the
/// per-pid full status read + line scan; unreadable or vanished
/// processes degrade to the same "unknown".
fn comm_of(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .and_then(|comm| {
            let stripped = comm.strip_suffix('\n').unwrap_or(&comm);
            (!stripped.is_empty()).then(|| stripped.to_owned())
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

/// One "Field:  N kB" line of /proc/meminfo, in KiB.
fn meminfo_field(contents: &str, field: &str) -> Option<u64> {
    let prefix = format!("{field}:");
    let line = contents.lines().find(|line| line.starts_with(&prefix))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

pub(crate) fn parse_meminfo(contents: &str) -> Option<MemInfo> {
    Some(MemInfo {
        total_kib: meminfo_field(contents, "MemTotal")?,
        free_kib: meminfo_field(contents, "MemFree")?,
        available_kib: meminfo_field(contents, "MemAvailable")?,
        cached_kib: meminfo_field(contents, "Cached")?,
        buffers_kib: meminfo_field(contents, "Buffers")?,
        shmem_kib: meminfo_field(contents, "Shmem")?,
        s_reclaimable_kib: meminfo_field(contents, "SReclaimable")?,
        s_unreclaim_kib: meminfo_field(contents, "SUnreclaim")?,
    })
}

/// One Pss field of /proc/*/smaps_rollup, in KiB.
fn rollup_field(contents: &str, field: &str) -> Option<u64> {
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{field}:")) {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

pub(crate) fn parse_smaps_rollup(contents: &str) -> Option<(u64, u64, u64, u64, u64)> {
    Some((
        rollup_field(contents, "Pss")?,
        rollup_field(contents, "Pss_Anon")?,
        rollup_field(contents, "Pss_File")?,
        rollup_field(contents, "Pss_Shmem")?,
        rollup_field(contents, "Rss")?,
    ))
}

/// The per-process PSS table: every pid whose rollup this invocation
/// can read. Refusals are counted by class - the read error names
/// which: PermissionDenied is the boundary (another user's process,
/// or hidepid), everything else (ENOENT races, empty parses) is a
/// process that vanished mid-scan. Both classes ride the Unaccounted
/// block; neither is ever silently dropped.
fn collect_pss(pids: &[u32], sample: &mut MemorySample) {
    for pid in pids {
        match fs::read_to_string(format!("/proc/{pid}/smaps_rollup")) {
            Ok(contents) => {
                // The empty read is its own class (night-dragon-lts-1):
                // a process with no mm - kernel threads, and zombies
                // past their exit - open the file fine and read back
                // zero bytes, because show_smaps_rollup has no mm to
                // walk. Counting them as "exited mid-scan" printed a
                // false race claim for a steady-state population of
                // 80-200 kthreads on a normal host; they carry no
                // user memory, so nothing was missed.
                if contents.trim().is_empty() {
                    sample.pss_kernel_threads += 1;
                } else if let Some((pss, anon, file, shmem, rss)) = parse_smaps_rollup(&contents) {
                    sample.pss.push(ProcessPss {
                        pid: *pid,
                        name: comm_of(*pid),
                        pss_kib: pss,
                        anon_kib: anon,
                        file_kib: file,
                        shmem_kib: shmem,
                        rss_kib: rss,
                    });
                } else {
                    sample.pss_vanished += 1;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                sample.pss_permission_refused += 1;
            }
            Err(_) => sample.pss_vanished += 1,
        }
    }
    // night-dragon-1: the head is all any consumer reads (top-10
    // positive rows for the ledger and JSON, first for the verdict
    // and --raw, sum for the residual), so select_nth plus a sorted
    // front slice is byte-identical to the full sort. The (Reverse
    // PSS, pid) key is the same total order the old full sort's
    // comparator spelled. Full-coverage reads stay: the residual
    // sums every row, and skipping small-RSS reads would move the
    // unaccounted number.
    let head_order = |process: &ProcessPss| (Reverse(process.pss_kib), process.pid);
    if sample.pss.len() > ledger::TOP_N {
        sample
            .pss
            .select_nth_unstable_by_key(ledger::TOP_N, head_order);
        sample.pss[..ledger::TOP_N].sort_by_key(head_order);
    } else {
        sample.pss.sort_by_key(head_order);
    }
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

fn collect_tmpfs(sample: &mut MemorySample) {
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

/// The fd walk's rare-shape accumulator (night-dragon-lts-1): the
/// deleted and memfd lists ride one borrow bundle with the per-pid
/// comm cache, so the walk pays one /proc/<pid>/comm read per pid
/// that needs a name - not one per qualifying fd - and
/// attribute_fd_target stays under the argument-count law.
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
/// for a deleted-but-open file. night-dragon-1: the stat used to run
/// for EVERY fd target although only the deleted and memfd branches
/// read it; it now runs inside those branches, and the tmpfs holder
/// lookup is the caller's path index, same push rule, same rows.
fn attribute_fd_target(
    pid: u32,
    target: &str,
    fd_path: &Path,
    shapes: &mut FdShapes<'_>,
    tmpfs_index: &HashMap<String, Vec<usize>>,
    tmpfs_files: &mut [TmpfsFile],
) {
    if target.ends_with(" (deleted)") {
        let size = fs::metadata(fd_path).ok().map(|m| m.len());
        // The comm rides the pid, not the fd: this branch fires per
        // deleted fd, and a Chromium-style process holds hundreds -
        // the bundle's cache reads /proc/<pid>/comm once.
        let name = shapes.comm(pid);
        shapes.deleted.push(DeletedOpenFile {
            pid,
            name,
            path: target.to_owned(),
            size_bytes: size,
        });
        return;
    }
    if target.starts_with("memfd:") {
        let size = fs::metadata(fd_path).ok().map(|m| m.len());
        let name = shapes.comm(pid);
        shapes.memfds.push(MemfdFile {
            pid,
            name,
            target: target.to_owned(),
            size_bytes: size,
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

fn collect_fds(pids: &[u32], sample: &mut MemorySample) {
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
    sample.deleted = deleted;
    sample.memfds = memfds;
}

/// One /proc/slabinfo row: name, num_objs, objsize are columns 0, 2,
/// and 3 of the data lines (after the two header lines). The real
/// kernel header (mm/slab_common.c) is
/// `# name <active_objs> <num_objs> <objsize> <objperslab>
/// <pagesperslab> : tunables ... : slabdata ...` - objsize is the
/// per-object byte size at column 3; column 4 is objperslab, the
/// objects-per-slab packing count. night-dragon-lts-1: this parser
/// read column 4 as the size, so every cache's footprint computed
/// as num_objs * objperslab - up to two orders of magnitude off in
/// either direction (kmalloc-8 overstated 64x, typical 1 KiB+ caches
/// understated 10-100x).
pub(crate) fn parse_slabinfo(contents: &str) -> Vec<SlabRow> {
    let mut rows = Vec::new();
    for line in contents.lines().skip(2) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        let Ok(num_objs) = fields[2].parse::<u64>() else {
            continue;
        };
        let Ok(objsize) = fields[3].parse::<u64>() else {
            continue;
        };
        rows.push(SlabRow {
            cache: fields[0].to_owned(),
            size_kib: num_objs.saturating_mul(objsize) / 1024,
        });
    }
    rows.sort_by(|left, right| {
        right
            .size_kib
            .cmp(&left.size_kib)
            .then(left.cache.cmp(&right.cache))
    });
    rows.truncate(5);
    rows
}

fn collect_slab(sample: &mut MemorySample) {
    match fs::read_to_string("/proc/slabinfo") {
        Ok(contents) => {
            sample.slab = parse_slabinfo(&contents);
            sample.slab_readable = true;
        }
        Err(_) => sample.slab_readable = false,
    }
}

/// The full sample, in the report's own order.
pub(crate) fn collect() -> MemorySample {
    let meminfo = fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|c| parse_meminfo(&c));
    let mut sample = MemorySample {
        meminfo,
        ..Default::default()
    };
    let pids = pid_dirs(Path::new("/proc"));
    collect_pss(&pids, &mut sample);
    collect_tmpfs(&mut sample);
    collect_fds(&pids, &mut sample);
    collect_slab(&mut sample);
    sample.exit_lane = exits::collect_window(exits::EXIT_WINDOW_SECS);
    sample
}

/// The residual arithmetic, stated once (night-dragon-lts-1
/// rewrite): the kernel's unavailable set minus what the readable
/// processes provably own inside it.
///
/// The unavailable set is total - MemAvailable: everything the
/// kernel does not count as readily reclaimable - process anon,
/// shmem, unreclaimable slab, kernel stacks, page tables, reserved
/// regions, and the non-reclaimable tail of the cache. This base
/// deliberately does NOT subtract the reclaimable buckets (page
/// cache, buffers, SReclaimable): MemAvailable already counts them
/// as available, so they are not in the base to begin with - the
/// pre-fix formula subtracted them anyway (double subtraction),
/// which saturated the residual to a permanent 0 B on every
/// cache-rich host and made the 15% verdict threshold unreachable.
///
/// From that base, only the process-owned parts that are genuinely
/// INSIDE the unavailable set come off: Pss_Anon and Pss_Shmem.
/// Pss_File (mapped file pages) is mostly counted as available by
/// the kernel, so subtracting it would double-subtract in the other
/// direction; a file page the kernel pinned as unavailable stays in
/// the residual, honestly. The tmpfs, memfd, and deleted-but-open
/// views attribute pages separately and stay OUT of the arithmetic
/// (their walks are bounded and partial - subtracting a partial sum
/// would make the residual irreproducible). The
/// permission-refused processes' memory rides the residual by
/// construction, and the Unaccounted block names that.
pub(crate) fn residual_kib(sample: &MemorySample) -> Option<u64> {
    let meminfo = sample.meminfo.as_ref()?;
    let unavailable = meminfo.total_kib.saturating_sub(meminfo.available_kib);
    let process_owned: u64 = sample
        .pss
        .iter()
        .map(|p| p.anon_kib.saturating_add(p.shmem_kib))
        .sum();
    Some(unavailable.saturating_sub(process_owned))
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
        .map(|pid| format!("{pid} ({})", comm_of(*pid)))
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

#[cfg(test)]
#[path = "../../../test/commands/doctor/memory_tests.rs"]
mod tests;
