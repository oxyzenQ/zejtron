// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The mount prerequisites (night-improve-61): tracefs and bpffs,
//! the two filesystems the probe estate rides on. aya resolves a
//! tracepoint attach through tracefs (it looks at /sys/kernel/tracing
//! and then /sys/kernel/debug/tracing, and answers "tracefs not
//! found" when neither is mounted), and the pins live on bpffs at
//! /sys/fs/bpf. On a fresh server NEITHER is mounted by default -
//! the first `doctor --attach` died at the tracepoint attach with a
//! library error that named neither the fix nor the filesystem,
//! while the doctor's readiness rows said nothing about the missing
//! mounts (the detective failed to detect its own prerequisites).
//!
//! The ensure pair closes that gap the way the kernel's own tooling
//! does (bpftool mounts bpffs on demand for a pinned load): a
//! privileged attach MOUNTS what it needs instead of failing, and an
//! unprivileged one refuses with the exact mount command in the
//! error. The detection is statfs(2) on the mount points - the
//! filesystem magic, not a `mount` parse, not a directory-existence
//! guess (the kernel creates /sys/kernel/tracing as an empty
//! sysfs directory even when tracefs is not mounted there; only the
//! magic distinguishes the mounted from the placeholder).
//!
//! std + the one libc escape hatch the Cargo.toml notes (statfs and
//! mount are syscalls without a std wrapper); no subprocess, no
//! mount(8) invocation.

use std::ffi::CString;

use crate::output::verbose::vlog;

/// The primary tracefs seat (kernel >= 4.1): the kernel creates the
/// directory whether or not tracefs is mounted there.
pub const TRACEFS_PRIMARY: &str = "/sys/kernel/tracing";

/// The legacy seat: some hosts mount tracefs only under debugfs.
pub const TRACEFS_FALLBACK: &str = "/sys/kernel/debug/tracing";

/// The bpffs seat: where every pin lives (loader::PIN_DIR's parent).
pub const BPFFS_DIR: &str = "/sys/fs/bpf";

/// tracefs magic (include/uapi/linux/magic.h).
const TRACEFS_MAGIC: i64 = 0x7472_6163;

/// debugfs magic: /sys/kernel/debug/tracing mounted via debugfs is a
/// valid tracefs seat for a tracepoint attach.
const DEBUGFS_MAGIC: i64 = 0x6462_6720;

/// bpf fs magic.
const BPF_FS_MAGIC: i64 = 0xcafe_4a11;

/// The filesystem magic statfs(2) reports at `path`, or None when
/// the path is absent or the stat itself fails (the honest absence -
/// an unstatable path is not a mounted anything).
fn fs_magic(path: &str) -> Option<i64> {
    let c_path = CString::new(path).ok()?;
    let mut buffer = unsafe { std::mem::zeroed::<libc::statfs>() };
    let rc = unsafe { libc::statfs(c_path.as_ptr(), &raw mut buffer) };
    if rc != 0 {
        return None;
    }
    Some(buffer.f_type)
}

/// The tracefs seat state: which path carries a mounted tracefs (or
/// a debugfs-backed tracing directory), or neither. One source for
/// the doctor's Tracefs row and the attach-time check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TracefsState {
    /// tracefs (or a debugfs tracing tree) is mounted here.
    Mounted(&'static str),
    /// Neither seat carries a mount: the placeholder directories
    /// under /sys/kernel are not tracefs.
    Absent,
}

/// Probe the tracefs seats, aya's own order: the primary first, the
/// debugfs-backed fallback second.
pub fn tracefs_state() -> TracefsState {
    for seat in [TRACEFS_PRIMARY, TRACEFS_FALLBACK] {
        match fs_magic(seat) {
            Some(TRACEFS_MAGIC) | Some(DEBUGFS_MAGIC) => return TracefsState::Mounted(seat),
            _ => continue,
        }
    }
    TracefsState::Absent
}

/// True when the bpffs seat carries a bpf filesystem mount.
fn bpffs_mounted() -> bool {
    fs_magic(BPFFS_DIR) == Some(BPF_FS_MAGIC)
}

/// True when the effective capability set carries CAP_SYS_ADMIN - the
/// capability a mount(2) needs. The CapEff line is the truth
/// regardless of euid, the same discipline as the lane's CAP_BPF /
/// CAP_PERFMON gate (a container root without the bit reads honestly
/// as unable to mount).
fn can_mount() -> bool {
    super::cap_bit_present(super::CAP_SYS_ADMIN)
}

/// The one mount, with the errno in the error when it fails. Used
/// for tracefs and bpffs alike; MS_RDONLY is deliberately absent
/// (tracefs needs writes for its own control files, and bpffs
/// carries the pin creates and unlinks).
fn mount_filesystem(fstype: &str, target: &str) -> Result<(), String> {
    let c_source = CString::new(fstype).map_err(|e| format!("{fstype} source: {e}"))?;
    let c_target = CString::new(target).map_err(|e| format!("{target}: {e}"))?;
    let c_fstype = CString::new(fstype).map_err(|e| format!("{fstype} type: {e}"))?;
    let rc = unsafe {
        libc::mount(
            c_source.as_ptr(),
            c_target.as_ptr(),
            c_fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(format!(
            "the {fstype} mount at {target} failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Ensure tracefs is mounted and return the seat the tracepoint
/// attaches resolve through. Mounted already: the seat, unchanged.
/// Absent and privileged: mount tracefs at the primary seat (the
/// kernel's own directory) and return it. Absent and unprivileged:
/// the refusal names the exact command, the shape every refusal in
/// the attach chain already carries.
pub fn ensure_tracefs() -> Result<&'static str, String> {
    if let TracefsState::Mounted(seat) = tracefs_state() {
        return Ok(seat);
    }
    if !can_mount() {
        return Err(format!(
            "tracefs is not mounted (neither {TRACEFS_PRIMARY} nor {TRACEFS_FALLBACK} \
             carries a tracefs mount) and this process lacks CAP_SYS_ADMIN, so it cannot \
             mount it. The tracepoint probes resolve through tracefs. Mount it as root: \
             mount -t tracefs tracefs {TRACEFS_PRIMARY}"
        ));
    }
    vlog!(
        "engine",
        "tracefs is not mounted - mounting it at {TRACEFS_PRIMARY} (the attach needs it)"
    );
    mount_filesystem("tracefs", TRACEFS_PRIMARY)?;
    Ok(TRACEFS_PRIMARY)
}

/// Ensure the bpffs seat is a bpf filesystem mount: the pins need it.
/// Mounted already: nothing. Absent and privileged: mount it (the
/// bpftool precedent - a pinned load mounts the seat it pins into).
/// Absent and unprivileged: the refusal names the command.
pub fn ensure_bpffs() -> Result<(), String> {
    if bpffs_mounted() {
        return Ok(());
    }
    if !can_mount() {
        return Err(format!(
            "bpffs is not mounted at {BPFFS_DIR} and this process lacks CAP_SYS_ADMIN, \
             so it cannot mount it. The probe estate pins into bpffs. Mount it as root: \
             mount -t bpf bpf {BPFFS_DIR}"
        ));
    }
    vlog!(
        "engine",
        "bpffs is not mounted - mounting it at {BPFFS_DIR} (the pins need it)"
    );
    mount_filesystem("bpf", BPFFS_DIR)
}

#[cfg(test)]
#[path = "../../test/ebpf/mounts_tests.rs"]
mod tests;
