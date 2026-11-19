// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The off-path probes' attach-time record verification
//! (night-frontier-Z7, D4 - the verify_write.rs doctrine carried to
//! the new classes): the offsets law and the anchor ladder verify
//! the PARSE; this verifies the RECORD. Every planted capability
//! must survive its own door:
//!
//! - mmap-dirty: a scratch file is tracked, opened MAP_SHARED, and
//!   one byte is stored through the mapping - the write fault fires
//!   the kernel's own dirty path, and the drained ring must carry
//!   the scratch's (inode, device, op=6) back.
//! - splice: a scratch file is tracked, a real pipe is filled, and
//!   splice(2) moves the bytes into the file's descriptor - the
//!   drained ring must carry op=7 back.
//! - io_uring: a scratch file is tracked, one IORING_OP_WRITE sqe is
//!   submitted through raw io_uring_setup/io_uring_enter (no
//!   liburing - the syscalls are the ABI), and the drained ring must
//!   carry op=9 back.
//! - memory-backed (night-frontier-Z9, D6): a real memfd is tracked
//!   and two real stores cross its MAP_SHARED mapping - the fresh-
//!   mapping store (the non-present fault arm) and the read-then-
//!   store ride (the write-protection arm) - and the drained ring
//!   must carry op=10 back.
//!
//! THE NAMED-DOWN LAW: a verification failure does NOT refuse the
//! attach - the core camera's five probes stand on their own, and a
//! capability whose record cannot be proven (a memory-backed scratch
//! filesystem, an io_uring-disabled sysctl, a moved kernel shape)
//! is UNPLANTED and NAMED: its pins come down, its mask bit is
//! never set, and the attach summary carries the exact reason. What
//! the estate never does is CLAIM a capability it cannot demonstrate
//! - a silent or guessed off-path probe would be the exact lie the
//!
//! estate refuses everywhere else.
//!
//! The scratch rides verify_write.rs's hardened creator (the atomic
//! mkdir, the ownership check, the process-random name); every
//! verify untracks its key on both legs of every retry, the fail
//! protocol.

use std::fs;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

use super::estate::{
    OFFPATH_BIT_DIRTY, OFFPATH_BIT_IOURING, OFFPATH_BIT_MEMBACKED, OFFPATH_BIT_SPLICE,
};
use super::events::{
    FILE_OP_IO_URING_WRITE, FILE_OP_MMAP_DIRTY, FILE_OP_MMAP_MEMBACKED, FILE_OP_SPLICE_IN,
};
use super::plant::unplant_offpath_capability;
use super::ringbuf::drain_file_events;
use super::tracked::{track_file, untrack_file};
use super::verify_write::create_scratch;
use crate::commands::lane::device_token_from_stat;

/// The verdict set: the mask the estate stamp carries (only the
/// capabilities that PROVED themselves) and the named-down reasons
/// the attach summary carries verbatim.
pub struct OffPathVerdict {
    pub mask: u64,
    pub named_down: Vec<String>,
}

/// Verify every planted off-path capability by firing its real
/// action on a tracked scratch. `planted` names which capabilities
/// the ladder and the availability scan decided to plant; the
/// verdict's mask names which ones PROVED themselves. The caller
/// writes the mask into the generation stamp and prints the
/// named-down reasons.
pub fn verify_offpath_probes(
    dirty: bool,
    splice: bool,
    iouring: bool,
    membacked: bool,
) -> Result<OffPathVerdict, String> {
    let mut mask = 0u64;
    let mut named_down = Vec::new();
    if dirty {
        match verify_capability(verify_mmap_once, FILE_OP_MMAP_DIRTY) {
            Ok(()) => mask |= OFFPATH_BIT_DIRTY,
            Err(error) => {
                // The named-down MUST be clean: an unplant that
                // removes fewer than both pins is the half state the
                // estate refuses - the error propagates and the
                // caller's fail protocol takes the whole estate down
                // (never a half-attached camera).
                unplant_offpath_capability(OFFPATH_BIT_DIRTY)?;
                named_down.push(format!("mmap-dirty named down: {error}"));
            }
        }
    }
    if splice {
        match verify_capability(verify_splice_once, FILE_OP_SPLICE_IN) {
            Ok(()) => mask |= OFFPATH_BIT_SPLICE,
            Err(error) => {
                unplant_offpath_capability(OFFPATH_BIT_SPLICE)?;
                named_down.push(format!("splice named down: {error}"));
            }
        }
    }
    if iouring {
        match verify_capability(verify_iouring_once, FILE_OP_IO_URING_WRITE) {
            Ok(()) => mask |= OFFPATH_BIT_IOURING,
            Err(error) => {
                unplant_offpath_capability(OFFPATH_BIT_IOURING)?;
                named_down.push(format!("io_uring named down: {error}"));
            }
        }
    }
    if membacked {
        match verify_membacked_capability() {
            Ok(()) => mask |= OFFPATH_BIT_MEMBACKED,
            Err(error) => {
                unplant_offpath_capability(OFFPATH_BIT_MEMBACKED)?;
                named_down.push(format!("memory-backed named down: {error}"));
            }
        }
    }
    Ok(OffPathVerdict { mask, named_down })
}

/// One capability's door: the hardened scratch, the tracked key, the
/// real action, the bounded drain. Every retry writes fresh facts
/// (the drain consumes by contract), every leg untracks its key.
fn verify_capability(action: fn(&Path) -> Result<(), String>, op: u8) -> Result<(), String> {
    let (dir, probe) = create_scratch()?;
    let result = once(probe, &dir, action, op);
    let _ = fs::remove_dir_all(&dir);
    result
}

fn once(
    probe_path: std::path::PathBuf,
    _dir: &Path,
    action: fn(&Path) -> Result<(), String>,
    op: u8,
) -> Result<(), String> {
    // The scratch exists with content already (the mmap needs a
    // page-sized file BEFORE the mapping; splice and io_uring write
    // into it). Extend to a full page so the mapping cannot run
    // past EOF.
    fs::write(&probe_path, vec![0x41u8; 4096])
        .map_err(|e| format!("the off-path verification scratch: {e}"))?;
    let meta =
        fs::metadata(&probe_path).map_err(|e| format!("the off-path verification scratch: {e}"))?;
    let inode = meta.ino();
    let device = device_token_from_stat(meta.dev());
    let deadline = Instant::now() + Duration::from_millis(400);
    loop {
        track_file(inode, device)?;
        let push = action(&probe_path);
        if let Err(error) = push {
            let _ = untrack_file(inode, device);
            return Err(format!("the off-path action failed: {error}"));
        }
        let drained = match drain_file_events() {
            Ok(events) => events,
            Err(error) => {
                let _ = untrack_file(inode, device);
                return Err(format!("the off-path verification drain failed: {error}"));
            }
        };
        if drained
            .iter()
            .any(|event| event.inode == inode && event.device == device && event.op == op)
        {
            let _ = untrack_file(inode, device);
            return Ok(());
        }
        if Instant::now() > deadline {
            let _ = untrack_file(inode, device);
            return Err(format!(
                "the probe stayed silent for its own off-path action \
                 (inode {inode:#x} tracked, no op={op} record drained) - the \
                 capability cannot demonstrate its own record"
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

// ── The mmap-dirty action: one real store through a MAP_SHARED page ──

fn verify_mmap_once(probe: &Path) -> Result<(), String> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(probe)
        .map_err(|e| format!("the mmap verification open: {e}"))?;
    // SAFETY: mmap maps one page of a real, page-sized file this
    // process owns (MAP_SHARED, PROT_WRITE - a write fault dirties
    // the page-cache page through the kernel's own dirty path);
    // every return is checked, the store is a plain byte write into
    // the mapped range, and the mapping is unmapped before the fd
    // drops. A failure names itself and never leaves a live mapping.
    unsafe {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_WRITE,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            0,
        );
        if ptr == libc::MAP_FAILED {
            return Err("mmap(MAP_SHARED, PROT_WRITE) failed on the scratch".to_owned());
        }
        let bytes = std::slice::from_raw_parts_mut(ptr.cast::<u8>(), 1);
        bytes[0] = 0x5a;
        if libc::munmap(ptr, 4096) != 0 {
            return Err("munmap failed on the mmap verification scratch".to_owned());
        }
    }
    drop(file);
    Ok(())
}

// ── The splice action: a real pipe filled and spliced into the file ──

fn verify_splice_once(probe: &Path) -> Result<(), String> {
    let mut pipe_fds = [0i32; 2];
    // SAFETY: pipe(2) through libc, the two fds checked and closed on
    // every exit path; the writes and the splice are the syscalls'
    // own contracts.
    unsafe {
        if libc::pipe(pipe_fds.as_mut_ptr()) != 0 {
            return Err("pipe(2) failed for the splice verification".to_owned());
        }
    }
    let (pipe_rd, pipe_wr) = (pipe_fds[0], pipe_fds[1]);
    // SAFETY: from_raw_fd takes ownership of the pipe's write end
    // exactly once; the wrapper's drop closes it (the EOF the splice's
    // read end needs), and nothing else touches this fd.
    let mut writer = unsafe { fs::File::from_raw_fd(pipe_wr) };
    writer
        .write_all(b"splice me into the tracked file - the copy path")
        .map_err(|e| format!("the splice verification pipe write: {e}"))?;
    drop(writer); // EOF for the splice read end
    let file = fs::OpenOptions::new()
        .write(true)
        .truncate(false)
        .open(probe)
        .map_err(|e| format!("the splice verification open: {e}"))?;
    // SAFETY: splice(2) moves the piped bytes into the file
    // descriptor (offsets NULL: the pipe drains, the file writes at
    // its position); the return is the moved byte count or the
    // named error.
    unsafe {
        let moved = libc::splice(
            pipe_rd,
            std::ptr::null_mut(),
            file.as_raw_fd(),
            std::ptr::null_mut(),
            48,
            0,
        );
        if moved < 0 {
            let err = std::io::Error::last_os_error();
            let _ = libc::close(pipe_rd);
            return Err(format!("splice(2) failed: {err}"));
        }
        libc::close(pipe_rd);
    }
    drop(file);
    Ok(())
}

// ── The io_uring action: one real IORING_OP_WRITE through raw syscalls ──

/// The io_uring setup parameter block (the ABI's own layout - no
/// liburing in the tree; the syscalls are the interface). Only the
/// fields the setup path touches are named; the tail padding rides
/// zeroed memory.
#[repr(C)]
struct IoUringParams {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: IoSqringOffsets,
    cq_off: IoCqringOffsets,
}

#[repr(C)]
struct IoSqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
struct IoCqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    user_addr: u64,
}

/// The mmap offsets (the ABI constants: the SQ ring at 0, the CQ
/// ring at 0x8000000, the SQE array at 0x10000000).
const IORING_OFF_CQ_RING: libc::off_t = 0x8000_0000;
const IORING_OFF_SQES: libc::off_t = 0x1000_0000;
/// IORING_OP_WRITE - the liburing ABI number the probe filters on.
const IORING_OP_WRITE_ABI: u8 = 23;

fn verify_iouring_once(probe: &Path) -> Result<(), String> {
    let file = fs::OpenOptions::new()
        .write(true)
        .truncate(false)
        .open(probe)
        .map_err(|e| format!("the io_uring verification open: {e}"))?;
    let fd = file.as_raw_fd();
    let payload = b"written through io_uring - the async kiocb path";
    // SAFETY: the io_uring_setup/enter syscalls through libc::syscall
    // (the ABI's own numbers); every returned fd checked, every ring
    // mapping checked and unmapped, the SQE written from zeroed
    // memory with the opcode the probe filters on. A failure at any
    // hop names itself and closes what it opened.
    unsafe {
        let mut params: IoUringParams = std::mem::zeroed();
        let setup = libc::syscall(libc::SYS_io_uring_setup, 4u32, &mut params as *mut _);
        if setup < 0 {
            let err = std::io::Error::last_os_error();
            return Err(format!(
                "io_uring_setup failed: {err} (a host with io_uring disabled names the capability down)"
            ));
        }
        let ring_fd = setup as i32;
        let sq_size = (params.sq_off.array as usize)
            + (params.sq_entries as usize) * std::mem::size_of::<u32>();
        let cq_size = (params.cq_off.cqes as usize)
            + (params.cq_entries as usize) * std::mem::size_of::<u64>() * 2;
        let sq = libc::mmap(
            std::ptr::null_mut(),
            sq_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            ring_fd,
            0,
        );
        let cq = libc::mmap(
            std::ptr::null_mut(),
            cq_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            ring_fd,
            IORING_OFF_CQ_RING,
        );
        let sqes = libc::mmap(
            std::ptr::null_mut(),
            (params.sq_entries as usize) * 64,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            ring_fd,
            IORING_OFF_SQES,
        );
        if sq == libc::MAP_FAILED || cq == libc::MAP_FAILED || sqes == libc::MAP_FAILED {
            libc::close(ring_fd);
            return Err("io_uring ring mmap failed for the verification".to_owned());
        }
        // One SQE: IORING_OP_WRITE, the scratch's fd, the payload.
        let tail_ptr = sq.add(params.sq_off.tail as usize).cast::<u32>();
        let mask_ptr = sq.add(params.sq_off.ring_mask as usize).cast::<u32>();
        let array_ptr = sq.add(params.sq_off.array as usize).cast::<u32>();
        let tail = tail_ptr.read();
        let index = tail & mask_ptr.read();
        let sqe = sqes.add(index as usize * 64);
        std::ptr::write_bytes(sqe, 0, 64);
        sqe.cast::<u8>().write(IORING_OP_WRITE_ABI);
        sqe.add(4).cast::<i32>().write(fd);
        sqe.add(16).cast::<u64>().write(payload.as_ptr() as u64);
        sqe.add(24).cast::<u32>().write(payload.len() as u32);
        array_ptr.add(index as usize).write(index);
        tail_ptr.write(tail.wrapping_add(1));
        let entered = libc::syscall(
            libc::SYS_io_uring_enter,
            ring_fd,
            1u32,
            0u32,
            0u32,
            std::ptr::null_mut::<()>(),
            std::ptr::null_mut::<()>(),
        );
        libc::munmap(sq, sq_size);
        libc::munmap(cq, cq_size);
        libc::munmap(sqes, (params.sq_entries as usize) * 64);
        libc::close(ring_fd);
        if entered < 0 {
            let err = std::io::Error::last_os_error();
            return Err(format!("io_uring_enter failed: {err}"));
        }
    }
    drop(file);
    Ok(())
}

// ── The memory-backed action (night-frontier-Z9, D6): real stores ────
// ── through MAP_SHARED mappings of a real memfd, both fault arms ────

/// One memory-backed verification door: a real memfd (tmpfs's own
/// anonymous superblock class), tracked by its own (inode, device),
/// two real store arms fired against it, and the drained ring must
/// carry op=10 back. The two arms cover the ladder's dialect split:
/// the fresh-mapping store rides the NON-PRESENT fault arm (the
/// funnel's own arm on the 5.15-6.8 dialects), and the read-then-
/// store ride forces a write-PROTECTION fault (the arm
/// wp_page_shared serves on the 7.x line, where fault-around mapped
/// the page read-only into the writable mapping). A host where
/// neither arm produces a record cannot demonstrate the capability -
/// the named-down shape, never a guess. Mirrors verify_capability's
/// fail protocol: the memfd's key is untracked on every leg of every
/// retry, the fd closed and the mapping torn down on every exit.
fn verify_membacked_capability() -> Result<(), String> {
    // SAFETY: memfd_create(2) through libc::syscall (the ABI's own
    // number, 319 on x86_64 - the same constant the musl and gnu
    // libc crates pin); the returned fd is checked and owned to the
    // end of the door.
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, c"zejtron-verify".as_ptr(), 0u32) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("memfd_create(2) failed: {err}"));
    }
    let fd = fd as i32;
    // SAFETY: ftruncate(2) sizes the memfd to one page - the mapping
    // below cannot run past EOF (the mmap-dirty door's own law).
    if unsafe { libc::ftruncate(fd, 4096) } != 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: closing the fd this door owns is the fail protocol;
        // a memfd has no kernel-visible aliases.
        let _ = unsafe { libc::close(fd) };
        return Err(format!("the memfd ftruncate failed: {err}"));
    }
    // SAFETY: zeroed libc::stat is the syscall's own output shape -
    // every byte the kernel does not write stays zero, no valid
    // address is built from it.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat(2) reads the memfd's own (inode, device) - the
    // identity the tracked_inodes gate and the probe's s_dev walk
    // must agree on (device_token_from_stat is the same converter
    // the file lanes ride).
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: closing the fd this door owns is the fail protocol;
        // a memfd has no kernel-visible aliases.
        let _ = unsafe { libc::close(fd) };
        return Err(format!("the memfd fstat failed: {err}"));
    }
    let inode = stat.st_ino;
    let device = device_token_from_stat(stat.st_dev);
    let deadline = Instant::now() + Duration::from_millis(400);
    let result = loop {
        track_file(inode, device)?;
        let push = membacked_action(fd);
        if let Err(error) = push {
            let _ = untrack_file(inode, device);
            break Err(format!("the memory-backed action failed: {error}"));
        }
        let drained = match drain_file_events() {
            Ok(events) => events,
            Err(error) => {
                let _ = untrack_file(inode, device);
                break Err(format!(
                    "the memory-backed verification drain failed: {error}"
                ));
            }
        };
        if drained.iter().any(|event| {
            event.inode == inode && event.device == device && event.op == FILE_OP_MMAP_MEMBACKED
        }) {
            let _ = untrack_file(inode, device);
            break Ok(());
        }
        if Instant::now() > deadline {
            let _ = untrack_file(inode, device);
            break Err(format!(
                "the probe stayed silent for its own memory-backed action \
                 (memfd inode {inode:#x} tracked, no op={FILE_OP_MMAP_MEMBACKED} record \
                 drained) - the capability cannot demonstrate its own record"
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    // SAFETY: closing the fd this door owns; the memfd's mappings are
    // already torn down inside the action.
    let _ = unsafe { libc::close(fd) };
    result
}

/// The two real store arms, fired per attempt: the fresh-mapping
/// store (the non-present arm) and the read-then-store ride (the
/// write-protection arm fault-around prepared). Every mapping is
/// torn down before the action returns; a failure names itself.
fn membacked_action(fd: i32) -> Result<(), String> {
    // SAFETY: two mappings of one real page-sized memfd this process
    // owns (MAP_SHARED, the stores are plain byte writes into the
    // mapped ranges); every return is checked, every mapping is
    // unmapped on every path, the fd outlives both mappings. The
    // read fault before the second store is what arms the
    // write-protection path on fault-around kernels.
    unsafe {
        // Arm A: the fresh mapping's first store - the non-present
        // fault arm the funnel serves directly.
        let ptr_a = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        if ptr_a == libc::MAP_FAILED {
            return Err("mmap(MAP_SHARED, PROT_WRITE) failed on the memfd".to_owned());
        }
        let bytes_a = std::slice::from_raw_parts_mut(ptr_a.cast::<u8>(), 1);
        bytes_a[0] = 0x5a;
        if libc::munmap(ptr_a, 4096) != 0 {
            return Err("munmap failed on the memfd arm-A mapping".to_owned());
        }
        // Arm B: read fault first (fault-around may map the page
        // read-only into this writable mapping), then the store - the
        // write-protection arm wp_page_shared serves on the 7.x line.
        let ptr_b = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        if ptr_b == libc::MAP_FAILED {
            return Err("mmap(MAP_SHARED, PROT_READ|PROT_WRITE) failed on the memfd".to_owned());
        }
        let probe_bytes = std::slice::from_raw_parts(ptr_b.cast::<u8>(), 1);
        let _touched = probe_bytes[0];
        let bytes_b = std::slice::from_raw_parts_mut(ptr_b.cast::<u8>(), 1);
        bytes_b[0] = 0xa5;
        if libc::munmap(ptr_b, 4096) != 0 {
            return Err("munmap failed on the memfd arm-B mapping".to_owned());
        }
    }
    Ok(())
}
