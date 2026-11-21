// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The why surface's --raw section (the kernel's own records as
//! drained, before the surface filter and before attribution).
//! Moved verbatim from the ledger module (night-improve-37's tree
//! discipline: the 600-line cap means SPLIT, a pure move, gates green
//! in between) - one function, no logic changed, the render byte-
//! identical in Mono and tiered on the stdout lane exactly as before.

use crate::commands::lane;
use crate::output::{grey_out, ok_out};

/// The --raw section: the kernel's own records as drained, before
/// the surface filter and before attribution.
pub(crate) fn raw_section(parts: &lane::LaneParts) -> String {
    {
        if parts.raw.is_empty() {
            return grey_out(
                "\nRaw kernel events (file_events ring, as drained):\n  (none - the \
                    event lane is not live in this run, or the window held nothing)",
            );
        }
        // The section header rides green; the event rows' keys ride
        // grey with their values (the timestamps, inodes, pids)
        // unwrapped. The identity block (night-frontier-Z8, D5) rides
        // its own three keys: comm (the actor's own name, the record
        // cannot outlive it), cgroup (the default-hierarchy cgroup
        // id, the kernfs inode stat(2) reports for the cgroup's
        // directory - hex, the form the pod spec names), and netns
        // (the network-namespace inode number, the integer /proc's
        // ns/net symlink prints). Zero netns = the walk could not
        // resolve on this host - the named unavailability, rendered
        // as such; an empty comm renders "(unnamed)", the honest
        // absence, never a guessed name.
        let mut lines = vec![ok_out(
            "Raw kernel events (file_events ring, as drained; CLOCK_MONOTONIC ns):",
        )];
        for event in &parts.raw {
            let op = match event.op {
                crate::ebpf::events::FILE_OP_OPEN => "open",
                crate::ebpf::events::FILE_OP_WRITE => "write",
                crate::ebpf::events::FILE_OP_UNLINK => "unlink",
                crate::ebpf::events::FILE_OP_RENAME => "rename",
                crate::ebpf::events::FILE_OP_WRITEV => "write (writev)",
                crate::ebpf::events::FILE_OP_MMAP_DIRTY => "write (mmap dirty page)",
                crate::ebpf::events::FILE_OP_MMAP_MEMBACKED => "write (mmap memory-backed page)",
                crate::ebpf::events::FILE_OP_SPLICE_IN => "splice (into)",
                crate::ebpf::events::FILE_OP_SPLICE_OUT => "splice (out of)",
                crate::ebpf::events::FILE_OP_IO_URING_WRITE => "write (io_uring)",
                _ => "unknown",
            };
            let device_hex = format!("{:#x}", event.device);
            let cgroup_hex = format!("{:#x}", event.cgroup_id);
            let comm = if event.comm[0] != 0 {
                crate::commands::doctor::memory::exits::comm_string(&event.comm)
            } else {
                "(unnamed)".to_owned()
            };
            let netns = if event.netns_inum == 0 {
                "unavailable".to_owned()
            } else {
                event.netns_inum.to_string()
            };
            lines.push(format!(
                "  {} {}{} {}{} {}{} {}{} {}{} {}{} {}{}",
                event.timestamp_ns,
                grey_out("op="),
                op,
                grey_out("inode="),
                event.inode,
                grey_out("device="),
                device_hex,
                grey_out("pid="),
                event.pid,
                grey_out("comm="),
                comm,
                grey_out("cgroup="),
                cgroup_hex,
                grey_out("netns="),
                netns
            ));
        }
        format!("\n{}", lines.join("\n"))
    }
}
