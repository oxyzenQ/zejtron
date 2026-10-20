// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

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
        // unwrapped.
        let mut lines = vec![ok_out(
            "Raw kernel events (file_events ring, as drained; CLOCK_MONOTONIC ns):",
        )];
        for event in &parts.raw {
            let op = match event.op {
                crate::ebpf::events::FILE_OP_OPEN => "open",
                crate::ebpf::events::FILE_OP_WRITE => "write",
                crate::ebpf::events::FILE_OP_UNLINK => "unlink",
                _ => "unknown",
            };
            let device_hex = format!("{:#x}", event.device);
            lines.push(format!(
                "  {} {}{} {}{} {}{} {}{}",
                event.timestamp_ns,
                grey_out("op="),
                op,
                grey_out("inode="),
                event.inode,
                grey_out("device="),
                device_hex,
                grey_out("pid="),
                event.pid
            ));
        }
        format!("\n{}", lines.join("\n"))
    }
}
