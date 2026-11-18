// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The loader's summary lane (night-frontier-Z7 moved it here - a
//! PURE move under the 600-LOC no-mercy cap, the lane_log.rs and
//! port/unaccounted.rs sibling precedents): the attach/detach
//! summaries and the estate classification the quiet-by-default law
//! serves. One module, one concern - the words the attach boundary
//! prints - so the orchestration half (loader.rs) and the words stop
//! competing for one file's line budget.

use std::path::Path;

use super::PIN_DIR;

// ── The summary lane (quiet by default, loud on request) ────────────

/// The estate's shape, classified from the pin base names: every pin
/// is a program, a link, or a map, and the naming contract carries
/// the role - `*_link` is a link, `probe` / `*_probe` is a program,
/// everything else is a map. The attach summary's (programs, links,
/// maps) counts derive from this one walk, so a future probe pair
/// updates the success line without touching it. The loader_tests
/// pin the classification against ALL_PINS, so a naming drift is
/// caught, not printed wrong.
pub(crate) fn estate_counts() -> (usize, usize, usize) {
    let mut programs = 0;
    let mut links = 0;
    let mut maps = 0;
    for pin in super::ALL_PINS {
        let base = Path::new(pin)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(pin);
        if base.ends_with("_link") {
            links += 1;
        } else if base == "probe" || base.ends_with("_probe") {
            programs += 1;
        } else {
            maps += 1;
        }
    }
    (programs, links, maps)
}

/// The counter readback as a display label: `N=<events>` when the
/// pinned map answered, the honest unreadable note when it did not.
pub(crate) fn count_label(count: &Result<u64, String>) -> String {
    match count {
        Ok(n) => format!("N={n}"),
        Err(e) => format!("counter unreadable ({e})"),
    }
}

/// The fresh-attach success summary. Default: ONE quiet line - the
/// estate's shape and the camera's posture, no probe names, no pin
/// list (the quiet-by-default law; the details are one `-v` away).
/// Verbose: the full report the wall used to print by default -
/// every probe by name and role, the BTF verification claims, the
/// counter read, and the whole pin list, multi-line.
pub(crate) fn attach_success_summary(
    count: &Result<u64, String>,
    writev_symbol: &str,
    offpath_mask: u64,
    verbose: bool,
) -> String {
    let (programs, links, maps) = estate_counts();
    if !verbose {
        let offpath = offpath_caps_label(offpath_mask);
        return format!(
            "eBPF probes attached successfully ({programs} programs, {links} links, \
             {maps} maps; off-path truth: {offpath}). Lazy Camera is now recording."
        );
    }
    format!(
        "probes attached: tracepoints sched/sched_process_exec + \
         sock/inet_sock_set_state + sched/sched_process_exit (the post-mortem \
         exit probe) + raw_syscalls/sys_enter (the write probe, verified by its \
         own recorded write), kprobes vfs_open + {writev_symbol} \
         (the vectorized-write probe, verified from this host's BTF) + \
         vfs_unlink + vfs_rename (the unlink/rename probes, verified from this \
         host's BTF), offsets verified from this host's BTF, counter live; \
         events since attach: {}\npins: {PIN_DIR} (probe, probe_link, stats, \
         sock_probe, sock_probe_link, sock_events, exit_probe, exit_probe_link, \
         proc_events, open_probe, open_probe_link, \
         write_probe, write_probe_link, writev_probe, writev_probe_link, \
         unlink_probe, unlink_probe_link, rename_probe, rename_probe_link, \
         tracked_inodes, file_events, offsets, drop_census)",
        count_label(count)
    )
}

/// The off-path capability set as one display word: the planted
/// classes named, `none` when the host named every one down (a
/// camera without the additive truths is still an honest camera).
pub(crate) fn offpath_caps_label(mask: u64) -> String {
    let mut caps = Vec::new();
    if mask & super::estate::OFFPATH_BIT_DIRTY != 0 {
        caps.push("mmap-dirty");
    }
    if mask & super::estate::OFFPATH_BIT_SPLICE != 0 {
        caps.push("splice");
    }
    if mask & super::estate::OFFPATH_BIT_IOURING != 0 {
        caps.push("io_uring");
    }
    if caps.is_empty() {
        "none".to_owned()
    } else {
        caps.join("+")
    }
}

/// The idempotent already-attached summary. Default: one quiet line
/// with the live counter; verbose: the same plus the pins-present
/// claim and the detach pointer.
pub(crate) fn attach_already_summary(count: &Result<u64, String>, verbose: bool) -> String {
    if !verbose {
        return format!(
            "eBPF probes already attached; nothing to do \
             (events since attach: {}).",
            count_label(count)
        );
    }
    format!(
        "probe is already attached - nothing to do (all pins present; \
         doctor --detach removes it); events since attach: {}",
        count_label(count)
    )
}

/// The detach summary. Default: one quiet line - the count that came
/// down, and the swept note only when the sledgehammer actually
/// swept something (a legacy or foreign leftover is an event worth
/// surfacing even quietly). Verbose: the same facts with the pin
/// directory named.
pub(crate) fn detach_summary(removed: usize, swept: usize, verbose: bool) -> String {
    if !verbose {
        return if swept > 0 {
            format!(
                "eBPF probes detached ({removed} pins removed, {swept} \
                 foreign entries swept)."
            )
        } else {
            format!("eBPF probes detached ({removed} pins removed).")
        };
    }
    if swept > 0 {
        return format!(
            "probes detached: unpinned {removed} pin(s), swept {swept} foreign \
             entr{}; {PIN_DIR} is gone",
            if swept == 1 { "y" } else { "ies" }
        );
    }
    format!("probes detached: unpinned {removed} pin(s); {PIN_DIR} is gone")
}
