// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

/// Why the window cannot run: the lane's actual state at capture
/// time, classified from the real `stat`/`open` results'
/// `ErrorKind`s, never from error-message text. The
/// live-verification residual: pins planted by a root
/// `doctor --attach` but read by a non-root euid used to render the
/// same "lane-not-attached" token a missing lane renders, and a
/// buyer's pipeline that token into "attach first" - an instruction
/// that never heals a permission wall. The text lane keeps its one
/// refusal sentence (the doctor names the exact cause there); this
/// vocabulary is the JSON changes block's
/// contract, one token and one hint per actual cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LaneUnavailable {
    /// `/sys/fs/bpf/zejtron` does not exist (ENOENT), or the chain
    /// is partial (a pin missing from the set) - or an exotic probe
    /// failure the vocabulary has no token for (the pre-fix
    /// blanket). `doctor --attach` heals every one of these.
    NotAttached,
    /// The pins exist but this euid cannot read them: EACCES at the
    /// directory probe, the directory walk, or the BPF_OBJ_GET open.
    Unreadable,
    /// The pins existed at window start and the directory was gone
    /// when the collection ended - the window watched its own lane
    /// being torn down.
    DetachedMidWindow,
}

/// The lane's reason token and the human next action, as the JSON
/// changes block renders them - one mapping, so the token and its
/// hint cannot drift apart.
pub(crate) fn lane_reason(lane: LaneUnavailable) -> (&'static str, &'static str) {
    match lane {
        LaneUnavailable::NotAttached => (
            "lane-not-attached",
            "attach first: sudo zejtron doctor --attach",
        ),
        LaneUnavailable::Unreadable => (
            "lane-unreadable",
            "pins exist but are root-owned: run with sudo",
        ),
        LaneUnavailable::DetachedMidWindow => (
            "lane-detached-mid-window",
            "the lane was detached mid-window: re-attach and retry",
        ),
    }
}

/// The pin directory's error kind, if any: a passed probe is `None`,
/// a failed one is its `ErrorKind`. The one shaper both the start
/// probe and the mid-window re-stat speak, so the classification is
/// pinned on the kinds alone (a test synthesizes an `io::Error` of
/// the kind; no bpffs, no root, no fixture host needed).
pub(crate) fn dir_error_kind(
    probe: std::io::Result<std::fs::Metadata>,
) -> Option<std::io::ErrorKind> {
    probe.err().map(|error| error.kind())
}

/// The lane state BEFORE the window, from the two probe kinds the
/// capture reads: the pin directory's metadata kind and the
/// directory listing's kind (the read-dir open or its first entry -
/// either refusing is the unreadable story). `None` is "proceed":
/// the directory exists and walks, the lane may be live.
pub(crate) fn lane_state_before_window(
    dir_kind: Option<std::io::ErrorKind>,
    listing_kind: Option<std::io::ErrorKind>,
) -> Option<LaneUnavailable> {
    match dir_kind {
        Some(std::io::ErrorKind::NotFound) => Some(LaneUnavailable::NotAttached),
        Some(std::io::ErrorKind::PermissionDenied) => Some(LaneUnavailable::Unreadable),
        // Any other directory-probe failure (an EIO on bpffs, say)
        // keeps the pre-fix blanket: the vocabulary has no token for
        // it, and the doctor's [eBPF] section names the exact cause.
        Some(_) => Some(LaneUnavailable::NotAttached),
        None => match listing_kind {
            Some(std::io::ErrorKind::PermissionDenied) => Some(LaneUnavailable::Unreadable),
            _ => None,
        },
    }
}

/// The mid-window detach story: the pin directory's re-stat kind
/// after the collection ran. `NotFound` is the detach (the lane
/// existed at the start probe, the directory is gone at the end);
/// any other outcome - present, or a different error - keeps the
/// window's own verdict.
pub(crate) fn lane_detached_mid_window(dir_kind: Option<std::io::ErrorKind>) -> bool {
    dir_kind == Some(std::io::ErrorKind::NotFound)
}

/// The pin directory listing's refusal kind, if any: the read-dir
/// open, or the first entry's read - either refusing is the
/// unreadable story. `None` is a listing this euid can walk.
pub(crate) fn pin_dir_listing_kind() -> Option<std::io::ErrorKind> {
    match std::fs::read_dir(crate::ebpf::PIN_DIR) {
        Err(error) => Some(error.kind()),
        Ok(mut entries) => match entries.next() {
            Some(Err(error)) => Some(error.kind()),
            _ => None,
        },
    }
}

#[cfg(test)]
#[path = "../../../test/commands/port/lane_state_tests.rs"]
mod tests;
