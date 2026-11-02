// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The Mode banner half of the port window (split from window.rs at
//! the 600-LOC cap, the night-hunter-4 precedent): the transparency
//! line the default shape opens with - live or snapshot, the lane's
//! actual cause riding as the qualifier - and the fallback assembly
//! it leads. The banner's sentence is single-sourced from
//! crate::evidence::render::mode_line, the same one-grammar law the
//! unavailability sentence already carries; this module shapes port's
//! words into it. The grammar, the capture pump, and the window
//! report stay in window.rs.

use std::time::Duration;

use super::lane_state::{LaneUnavailable, lane_mode_qualifier};
use super::model::{OwnerMap, PortOptions, ScanStats, SocketEntry};
use super::render::format_report;
use super::window::window_label;

/// The Mode banner (the buyer verification fix): the first line of
/// the default shape's human output, before the ports list - the
/// same sentence the evidence family (why, holds, touch) prints,
/// spoken from the same source
/// (crate::evidence::render::mode_line) so the surfaces cannot
/// drift. `None` is the live window (the capture ran); a lane is the
/// snapshot fallback, and the lane's actual cause rides as the
/// qualifier - the same vocabulary lane_reason's JSON tokens name,
/// one cause, one qualifier, two renderings. The base words come
/// from the evidence Mode enum itself (`Mode::base`), so the words
/// live/snapshot stay single-sourced even here.
pub(super) fn port_mode_line(lane: Option<LaneUnavailable>, window: Duration) -> String {
    let (base, qualifier) = match lane {
        None => (crate::evidence::Mode::Live.base(), ""),
        Some(lane) => (
            crate::evidence::Mode::SnapshotNoLane.base(),
            lane_mode_qualifier(lane),
        ),
    };
    crate::evidence::render::mode_line(base, &window_label(window), qualifier)
}

/// The default shape's fallback: the Mode banner naming the lane's
/// actual refusal, one blank line, then the phase-1 tree
/// byte-identical below it. The tree is the snapshot truth; the
/// banner is the honesty the tree never carried (the buyer
/// verification defect: without it, a degraded run and an attached
/// run with an empty window printed the same bytes, and only
/// --print-json could tell the two apart).
pub(super) fn snapshot_fallback_output(
    sockets: &[SocketEntry],
    owners: &OwnerMap,
    stats: &ScanStats,
    options: &PortOptions,
    lane: LaneUnavailable,
) -> String {
    format!(
        "{}\n\n{}",
        port_mode_line(Some(lane), options.window),
        format_report(sockets, owners, stats, options)
    )
}
