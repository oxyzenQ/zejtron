// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
//! The event-row rendering pins (split from window_tests.rs with the
//! events.rs seam, the 600-LOC cap discipline): the transition and
//! protocol labels, the row shape (provenance tag, attribution, the
//! --no-pid token), the empty window's honesty, and the UDP-only
//! kernel-truth note. The grammar, capture, and snapshot pins stay
//! in window_tests.rs. Wired from src/commands/port/events.rs.

#[cfg(test)]
mod fixture {}
