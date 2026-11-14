// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The command surface (night-improve-14): one module per subcommand,
//! grouped under this hub so the crate root carries only main.rs -
//! the sibling's src/ root single-file policy. Every consumer resolves
//! through `crate::commands::<name>`, and the check-loc.sh gate
//! enforces that no stray *.rs file ever joins src/ root again.

pub mod doctor;
pub mod holds;
pub mod lane;
pub(crate) mod lane_unaccounted;
pub mod net;
pub mod path;
pub mod port;
pub mod proc;
pub mod recent;
pub mod sig;
pub mod touch;
pub mod why;

// The Mode banner guard (the buyer verification defect class): the cross-verb
// net that keeps every --since verb's human output banner-first.
#[cfg(test)]
#[path = "../../test/commands/mode_banner_guard_tests.rs"]
mod mode_banner_guard;
