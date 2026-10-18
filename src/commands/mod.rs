// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The command surface (night-improve-14): one module per subcommand,
//! grouped under this hub so the crate root carries only main.rs -
//! the sibling's src/ root single-file policy. Every consumer resolves
//! through `crate::commands::<name>`, and the check-loc.sh gate
//! enforces that no stray *.rs file ever joins src/ root again.

pub mod doctor;
pub mod holds;
pub mod lane;
pub mod net;
pub mod path;
pub mod port;
pub mod proc;
pub mod recent;
pub mod touch;
pub mod why;
