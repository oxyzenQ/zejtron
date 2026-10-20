// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

pub(crate) mod ledger;
pub(crate) mod raw;

use std::error::Error;
use std::fmt;
use std::path::PathBuf;

use crate::commands::lane::resolve_window;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Port(u16),
    Path(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhyError(String);

impl fmt::Display for WhyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for WhyError {}

pub fn run(
    target: &str,
    since: Option<&str>,
    trace: bool,
    raw: bool,
) -> Result<(), Box<dyn Error>> {
    let target = parse_target(target)?;
    let (window, window_label) = resolve_window(since).map_err(WhyError)?;
    let output = match target {
        Target::Port(port) => ledger::build_port_report(port, window, window_label, trace, raw)?,
        Target::Path(path) => ledger::build_path_report(&path, window, window_label, trace, raw)?,
    };
    println!("{output}");
    Ok(())
}

fn parse_target(input: &str) -> Result<Target, WhyError> {
    if input.chars().all(|character| character.is_ascii_digit()) {
        let port = input
            .parse::<u32>()
            .map_err(|_| WhyError(format!("invalid port: {input}")))?;
        if !(1..=u32::from(u16::MAX)).contains(&port) {
            return Err(WhyError(format!("invalid port: {input}")));
        }
        return Ok(Target::Port(port as u16));
    }

    Ok(Target::Path(PathBuf::from(input)))
}

#[cfg(test)]
#[path = "../../test/commands/why_tests.rs"]
mod tests;
