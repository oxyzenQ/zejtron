// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

mod json;
mod model;
mod owners;
mod parser;
mod render;
pub(crate) mod window;

use std::error::Error;

use model::{PortError, PortOptions, Protocol, SocketEntry};
use window::WINDOW_DEFAULT;

pub use model::PortFlags;

#[cfg(test)]
use render::{format_owner, format_unknown_owner, should_show_unreadable_note};

pub fn run(port: Option<&str>, flags: PortFlags) -> Result<(), Box<dyn Error>> {
    let print_json = flags.print_json;
    let options = parse_options(port, flags)?;
    let (sockets, owners, stats) = parser::scan_proc()?;
    let selected = filter_sockets(&sockets, &options);
    // The renderer branch (night-badass-9): the JSON lane speaks the
    // same two truths - the snapshot table and the event window - as
    // one typed line. The lane decision mirrors format_port_output's
    // own branches: --snapshot-only never asks the chain, the default
    // and --events-only shapes capture the window when the chain can
    // serve it and carry the named refusal reason when it cannot.
    // One scan, one capture, two renderers - the text lane below is
    // untouched.
    if print_json {
        let events = if options.snapshot_only {
            None
        } else {
            window::capture_window(&options)
        };
        println!(
            "{}",
            json::port_report_json(&selected, &owners, &stats, &options, events.as_deref())
        );
        return Ok(());
    }
    let output = window::format_port_output(&selected, &owners, &stats, &options);
    println!("{output}");
    Ok(())
}

pub fn parse_options(port: Option<&str>, flags: PortFlags) -> Result<PortOptions, PortError> {
    if flags.listen && flags.all {
        return Err(PortError("--listen cannot be used with --all".to_owned()));
    }
    if flags.events_only && flags.snapshot_only {
        return Err(PortError(
            "--events-only cannot be used with --snapshot-only".to_owned(),
        ));
    }

    let window = match flags.since.as_deref() {
        Some(raw) => window::clamp_window(window::parse_window(raw)?),
        None => WINDOW_DEFAULT,
    };

    Ok(PortOptions {
        port: port.map(validate_port).transpose()?,
        tcp: flags.tcp,
        udp: flags.udp,
        listen: flags.listen,
        all: flags.all,
        numeric: flags.numeric,
        group: flags.group,
        no_pid: flags.no_pid,
        window,
        events_only: flags.events_only,
        snapshot_only: flags.snapshot_only,
    })
}

pub fn validate_port(input: &str) -> Result<u16, PortError> {
    let port: u16 = input
        .parse()
        .map_err(|_| PortError(format!("invalid port: {input}")))?;
    if port == 0 {
        return Err(PortError(format!("invalid port: {input}")));
    }
    Ok(port)
}

pub(crate) fn filter_sockets(sockets: &[SocketEntry], options: &PortOptions) -> Vec<SocketEntry> {
    let include_tcp = options.tcp || !options.udp;
    let include_udp = options.udp || !options.tcp;
    let listen_mode = !options.all;

    let mut selected: Vec<SocketEntry> = sockets
        .iter()
        .filter(|socket| match socket.protocol {
            Protocol::Tcp => include_tcp,
            Protocol::Udp => include_udp,
        })
        .filter(|socket| options.port.is_none_or(|port| socket.port == port))
        .filter(|socket| {
            if !listen_mode {
                return true;
            }
            match socket.protocol {
                Protocol::Tcp => parser::is_tcp_listen(socket.state.as_deref()),
                Protocol::Udp => socket.port != 0,
            }
        })
        .cloned()
        .collect();

    selected.sort_by(|left, right| {
        left.port
            .cmp(&right.port)
            .then(left.protocol.cmp(&right.protocol))
            .then(left.address.cmp(&right.address))
    });
    selected
}

#[cfg(test)]
#[path = "../../../test/commands/port/port_tests.rs"]
mod tests;
