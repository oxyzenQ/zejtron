// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

mod model;
mod owners;
mod parser;
mod render;

use std::error::Error;

use model::{PortError, PortOptions, Protocol, SocketEntry};
use render::format_report;

pub use model::PortFlags;

#[cfg(test)]
use render::{format_owner, format_unknown_owner, should_show_unreadable_note};

pub fn run(port: Option<&str>, flags: PortFlags) -> Result<(), Box<dyn Error>> {
    let options = parse_options(port, flags)?;
    let (sockets, owners, stats) = parser::scan_proc()?;
    let selected = filter_sockets(&sockets, &options);
    let output = format_report(&selected, &owners, &stats, &options);
    println!("{output}");
    Ok(())
}

pub fn parse_options(port: Option<&str>, flags: PortFlags) -> Result<PortOptions, PortError> {
    if flags.listen && flags.all {
        return Err(PortError("--listen cannot be used with --all".to_owned()));
    }

    Ok(PortOptions {
        port: port.map(validate_port).transpose()?,
        tcp: flags.tcp,
        udp: flags.udp,
        listen: flags.listen,
        all: flags.all,
        numeric: flags.numeric,
        group: flags.group,
        no_pid: flags.no_pid,
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
