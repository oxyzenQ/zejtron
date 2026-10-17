// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! parser unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/commands/port/parser.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;

#[test]
fn parses_ipv4_local_address_hex_and_port() {
    assert_eq!(
        parse_local_address("0100007F:0BB8", false),
        Some(("127.0.0.1".to_owned(), 3000))
    );
}

#[test]
fn parses_ipv6_line_without_panicking() {
    let line = "0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 42 1 0000000000000000 100 0 0 10 0";
    let entry = parse_proc_net_line(line, Protocol::Tcp, true).unwrap();
    assert_eq!(entry.port, 8080);
    assert_eq!(entry.state, Some("LISTEN".to_owned()));
}

#[test]
fn detects_tcp_listen_state() {
    let line = "0: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000 100 0 0 10 0";
    let entry = parse_proc_net_line(line, Protocol::Tcp, false).unwrap();
    assert!(is_tcp_listen(entry.state.as_deref()));
}
