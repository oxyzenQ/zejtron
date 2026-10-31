// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The netlink address-dump parser's pins (night-dragon-lts-4):
//! every message shape the RTM_GETADDR dump rides, built as raw
//! bytes so the walker is pinned against the kernel's own wire
//! format - header strides, attribute alignment, the IFA_LOCAL
//! precedence law, and the refusal shapes.

use super::*;

/// One netlink message: the 16-byte nlmsghdr plus a payload.
/// nlmsg_len counts header + payload; the walker strides the
/// buffer by the 4-byte alignment of that length.
fn nlmsg(msg_type: u16, payload: &[u8]) -> Vec<u8> {
    let len = 16 + payload.len();
    let mut msg = Vec::with_capacity((len + 3) & !3);
    msg.extend_from_slice(&(len as u32).to_ne_bytes());
    msg.extend_from_slice(&msg_type.to_ne_bytes());
    msg.extend_from_slice(&0u16.to_ne_bytes()); // flags
    msg.extend_from_slice(&1u32.to_ne_bytes()); // seq
    msg.extend_from_slice(&0u32.to_ne_bytes()); // pid
    msg.extend_from_slice(payload);
    msg
}

/// One ifaddrmsg: family, prefixlen, flags, scope, ifindex - plus
/// the attribute bytes the caller appends.
fn ifaddrmsg(family: u8, ifindex: u32, attrs: &[u8]) -> Vec<u8> {
    let mut payload = vec![family, 0, 0, 0];
    payload.extend_from_slice(&ifindex.to_ne_bytes());
    payload.extend_from_slice(attrs);
    payload
}

/// One rtattr: len (header + payload, unpadded), type, payload.
fn rtattr(rta_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut attr = Vec::new();
    attr.extend_from_slice(&((4 + payload.len()) as u16).to_ne_bytes());
    attr.extend_from_slice(&rta_type.to_ne_bytes());
    attr.extend_from_slice(payload);
    // The kernel writes each attribute's footprint 4-byte aligned:
    // rta_len stays unpadded, the trailing bytes are padding.
    while attr.len() % 4 != 0 {
        attr.push(0);
    }
    attr
}

#[test]
fn the_addr_dump_yields_per_interface_rows_and_ends_cleanly() {
    // Two interfaces, one address each: eth0 (ifindex 2) carries its
    // address as IFA_LOCAL, wlan0 (ifindex 3) as IFA_ADDRESS only -
    // both are the host's own address and both yield a row. The
    // NLMSG_DONE marker ends the dump.
    let mut buf = Vec::new();
    buf.extend_from_slice(&nlmsg(
        RTM_NEWADDR,
        &ifaddrmsg(2, 2, &rtattr(IFA_LOCAL, &[192, 168, 1, 5])),
    ));
    buf.extend_from_slice(&nlmsg(
        RTM_NEWADDR,
        &ifaddrmsg(2, 3, &rtattr(IFA_ADDRESS, &[10, 0, 0, 1])),
    ));
    buf.extend_from_slice(&nlmsg(NLMSG_DONE, &[0; 4]));

    let chunk = parse_addr_dump(&buf);
    assert_eq!(chunk.rows, vec![(2, [192, 168, 1, 5]), (3, [10, 0, 0, 1])]);
    assert!(chunk.ended);
    assert!(chunk.error.is_none());
}

#[test]
fn ifa_local_wins_over_ifa_address_on_point_to_point_shapes() {
    // A point-to-point link carries both attributes: IFA_ADDRESS is
    // the PEER's address, IFA_LOCAL is the host's own - the row
    // must carry the local one, never the peer.
    let mut attrs = rtattr(IFA_ADDRESS, &[10, 9, 9, 9]);
    attrs.extend_from_slice(&rtattr(IFA_LOCAL, &[10, 1, 1, 1]));
    let buf = nlmsg(RTM_NEWADDR, &ifaddrmsg(2, 7, &attrs));

    let chunk = parse_addr_dump(&buf);
    assert_eq!(chunk.rows, vec![(7, [10, 1, 1, 1])]);
}

#[test]
fn non_ipv4_families_and_other_messages_are_skipped() {
    // An AF_INET6 row rides the same dump shape and must not yield
    // an IPv4 row; a foreign message type strides past untouched.
    let mut buf = Vec::new();
    buf.extend_from_slice(&nlmsg(
        RTM_NEWADDR,
        &ifaddrmsg(10, 5, &rtattr(IFA_LOCAL, &[0x20, 0x01, 0x0d, 0xb8])),
    ));
    buf.extend_from_slice(&nlmsg(16, &[0; 4])); // some other rtnetlink type
    buf.extend_from_slice(&nlmsg(NLMSG_DONE, &[0; 4]));

    let chunk = parse_addr_dump(&buf);
    assert!(chunk.rows.is_empty());
    assert!(chunk.ended);
}

#[test]
fn an_error_message_names_the_refusal() {
    // EPERM as an i32 payload: the dump is refused and the walker
    // says so instead of rendering a quietly empty table.
    let payload = (-13i32).to_ne_bytes().to_vec();
    let buf = nlmsg(NLMSG_ERROR, &payload);

    let chunk = parse_addr_dump(&buf);
    assert_eq!(chunk.error, Some(-13));
    assert!(!chunk.ended);
    assert!(chunk.rows.is_empty());
}

#[test]
fn attribute_alignment_strides_the_four_byte_law() {
    // An attribute with a 5-byte payload (IFA_LABEL is the classic
    // odd-length shape, here 4 bytes of label plus its NUL is 5):
    // its rta_len is 9 and the walker must stride 12 to the next
    // attribute - the IFA_LOCAL behind it still parses.
    let mut attrs = rtattr(3, &[b'e', b't', b'h', b'0', 0]); // IFA_LABEL
    attrs.extend_from_slice(&rtattr(IFA_LOCAL, &[172, 16, 0, 1]));
    let buf = nlmsg(RTM_NEWADDR, &ifaddrmsg(2, 4, &attrs));

    let chunk = parse_addr_dump(&buf);
    assert_eq!(chunk.rows, vec![(4, [172, 16, 0, 1])]);
}

#[test]
fn malformed_lengths_stop_the_walk_where_they_stand() {
    // A lying nlmsg_len past the buffer's end, a header-only
    // fragment, and an empty buffer: none of them may panic or
    // guess a stride - the walk stops, zero rows, not ended.
    let lying = {
        let mut b = 16u32.to_ne_bytes().to_vec();
        b[0..4].copy_from_slice(&999u32.to_ne_bytes()); // len 999 > buffer
        b
    };
    assert!(parse_addr_dump(&lying).rows.is_empty());

    let fragment = [0u8; 10]; // shorter than a header
    let chunk = parse_addr_dump(&fragment);
    assert!(chunk.rows.is_empty() && !chunk.ended);

    let chunk = parse_addr_dump(&[]);
    assert!(chunk.rows.is_empty() && !chunk.ended);
}
