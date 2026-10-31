// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! net unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/commands/net.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;

#[test]
fn hex_to_ipv4_decodes_little_endian() {
    // 0x0100007F in little-endian = 127.0.0.1
    assert_eq!(hex_to_ipv4("0100007F"), Some("127.0.0.1".to_owned()));
    // 0x00000000 = 0.0.0.0
    assert_eq!(hex_to_ipv4("00000000"), Some("0.0.0.0".to_owned()));
    // Invalid length
    assert_eq!(hex_to_ipv4("abc"), None);
}

#[test]
fn decode_flags_includes_up_and_promisc() {
    let flags = 0x1 | 0x100; // UP | PROMISC
    let decoded = decode_flags(flags);
    assert!(decoded.contains("UP"));
    assert!(decoded.contains("PROMISC"));
}

#[test]
fn decode_flags_loopback_only() {
    let decoded = decode_flags(0x8 | 0x1 | 0x40); // LOOPBACK | UP | RUNNING
    assert!(decoded.contains("LOOPBACK"));
    assert!(decoded.contains("UP"));
    assert!(decoded.contains("RUNNING"));
    assert!(!decoded.contains("PROMISC"));
}

#[test]
fn human_bytes_formats_correctly() {
    assert_eq!(human_bytes(0), "0B");
    assert_eq!(human_bytes(512), "512B");
    assert_eq!(human_bytes(1024), "1.0KB");
    assert_eq!(human_bytes(1024 * 1024), "1.0MB");
    assert_eq!(human_bytes(1024 * 1024 * 1024), "1.00GB");
}

#[test]
fn format_iface_summary_skips_zero_mac() {
    let iface = InterfaceEntry {
        name: "lo".to_owned(),
        state: Some("unknown".to_owned()),
        mtu: Some(65536),
        mac: Some("00:00:00:00:00:00".to_owned()),
        flags: None,
        iftype: None,
        ipv4: vec![],
        ipv6: vec![],
        rx_bytes: None,
        tx_bytes: None,
        rx_packets: None,
        tx_packets: None,
        rx_errors: None,
        tx_errors: None,
        rx_dropped: None,
        tx_dropped: None,
    };
    let s = format_iface_summary(&iface);
    assert!(!s.contains("mac="));
    assert!(s.contains("lo unknown mtu=65536"));
}

#[test]
fn render_full_report_has_all_sections() {
    let report = NetReport {
        interfaces: vec![InterfaceEntry {
            name: "eth0".to_owned(),
            state: Some("up".to_owned()),
            mtu: Some(1500),
            mac: Some("aa:bb:cc:dd:ee:ff".to_owned()),
            flags: Some(0x1 | 0x40 | 0x100), // UP | RUNNING | PROMISC
            iftype: Some(1),
            ipv4: vec!["10.0.0.5".to_owned()],
            ipv6: vec!["fe80::1".to_owned()],
            rx_bytes: Some(123456),
            tx_bytes: Some(654321),
            rx_packets: Some(100),
            tx_packets: Some(200),
            rx_errors: Some(0),
            tx_errors: Some(0),
            rx_dropped: Some(0),
            tx_dropped: Some(0),
        }],
        arp_neighbors: vec![ArpEntry {
            ip: "10.0.0.1".to_owned(),
            hw_type: "0x1".to_owned(),
            flags: "0x2".to_owned(),
            mac: "ff:ff:ff:ff:ff:ff".to_owned(),
            iface: "eth0".to_owned(),
        }],
        routes: vec![RouteEntry {
            iface: "eth0".to_owned(),
            destination: "default".to_owned(),
            gateway: "10.0.0.1".to_owned(),
            flags: "0003".to_owned(),
            metric: Some(100),
        }],
        default_route: Some("eth0".to_owned()),
        resolver: Some(ResolverConfig {
            nameservers: vec!["8.8.8.8".to_owned()],
            search: vec!["example.com".to_owned()],
            options: vec!["timeout:5".to_owned()],
        }),
    };
    let out = render_report(&report);
    assert!(out.contains("interfaces"));
    assert!(out.contains("eth0 up mtu=1500 mac=aa:bb:cc:dd:ee:ff"));
    assert!(out.contains("ipv4 10.0.0.5"));
    assert!(out.contains("ipv6 fe80::1"));
    assert!(out.contains("PROMISC"));
    assert!(out.contains("rx 120.6KB tx 639.0KB"));
    assert!(out.contains("pkts rx=100 tx=200"));
    assert!(out.contains("arp-neighbors"));
    assert!(out.contains("10.0.0.1 ff:ff:ff:ff:ff:ff eth0"));
    assert!(out.contains("routes"));
    assert!(out.contains("default via 10.0.0.1 eth0 metric=100"));
    assert!(out.contains("resolver"));
    assert!(out.contains("nameserver 8.8.8.8"));
    assert!(out.contains("search example.com"));
    assert!(out.contains("options timeout:5"));
}

#[test]
fn render_empty_report() {
    let report = NetReport {
        interfaces: vec![],
        arp_neighbors: vec![],
        routes: vec![],
        default_route: None,
        resolver: None,
    };
    let out = render_report(&report);
    assert!(out.contains("interfaces"));
    assert!(out.contains("none visible"));
    assert!(out.contains("resolver"));
    assert!(out.contains("missing"));
}

// The JSON lane (night-badass-9): the same report, typed.

#[test]
fn json_report_mirrors_the_model() {
    let report = NetReport {
        interfaces: vec![InterfaceEntry {
            name: "eth0".to_owned(),
            state: Some("up".to_owned()),
            mtu: Some(1500),
            mac: Some("aa:bb:cc:dd:ee:ff".to_owned()),
            flags: Some(0x1 | 0x40 | 0x100),
            iftype: Some(1),
            ipv4: vec!["10.0.0.5".to_owned()],
            ipv6: vec!["fe80::1".to_owned()],
            rx_bytes: Some(123456),
            tx_bytes: Some(654321),
            rx_packets: Some(100),
            tx_packets: Some(200),
            rx_errors: Some(0),
            tx_errors: Some(0),
            rx_dropped: Some(0),
            tx_dropped: Some(0),
        }],
        arp_neighbors: vec![ArpEntry {
            ip: "10.0.0.1".to_owned(),
            hw_type: "0x1".to_owned(),
            flags: "0x2".to_owned(),
            mac: "ff:ff:ff:ff:ff:ff".to_owned(),
            iface: "eth0".to_owned(),
        }],
        routes: vec![RouteEntry {
            iface: "eth0".to_owned(),
            destination: "default".to_owned(),
            gateway: "10.0.0.1".to_owned(),
            flags: "0003".to_owned(),
            metric: Some(100),
        }],
        default_route: Some("eth0".to_owned()),
        resolver: Some(ResolverConfig {
            nameservers: vec!["8.8.8.8".to_owned()],
            search: vec![],
            options: vec![],
        }),
    };
    let out = super::json::report_json(&report);
    // The scalars and the arrays all ride the struct's own field names.
    assert!(out.starts_with("{\"interfaces\":["));
    assert!(out.contains("\"name\":\"eth0\""));
    assert!(out.contains("\"state\":\"up\""));
    assert!(out.contains("\"mtu\":1500"));
    assert!(out.contains("\"mac\":\"aa:bb:cc:dd:ee:ff\""));
    assert!(out.contains("\"ipv4\":[\"10.0.0.5\"]"));
    assert!(out.contains("\"ipv6\":[\"fe80::1\"]"));
    assert!(out.contains("\"rx_bytes\":123456"));
    assert!(out.contains("\"tx_bytes\":654321"));
    assert!(out.contains("\"arp_neighbors\":[{\"ip\":\"10.0.0.1\""));
    assert!(out.contains("\"routes\":[{\"iface\":\"eth0\""));
    assert!(out.contains("\"destination\":\"default\""));
    assert!(out.contains("\"metric\":100"));
    assert!(out.contains("\"default_route\":\"eth0\""));
    assert!(out.contains("\"resolver\":{\"nameservers\":[\"8.8.8.8\"]"));
    // One line, valid JSON shape (balanced).
    assert!(!out.contains('\n'));
}

#[test]
fn json_report_carries_the_absences_as_nulls() {
    let report = NetReport {
        interfaces: vec![InterfaceEntry {
            name: "lo".to_owned(),
            state: None,
            mtu: None,
            mac: None,
            flags: None,
            iftype: None,
            ipv4: vec![],
            ipv6: vec![],
            rx_bytes: None,
            tx_bytes: None,
            rx_packets: None,
            tx_packets: None,
            rx_errors: None,
            tx_errors: None,
            rx_dropped: None,
            tx_dropped: None,
        }],
        arp_neighbors: vec![],
        routes: vec![],
        default_route: None,
        resolver: None,
    };
    let out = super::json::report_json(&report);
    // The absence law: a fact the /proc read could not answer is
    // null, never an empty string and never a fabricated zero.
    assert!(out.contains("\"state\":null"));
    assert!(out.contains("\"mtu\":null"));
    assert!(out.contains("\"mac\":null"));
    assert!(out.contains("\"rx_bytes\":null"));
    assert!(out.contains("\"ipv4\":[],"));
    assert!(out.contains("\"default_route\":null"));
    assert!(out.contains("\"resolver\":null"));
    assert!(out.contains("\"arp_neighbors\":[]"));
    assert!(out.contains("\"routes\":[]"));
}

#[test]
fn loopback_state_resolves_through_the_iff_up_bit() {
    // night-dragon-lts-2: RFC 2863 exempts lo from operstate
    // reporting ("unknown" on every host), so the flags' IFF_UP bit
    // carries the administrative truth instead.
    assert_eq!(
        resolved_state("lo", Some("unknown".to_owned()), Some(0x10049)),
        Some("up".to_owned()),
        "IFF_UP set renders up"
    );
    assert_eq!(
        resolved_state("lo", Some("unknown".to_owned()), Some(0x10048)),
        Some("down".to_owned()),
        "IFF_UP clear renders down"
    );
    // An unreadable flags file never guesses - the kernel's own
    // word rides through untouched.
    assert_eq!(
        resolved_state("lo", Some("unknown".to_owned()), None),
        Some("unknown".to_owned())
    );
    // Every other interface keeps the kernel's operstate word,
    // whatever it says.
    assert_eq!(
        resolved_state("eth0", Some("unknown".to_owned()), Some(0)),
        Some("unknown".to_owned())
    );
    assert_eq!(
        resolved_state("eth0", Some("up".to_owned()), None),
        Some("up".to_owned())
    );
    assert_eq!(resolved_state("eth0", None, None), None);
}

#[test]
fn parse_sysfs_u32_reads_both_kernel_shapes() {
    // night-dragon-lts-2: the flags file rides hex with the 0x
    // prefix ("0x9" on loopback), mtu and type ride decimal. The hex
    // arm repairs the dormant flags lane - read on every host,
    // parsed on none, since plain str::parse rejects the prefix.
    assert_eq!(parse_sysfs_u32("0x9"), Some(0x9));
    assert_eq!(parse_sysfs_u32("0X9"), Some(0x9));
    assert_eq!(parse_sysfs_u32("0x10049"), Some(0x10049));
    assert_eq!(parse_sysfs_u32("65536"), Some(65536));
    assert_eq!(parse_sysfs_u32("772"), Some(772));
    assert_eq!(parse_sysfs_u32(""), None);
    assert_eq!(parse_sysfs_u32("0x"), None);
    assert_eq!(parse_sysfs_u32("not-a-number"), None);
}
