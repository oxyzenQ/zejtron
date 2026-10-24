// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The net surface's JSON lane (night-badass-9, the universal JSON
//! law): the report the text tree renders, as one typed line. The
//! schema mirrors the surface's own data model one-to-one - the
//! [`NetReport`] struct IS the schema - so an SRE reads the shape off
//! the same types the renderer walks: interfaces with their counters,
//! the ARP neighbors, the routes, the default route, the resolver.
//! The absence law is the ledger JSON's own: a fact the /proc read
//! could not answer is JSON null, never an empty string and never a
//! fabricated zero.

use super::{ArpEntry, InterfaceEntry, NetReport, ResolverConfig, RouteEntry};
use crate::evidence::json::{write_array, write_opt_string, write_opt_u64, write_string};

/// The report as one JSON line. Field order follows the text render's
/// section order (interfaces, arp, routes, resolver) with the report's
/// scalars beside them; the order is the contract the automation lane
/// pins, same as the ledger's own writer.
pub(super) fn report_json(report: &NetReport) -> String {
    let mut out = String::with_capacity(1024);
    out.push_str("{\"interfaces\":");
    write_array(&mut out, report.interfaces.len(), |out, index| {
        interface_json(out, &report.interfaces[index]);
    });
    out.push_str(",\"arp_neighbors\":");
    write_array(&mut out, report.arp_neighbors.len(), |out, index| {
        arp_json(out, &report.arp_neighbors[index]);
    });
    out.push_str(",\"routes\":");
    write_array(&mut out, report.routes.len(), |out, index| {
        route_json(out, &report.routes[index]);
    });
    out.push_str(",\"default_route\":");
    write_opt_string(&mut out, report.default_route.as_deref());
    out.push_str(",\"resolver\":");
    match &report.resolver {
        Some(resolver) => resolver_json(&mut out, resolver),
        None => out.push_str("null"),
    }
    out.push('}');
    out
}

fn interface_json(out: &mut String, iface: &InterfaceEntry) {
    out.push_str("{\"name\":");
    write_string(out, &iface.name);
    out.push_str(",\"state\":");
    write_opt_string(out, iface.state.as_deref());
    out.push_str(",\"mtu\":");
    write_opt_u64(out, iface.mtu.map(u64::from));
    out.push_str(",\"mac\":");
    write_opt_string(out, iface.mac.as_deref());
    out.push_str(",\"ipv4\":");
    write_array(out, iface.ipv4.len(), |out, index| {
        write_string(out, &iface.ipv4[index]);
    });
    out.push_str(",\"ipv6\":");
    write_array(out, iface.ipv6.len(), |out, index| {
        write_string(out, &iface.ipv6[index]);
    });
    out.push_str(",\"rx_bytes\":");
    write_opt_u64(out, iface.rx_bytes);
    out.push_str(",\"tx_bytes\":");
    write_opt_u64(out, iface.tx_bytes);
    out.push_str(",\"rx_packets\":");
    write_opt_u64(out, iface.rx_packets);
    out.push_str(",\"tx_packets\":");
    write_opt_u64(out, iface.tx_packets);
    out.push_str(",\"rx_errors\":");
    write_opt_u64(out, iface.rx_errors);
    out.push_str(",\"tx_errors\":");
    write_opt_u64(out, iface.tx_errors);
    out.push_str(",\"rx_dropped\":");
    write_opt_u64(out, iface.rx_dropped);
    out.push_str(",\"tx_dropped\":");
    write_opt_u64(out, iface.tx_dropped);
    out.push('}');
}

fn arp_json(out: &mut String, entry: &ArpEntry) {
    out.push_str("{\"ip\":");
    write_string(out, &entry.ip);
    out.push_str(",\"hw_type\":");
    write_string(out, &entry.hw_type);
    out.push_str(",\"flags\":");
    write_string(out, &entry.flags);
    out.push_str(",\"mac\":");
    write_string(out, &entry.mac);
    out.push_str(",\"iface\":");
    write_string(out, &entry.iface);
    out.push('}');
}

fn route_json(out: &mut String, entry: &RouteEntry) {
    out.push_str("{\"iface\":");
    write_string(out, &entry.iface);
    out.push_str(",\"destination\":");
    write_string(out, &entry.destination);
    out.push_str(",\"gateway\":");
    write_string(out, &entry.gateway);
    out.push_str(",\"flags\":");
    write_string(out, &entry.flags);
    out.push_str(",\"metric\":");
    write_opt_u64(out, entry.metric.map(u64::from));
    out.push('}');
}

fn resolver_json(out: &mut String, resolver: &ResolverConfig) {
    out.push_str("{\"nameservers\":");
    write_array(out, resolver.nameservers.len(), |out, index| {
        write_string(out, &resolver.nameservers[index]);
    });
    out.push_str(",\"search\":");
    write_array(out, resolver.search.len(), |out, index| {
        write_string(out, &resolver.search[index]);
    });
    out.push_str(",\"options\":");
    write_array(out, resolver.options.len(), |out, index| {
        write_string(out, &resolver.options[index]);
    });
    out.push('}');
}
