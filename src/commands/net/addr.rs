// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! Per-interface IPv4 addresses from the kernel's own address
//! table (night-dragon-lts-4): one RTM_GETADDR dump on a netlink
//! route socket, parsed into (ifindex, address) rows.
//!
//! The pre-fix reader walked /proc/net/fib_trie with an off-by-one
//! (the candidate line was read two lines above the "32 host LOCAL"
//! marker instead of one), so the walker harvested trie-branch
//! lines and network addresses - on this project's own 5.10 host it
//! returned nothing while the interface carried 21.0.4.77 - and
//! fib_trie carries no interface names at all, so the list could
//! never have been per-interface. The kernel's netlink table is
//! the authoritative source iproute2 itself reads: one request,
//! every RTM_NEWADDR row keyed by ifindex, IFA_LOCAL preferred over
//! IFA_ADDRESS (on point-to-point links IFA_ADDRESS is the peer;
//! on normal interfaces the two are equal and IFA_LOCAL is the
//! host's own).
//!
//! Honesty of the failure mode: any refusal (no socket, a send
//! failure, a netlink error, a recv timeout) yields an empty table
//! and the interfaces render no IPv4 rows - the same named absence
//! an unreadable /proc yields, never a guessed address. A recv
//! timeout mid-dump keeps the rows already parsed; NLMSG_DONE is
//! the only clean end.

use std::collections::HashMap;

// The netlink constants the walker speaks (linux/netlink.h,
// linux/rtnetlink.h, linux/if_addr.h) - a handful, kept local so
// the protocol surface this module rides is readable in one place.
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const NLMSG_ERROR: u16 = 0x2;
const NLMSG_DONE: u16 = 0x3;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ROOT: u16 = 0x100;
const NLM_F_MATCH: u16 = 0x200;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const AF_INET: u8 = 2;

/// One recv buffer's verdict: the (ifindex, dotted-quad octets)
/// rows the buffer carried, whether the dump ended inside it
/// (NLMSG_DONE), and the netlink error code if the kernel refused
/// the dump (None for no error; code 0 is a bare ACK, which a dump
/// without NLM_F_ACK never receives).
pub(crate) struct AddrDumpChunk {
    pub rows: Vec<(u32, [u8; 4])>,
    pub ended: bool,
    pub error: Option<i32>,
}

/// Walk one recv buffer's netlink messages: every RTM_NEWADDR of
/// AF_INET yields its interface's address row (IFA_LOCAL first,
/// IFA_ADDRESS as the fallback), NLMSG_DONE ends the dump, and
/// NLMSG_ERROR with a nonzero code names the refusal. Malformed
/// lengths stop the walk where they stand - the driver's recv loop
/// owns the retry law, and a guessed stride past a lying length
/// would read past the buffer.
pub(crate) fn parse_addr_dump(buf: &[u8]) -> AddrDumpChunk {
    let mut chunk = AddrDumpChunk {
        rows: Vec::new(),
        ended: false,
        error: None,
    };
    let mut offset = 0;
    while offset + 16 <= buf.len() {
        let Ok(len_bytes) = buf[offset..offset + 4].try_into() else {
            break;
        };
        let len = u32::from_ne_bytes(len_bytes) as usize;
        if len < 16 || offset + len > buf.len() {
            break;
        }
        let Ok(msg_type) = buf[offset + 4..offset + 6].try_into() else {
            break;
        };
        let msg_type = u16::from_ne_bytes(msg_type);
        let payload = &buf[offset + 16..offset + len];
        match msg_type {
            RTM_NEWADDR if payload.len() >= 8 => {
                let ifindex = u32::from_ne_bytes(payload[4..8].try_into().unwrap_or([0; 4]));
                if payload[0] == AF_INET {
                    let (local, address) = walk_addr_attrs(&payload[8..]);
                    if let Some(octets) = local.or(address) {
                        chunk.rows.push((ifindex, octets));
                    }
                }
            }
            NLMSG_DONE => {
                chunk.ended = true;
                break;
            }
            NLMSG_ERROR if payload.len() >= 4 => {
                let code = i32::from_ne_bytes(payload[0..4].try_into().unwrap_or([0; 4]));
                if code != 0 {
                    chunk.error = Some(code);
                    break;
                }
            }
            _ => {}
        }
        // NLMSG_ALIGN: netlink strides every header to 4 bytes.
        offset += (len + 3) & !3;
    }
    chunk
}

/// The address attributes' walk: IFA_LOCAL is the host's own
/// address (equal to IFA_ADDRESS on normal interfaces, the local
/// endpoint on point-to-point links), so it wins when present;
/// IFA_ADDRESS is the fallback. One pass, first occurrence kept -
/// the kernel writes each attribute once per message.
fn walk_addr_attrs(attrs: &[u8]) -> (Option<[u8; 4]>, Option<[u8; 4]>) {
    let mut local = None;
    let mut address = None;
    let mut offset = 0;
    while offset + 4 <= attrs.len() {
        let len =
            u16::from_ne_bytes(attrs[offset..offset + 2].try_into().unwrap_or([0; 2])) as usize;
        if len < 4 || offset + len > attrs.len() {
            break;
        }
        let rta_type =
            u16::from_ne_bytes(attrs[offset + 2..offset + 4].try_into().unwrap_or([0; 2]));
        if len >= 8 {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&attrs[offset + 4..offset + 8]);
            match rta_type {
                IFA_LOCAL if local.is_none() => local = Some(octets),
                IFA_ADDRESS if address.is_none() => address = Some(octets),
                _ => {}
            }
        }
        // RTA_ALIGN: attributes stride to 4 bytes like messages.
        offset += (len + 3) & !3;
    }
    (local, address)
}

/// The RTM_GETADDR dump request: one nlmsghdr (16 bytes) plus one
/// ifaddrmsg (8 bytes), no attributes - family AF_INET, every
/// interface, the kernel filters what it returns. Seq and pid stay
/// zero: the reply rides the bound socket, and a dump's parts carry
/// the request's own seq so no client-side matching is needed.
fn build_request() -> [u8; 24] {
    let mut req = [0u8; 24];
    req[0..4].copy_from_slice(&24u32.to_ne_bytes());
    req[4..6].copy_from_slice(&RTM_GETADDR.to_ne_bytes());
    req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH).to_ne_bytes());
    req[16] = AF_INET;
    req
}

/// The whole-scan address table: one dump, keyed by ifindex, the
/// addresses formatted as dotted quads. Empty on any refusal - the
/// interfaces then render no IPv4 rows, the named absence, never a
/// guess. Both the socket fd's lifetime and the recv cap are owned
/// here: the fd closes on every path (the guard's Drop), and the
/// loop refuses to chase an endless dump past 64 packets.
pub(crate) fn read_addr_table() -> HashMap<u32, Vec<String>> {
    let mut table: HashMap<u32, Vec<String>> = HashMap::new();
    let Some(socket) = SocketGuard::new() else {
        return table;
    };
    if !socket.send_request(&build_request()) {
        return table;
    }
    let mut buf = [0u8; 8192];
    // 64 packets is a dump of a few thousand addresses - a host
    // would have to carry more interfaces than the kernel's own
    // ifindex space allows before this cap cuts a healthy dump.
    for _ in 0..64 {
        let Some(n) = socket.recv(&mut buf) else {
            break;
        };
        let chunk = parse_addr_dump(&buf[..n]);
        for (ifindex, octets) in chunk.rows {
            let dotted = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
            let rows = table.entry(ifindex).or_default();
            if !rows.contains(&dotted) {
                rows.push(dotted);
            }
        }
        if chunk.error.is_some() {
            table.clear();
            return table;
        }
        if chunk.ended {
            break;
        }
    }
    table
}

/// The netlink socket's lifetime: opens AF_NETLINK/SOCK_RAW on
/// NETLINK_ROUTE with CLOEXEC, binds the kernel-assigned pid, and
/// sets a 1-second receive timeout so a dump that never sends its
/// NLMSG_DONE cannot hang the scan. Drop closes the fd on every
/// path - no leaked descriptor outlives the table it served.
struct SocketGuard {
    fd: i32,
}

impl SocketGuard {
    fn new() -> Option<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return None;
        }
        let guard = SocketGuard { fd };
        // zeroed() seeds the padding field libc's newer sockaddr_nl
        // carries (Padding<u16>) and the zero pid the kernel
        // requires; the family is the one field that carries a law.
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as u16;
        let bound = unsafe {
            libc::bind(
                fd,
                &kernel as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if bound < 0 {
            return None;
        }
        // One second: enough for a full-table dump on a loaded
        // host, short enough that a wedged netlink lane cannot hold
        // the scan hostage.
        let timeout = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        let timed = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const libc::timeval as *const std::ffi::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            )
        };
        if timed < 0 {
            return None;
        }
        Some(guard)
    }

    /// Send the dump request to the kernel (pid 0): false on any
    /// send refusal or short write.
    fn send_request(&self, request: &[u8; 24]) -> bool {
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as u16;
        let sent = unsafe {
            libc::sendto(
                self.fd,
                request.as_ptr() as *const std::ffi::c_void,
                request.len(),
                0,
                &kernel as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        sent == request.len() as isize
    }

    /// One receive: None on a refusal (a timeout yields EAGAIN,
    /// the honest stop for a dump that will not end) or a
    /// non-positive length.
    fn recv(&self, buf: &mut [u8]) -> Option<usize> {
        let n = unsafe {
            libc::recv(
                self.fd,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                buf.len(),
                0,
            )
        };
        if n > 0 { Some(n as usize) } else { None }
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[cfg(test)]
#[path = "../../../test/commands/net_addr_tests.rs"]
mod tests;
