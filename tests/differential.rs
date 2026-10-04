//! Differential testing against a real `tcpdump`.
//!
//! This compares *semantics*, not `tcpdump -d` disassembly text!
//!
//! Current implementation is IPv4-only for these primitives (see `codegen.rs`'s module doc comment), so its `Display`
//! output is never byte-identical to `tcpdump -d`'s.
//!
//! But when running `tcpdump` with modern libpcap (I've verified it against tcpdump 4.99.6 & libpcap 1.10.6) compiles
//! `tcp`/`udp`/`icmp`/`port` primitives into code that checks IPv6 packets, - an entire parallel ethertype-0x86dd branch,
//! even when the filter never mentions IPv6.
//!
//! So note that `cbpf-rs`'s `Display` output is never byte-identical to `tcpdump -d`'s.
//!
//! But doesn't need to be: for any actual IPv4 packet, tcpdump's IPv6 branch never fires, so comparing accept/reject decisions
//! on IPv4 packets is exactly the right level to hold `cbpf-rs` accountable at for what it currently claims to support.
//!
//! `tcpdump -r <file> -n <filter>` doesn't need capture permissions the way reading a live interface does, so packets are shipped
//! to it via a scratch one-packet `.pcap` file instead.

use cbpf_rs::{KEEP_WHOLE_PACKET, LinkType, compile};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn tcpdump_available() -> bool {
    Command::new("tcpdump")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn pcap_with_one_packet(packet: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24 + 16 + packet.len());
    buf.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes()); // magic
    buf.extend_from_slice(&2u16.to_le_bytes()); // version_major
    buf.extend_from_slice(&4u16.to_le_bytes()); // version_minor
    buf.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    buf.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    buf.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    buf.extend_from_slice(&1u32.to_le_bytes()); // linktype: LINKTYPE_ETHERNET

    buf.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
    buf.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
    buf.extend_from_slice(&(packet.len() as u32).to_le_bytes()); // incl_len
    buf.extend_from_slice(&(packet.len() as u32).to_le_bytes()); // orig_len
    buf.extend_from_slice(packet);
    buf
}

/// `Some(true)`/`Some(false)`: tcpdump ran and printed (or didn't print) a summary line for the packet.
///
/// `None`: tcpdump itself failed (unrelated to whether the packet matches - e.g. this environment's tcpdump rejected the filter syntax).
fn tcpdump_matches(filter: &str, packet: &[u8]) -> Option<bool> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    // Tests in this binary run concurrently; a filename shared across them would race two `tcpdump` invocations against the same file.
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "cbpf-rs-differential-{}-{unique}.pcap",
        std::process::id()
    ));
    std::fs::write(&path, pcap_with_one_packet(packet)).expect("failed to write scratch pcap file");
    let output = Command::new("tcpdump")
        .arg("-r")
        .arg(&path)
        .arg("-n")
        .arg(filter)
        .output()
        .ok();
    let _ = std::fs::remove_file(&path);
    let output = output?;
    if !output.status.success() {
        return None;
    }
    Some(!String::from_utf8_lossy(&output.stdout).trim().is_empty())
}

fn assert_agrees(filter: &str, packet: &[u8], label: &str) {
    if !tcpdump_available() {
        eprintln!("tcpdump not found on PATH; skipping differential test");
        return;
    }
    let Some(theirs) = tcpdump_matches(filter, packet) else {
        eprintln!("skipping '{filter}' / {label}: tcpdump couldn't run it in this environment");
        return;
    };
    let program = compile(filter, LinkType::Ethernet, KEEP_WHOLE_PACKET)
        .unwrap_or_else(|e| panic!("cbpf-rs failed to compile '{filter}': {e}"));
    let ours = program.matches(packet);
    assert_eq!(
        ours, theirs,
        "cbpf-rs and tcpdump disagree on '{filter}' for packet '{label}': cbpf-rs={ours} tcpdump={theirs}"
    );
}

/// A minimal Ethernet + IPv4 + TCP/UDP packet.
struct Pkt(Vec<u8>);

impl Pkt {
    fn new(ip_proto: u8) -> Self {
        let mut b = vec![0u8; 40];
        b[12] = 0x08;
        b[13] = 0x00; // ethertype IPv4
        b[14] = 0x45; // version 4, IHL 5 (20-byte header, no options)
        b[23] = ip_proto;
        Pkt(b)
    }

    fn src_addr(mut self, a: [u8; 4]) -> Self {
        self.0[26..30].copy_from_slice(&a);
        self
    }

    fn dst_addr(mut self, a: [u8; 4]) -> Self {
        self.0[30..34].copy_from_slice(&a);
        self
    }

    fn ports(mut self, src: u16, dst: u16) -> Self {
        self.0[34..36].copy_from_slice(&src.to_be_bytes());
        self.0[36..38].copy_from_slice(&dst.to_be_bytes());
        self
    }

    fn fragment_offset(mut self, units_of_8_bytes: u16) -> Self {
        self.0[20..22].copy_from_slice(&units_of_8_bytes.to_be_bytes());
        self
    }
}

/// A minimal Ethernet + IPv6 + UDP packet (the transport header is empty: only the addresses matter to these tests).
struct Pkt6(Vec<u8>);

impl Pkt6 {
    fn new() -> Self {
        let mut b = vec![0u8; 14 + 40 + 8];
        b[12] = 0x86;
        b[13] = 0xdd; // ethertype IPv6
        b[14] = 0x60; // version 6
        b[18..20].copy_from_slice(&8u16.to_be_bytes()); // payload length
        b[20] = UDP; // next header
        b[21] = 64; // hop limit
        Pkt6(b)
    }

    fn src_addr(mut self, a: &str) -> Self {
        self.0[22..38].copy_from_slice(&a.parse::<std::net::Ipv6Addr>().unwrap().octets());
        self
    }

    fn dst_addr(mut self, a: &str) -> Self {
        self.0[38..54].copy_from_slice(&a.parse::<std::net::Ipv6Addr>().unwrap().octets());
        self
    }

    fn next_header(mut self, proto: u8) -> Self {
        self.0[20] = proto;
        self
    }

    fn ports(mut self, src: u16, dst: u16) -> Self {
        self.0[54..56].copy_from_slice(&src.to_be_bytes());
        self.0[56..58].copy_from_slice(&dst.to_be_bytes());
        self
    }
}

const TCP: u8 = 6;
const UDP: u8 = 17;

#[test]
fn port_primitives_agree_with_tcpdump() {
    assert_agrees(
        "tcp port 80",
        &Pkt::new(TCP).ports(80, 4000).0,
        "src port 80",
    );
    assert_agrees(
        "tcp port 80",
        &Pkt::new(TCP).ports(4000, 80).0,
        "dst port 80",
    );
    assert_agrees(
        "tcp port 80",
        &Pkt::new(TCP).ports(4000, 4001).0,
        "neither port 80",
    );
    assert_agrees(
        "udp port 53",
        &Pkt::new(UDP).ports(53, 4000).0,
        "udp src port 53",
    );
    assert_agrees(
        "tcp src port 80",
        &Pkt::new(TCP).ports(4000, 80).0,
        "dst-only 80 shouldn't match src-qualified",
    );
}

#[test]
fn fragmented_packets_agree_with_tcpdump() {
    let pkt = Pkt::new(TCP).ports(80, 4000).fragment_offset(5).0;
    assert_agrees("tcp port 80", &pkt, "non-first fragment");
}

#[test]
fn host_and_net_primitives_agree_with_tcpdump() {
    assert_agrees(
        "ip host 10.0.0.1",
        &Pkt::new(TCP).src_addr([10, 0, 0, 1]).0,
        "as src",
    );
    assert_agrees(
        "ip host 10.0.0.1",
        &Pkt::new(TCP).dst_addr([10, 0, 0, 1]).0,
        "as dst",
    );
    assert_agrees(
        "ip host 10.0.0.1",
        &Pkt::new(TCP).src_addr([9, 9, 9, 9]).0,
        "no match",
    );
    assert_agrees(
        "net 10.0.0.0/8",
        &Pkt::new(TCP).src_addr([10, 250, 1, 2]).0,
        "inside /8",
    );
    assert_agrees(
        "net 10.0.0.0/8",
        &Pkt::new(TCP).src_addr([11, 0, 0, 1]).0,
        "outside /8",
    );
}

#[test]
fn portrange_agrees_with_tcpdump() {
    assert_agrees(
        "portrange 8000-8008",
        &Pkt::new(TCP).ports(8004, 1).0,
        "inside range",
    );
    assert_agrees(
        "portrange 8000-8008",
        &Pkt::new(TCP).ports(7999, 1).0,
        "just below range",
    );
    assert_agrees(
        "portrange 8000-8008",
        &Pkt::new(TCP).ports(8009, 1).0,
        "just above range",
    );
}

#[test]
fn boolean_connectives_agree_with_tcpdump() {
    let filter = "(tcp port 80 or tcp port 443) and not net 10.0.0.0/8";
    assert_agrees(
        filter,
        &Pkt::new(TCP).src_addr([192, 168, 1, 1]).ports(80, 4000).0,
        "matches",
    );
    assert_agrees(
        filter,
        &Pkt::new(TCP).src_addr([10, 1, 2, 3]).ports(80, 4000).0,
        "excluded by net",
    );
    assert_agrees(
        filter,
        &Pkt::new(TCP).src_addr([192, 168, 1, 1]).ports(22, 4000).0,
        "wrong port",
    );
}

#[test]
fn ipv6_host_agrees_with_tcpdump() {
    let src = Pkt6::new().src_addr("2001:db8::1").dst_addr("fe80::9");
    let dst = Pkt6::new().src_addr("fe80::9").dst_addr("2001:db8::1");
    let other = Pkt6::new().src_addr("2001:db8::2").dst_addr("fe80::9");

    for filter in ["ip6 host 2001:db8::1", "host 2001:db8::1"] {
        assert_agrees(filter, &src.0, "as src");
        assert_agrees(filter, &dst.0, "as dst");
        assert_agrees(filter, &other.0, "no match");
    }
    assert_agrees("ip6 src host 2001:db8::1", &src.0, "src filter, as src");
    assert_agrees("ip6 src host 2001:db8::1", &dst.0, "src filter, as dst");
    assert_agrees("ip6 dst host 2001:db8::1", &dst.0, "dst filter, as dst");
    assert_agrees("ip6 dst host 2001:db8::1", &src.0, "dst filter, as src");
    // The last word differing by a single bit must not match.
    assert_agrees("ip6 host 2001:db8::1", &other.0, "differs in the last bit");
}

#[test]
fn ipv6_net_prefixes_agree_with_tcpdump() {
    let addrs = [
        "2001:db8::1",
        "2001:db8:0:1::1",
        "2001:db8:8000::1",
        "2001:db9::1",
        "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
        "::1",
    ];
    let base = u128::from("2001:db8::".parse::<std::net::Ipv6Addr>().unwrap());
    // Prefix lengths that end on a word boundary, one bit into a word, one bit short of the next, and the extremes.
    for prefix in [0u32, 1, 31, 32, 33, 47, 48, 63, 64, 65, 96, 127, 128] {
        // libpcap rejects a network address with bits set past the prefix ("non-network bits set"), so mask it first.
        let mask = if prefix == 0 {
            0
        } else {
            u128::MAX << (128 - prefix)
        };
        let network = std::net::Ipv6Addr::from(base & mask);
        let filter = format!("ip6 src net {network}/{prefix}");
        for a in addrs {
            assert_agrees(
                &filter,
                &Pkt6::new().src_addr(a).dst_addr("fe80::9").0,
                &format!("src {a}"),
            );
        }
    }
}

#[test]
fn ipv6_filters_never_match_ipv4_packets_and_vice_versa() {
    let v4 = Pkt::new(UDP).src_addr([10, 0, 0, 1]);
    let v6 = Pkt6::new().src_addr("::ffff:10.0.0.1");
    assert_agrees("ip6 host ::ffff:10.0.0.1", &v4.0, "IPv4 packet, ip6 filter");
    assert_agrees("ip6 host ::ffff:10.0.0.1", &v6.0, "IPv6 mapped address");
    assert_agrees("ip host 10.0.0.1", &v6.0, "IPv6 packet, ip filter");
    assert_agrees("net ::/0", &v4.0, "::/0 on an IPv4 packet");
    assert_agrees("net ::/0", &v6.0, "::/0 on an IPv6 packet");
}

/// The headline "level 2" case: a filter that never mentions IPv6 (`tcp port 80`) must still match IPv6 traffic, the same
/// way real libpcap's generated code does (it compiles a parallel ethertype-0x86dd branch even here).
#[test]
fn tcp_port_80_agrees_with_tcpdump_on_ipv6_packets_too() {
    let matching = Pkt6::new()
        .next_header(TCP)
        .src_addr("2001:db8::1")
        .dst_addr("2001:db8::2")
        .ports(4000, 80);
    assert_agrees("tcp port 80", &matching.0, "IPv6, dst port 80");

    let no_port_match = Pkt6::new()
        .next_header(TCP)
        .src_addr("2001:db8::1")
        .dst_addr("2001:db8::2")
        .ports(4000, 81);
    assert_agrees("tcp port 80", &no_port_match.0, "IPv6, neither port is 80");

    let wrong_proto = Pkt6::new()
        .next_header(UDP)
        .src_addr("2001:db8::1")
        .dst_addr("2001:db8::2")
        .ports(4000, 80);
    assert_agrees("tcp port 80", &wrong_proto.0, "IPv6 UDP, not TCP");
}

/// A minimal frame with just an Ethernet header (14 bytes) and an ethertype - Ether-layer primitives
/// don't look past it, so nothing else needs to be there.
fn eth_frame(src_mac: [u8; 6], dst_mac: [u8; 6], ethertype: u16) -> Vec<u8> {
    let mut f = vec![0u8; 14];
    f[0..6].copy_from_slice(&dst_mac);
    f[6..12].copy_from_slice(&src_mac);
    f[12..14].copy_from_slice(&ethertype.to_be_bytes());
    f
}

#[test]
fn ether_host_agrees_with_tcpdump() {
    let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let other = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

    assert_agrees(
        "ether host aa:bb:cc:dd:ee:ff",
        &eth_frame(mac, other, 0x0800),
        "as src",
    );
    assert_agrees(
        "ether host aa:bb:cc:dd:ee:ff",
        &eth_frame(other, mac, 0x0800),
        "as dst",
    );
    assert_agrees(
        "ether host aa:bb:cc:dd:ee:ff",
        &eth_frame(other, other, 0x0800),
        "neither",
    );
    assert_agrees(
        "ether src aa:bb:cc:dd:ee:ff",
        &eth_frame(other, mac, 0x0800),
        "src filter, mac is dst",
    );
    assert_agrees(
        "ether dst aa:bb:cc:dd:ee:ff",
        &eth_frame(other, mac, 0x0800),
        "dst filter, mac is dst",
    );
}

#[test]
fn broadcast_and_multicast_agree_with_tcpdump() {
    let broadcast_frame = eth_frame([0, 0, 0, 0, 0, 0], [0xff; 6], 0x0800);
    let multicast_frame = eth_frame([0, 0, 0, 0, 0, 0], [0x01, 0, 0, 0, 0, 0], 0x0800);
    let unicast_frame = eth_frame([0, 0, 0, 0, 0, 0], [0x02, 0, 0, 0, 0, 0], 0x0800);

    assert_agrees("broadcast", &broadcast_frame, "broadcast dst");
    assert_agrees(
        "broadcast",
        &multicast_frame,
        "multicast dst, not broadcast",
    );
    assert_agrees("broadcast", &unicast_frame, "unicast dst");

    assert_agrees(
        "multicast",
        &broadcast_frame,
        "broadcast dst (multicast bit is also set)",
    );
    assert_agrees("multicast", &multicast_frame, "multicast dst");
    assert_agrees("multicast", &unicast_frame, "unicast dst");
}

#[test]
fn ether_proto_agrees_with_tcpdump() {
    for (name, ethertype) in [
        ("ip", 0x0800u16),
        ("ip6", 0x86dd),
        ("arp", 0x0806),
        ("rarp", 0x8035),
    ] {
        let filter = format!("ether proto {name}");
        assert_agrees(
            &filter,
            &eth_frame([0; 6], [0; 6], ethertype),
            &format!("{name}, matching ethertype"),
        );
        assert_agrees(
            &filter,
            &eth_frame([0; 6], [0; 6], 0x9999),
            &format!("{name}, unrelated ethertype"),
        );
    }
}
