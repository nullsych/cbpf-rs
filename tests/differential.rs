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
