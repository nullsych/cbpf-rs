//! Black-box tests of the public `compile()` entry point.
//!
//! The crate's own canonical example: `tcp port 80` over Ethernet. Proto is
//! given explicitly, so only `dir` expands, and codegen shares the whole
//! ethertype/proto/fragment/IHL prefix between the src- and dst-port
//! checks instead of compiling them as two fully independent branches (see
//! `codegen.rs`'s `compile_dir_pair`).
//!
//! This pins `cbpf-rs`'s own output shape, not a claim of byte-parity with
//! `tcpdump -d`: `tests/differential.rs` found that real libpcap compiles
//! `tcp`/`udp`/`icmp`/`port` primitives into code that *also* checks IPv6
//! packets, via an entire parallel ethertype-0x86dd branch, even when a
//! filter like this one never mentions IPv6. `cbpf-rs`'s MVP is
//! deliberately IPv4-only for these primitives (see `codegen.rs`'s module
//! doc comment), so its `Display` output is smaller than - and never
//! identical to - `tcpdump -d`'s. `tests/differential.rs` is what actually
//! checks this crate against a live tcpdump, by comparing accept/reject
//! decisions on real IPv4 packets rather than disassembly text.
//!

use cbpf_rs::{ErrorTag, KEEP_WHOLE_PACKET, LinkType, compile};

/// Test: if `tcp port 80`` matches itself.
#[test]
fn tcp_port_80_simple() {
    let program: cbpf_rs::Program =
        compile("tcp port 80", LinkType::Ethernet, KEEP_WHOLE_PACKET).unwrap();
    let rendered = program.to_string();
    let expected = "\
(000) ldh      [12]
(001) jeq      #0x800           jt 2\tjf 12
(002) ldb      [23]
(003) jeq      #0x6             jt 4\tjf 12
(004) ldh      [20]
(005) jset     #0x1fff          jt 12\tjf 6
(006) ldxb     4*([14]&0xf)
(007) ldh      [x + 14]
(008) jeq      #0x50            jt 11\tjf 9
(009) ldh      [x + 16]
(010) jeq      #0x50            jt 11\tjf 12
(011) ret      #0xffffffff
(012) ret      #0x0";
    assert_eq!(rendered, expected);
}

/// Test: if `tcp port 80`` has bidirectional matches.
#[test]
fn tcp_port_80_bidir() {
    let program = compile("tcp port 80", LinkType::Ethernet, KEEP_WHOLE_PACKET).unwrap();

    let mut packet = vec![0u8; 40];
    packet[12] = 0x08;
    packet[13] = 0x00; // ethertype IP
    packet[14] = 0x45; // IHL = 5
    packet[23] = 6; // proto TCP
    packet[20] = 0x00;
    packet[21] = 0x00; // not a fragment
    packet[34] = 0x00;
    packet[35] = 80; // src port 80
    packet[36] = 0x00;
    packet[37] = 1; // dst port 1
    assert!(program.matches(&packet), "src port 80 should match");

    packet[35] = 2; // src port 2
    packet[37] = 80; // dst port 80
    assert!(program.matches(&packet), "dst port 80 should match");

    packet[37] = 81; // neither port is 80
    assert!(!program.matches(&packet), "no port 80 should not match");
}

#[test]
fn fragmented_packets_never_match_a_port_primitive() {
    let program = compile("udp port 53", LinkType::Ethernet, KEEP_WHOLE_PACKET).unwrap();

    let mut packet = vec![0u8; 40];
    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[14] = 0x45;
    packet[23] = 17; // UDP

    // The 16-bit flags & fragoffset field: byte[20] bits 5-7 are reserved/DF/MF flags, not part of the offset.
    // The 13-bit fragment offset itself is byte[20] bits 0-4 plus all of byte[21] - set byte[21] nonzero so this
    // is unambiguously a non-first fragment, not just a "more fragments follow" first fragment (which would still carry ports).
    packet[20] = 0x00;
    packet[21] = 0x20;
    packet[34] = 0x00;
    packet[35] = 53;

    assert!(
        !program.matches(&packet),
        "a non-first fragment must never match a port check"
    );
}

#[test]
fn ip_host_matches_src_or_dst_by_default() {
    let program = compile("ip host 10.0.0.1", LinkType::Ethernet, KEEP_WHOLE_PACKET).unwrap();

    let mut packet = vec![0u8; 34];
    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[14] = 0x45;
    packet[26..30].copy_from_slice(&[10, 0, 0, 1]);
    assert!(program.matches(&packet), "as src address");

    packet[26..30].copy_from_slice(&[0, 0, 0, 0]);
    packet[30..34].copy_from_slice(&[10, 0, 0, 1]);
    assert!(program.matches(&packet), "as dst address");

    packet[30..34].copy_from_slice(&[9, 9, 9, 9]);
    assert!(!program.matches(&packet));
}

#[test]
fn net_prefix_masks_the_address() {
    let program = compile("net 10.0.0.0/8", LinkType::Ethernet, KEEP_WHOLE_PACKET).unwrap();

    let mut packet = vec![0u8; 34];
    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[26..30].copy_from_slice(&[10, 250, 1, 2]); // within 10.0.0.0/8
    assert!(program.matches(&packet));

    packet[26..30].copy_from_slice(&[11, 0, 0, 1]); // outside the /8
    assert!(!program.matches(&packet));
}

#[test]
fn boolean_connectives_and_parens() {
    let program = compile(
        "(tcp port 80 or tcp port 443) and not net 10.0.0.0/8",
        LinkType::Ethernet,
        KEEP_WHOLE_PACKET,
    )
    .unwrap();

    let mut packet = vec![0u8; 40];
    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[14] = 0x45;
    packet[23] = 6;
    packet[26..30].copy_from_slice(&[192, 168, 1, 1]); // not in 10.0.0.0/8
    packet[34] = 0x00;
    packet[35] = 80;
    packet[36..38].copy_from_slice(&12345u16.to_be_bytes());
    assert!(program.matches(&packet));

    packet[26..30].copy_from_slice(&[10, 1, 2, 3]); // now inside 10.0.0.0/8 -> excluded
    assert!(!program.matches(&packet));
}

#[test]
fn portrange_accepts_the_inclusive_bounds_and_rejects_outside() {
    let program = compile("portrange 8000-8008", LinkType::Ethernet, KEEP_WHOLE_PACKET).unwrap();

    let mut packet = vec![0u8; 40];
    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[14] = 0x45;
    packet[23] = 6; // tcp (one of the default-expanded protos)
    packet[20] = 0;
    packet[21] = 0;

    for port in [8000u16, 8004, 8008] {
        let bytes = port.to_be_bytes();
        packet[34] = bytes[0];
        packet[35] = bytes[1];
        packet[36] = 0;
        packet[37] = 1;
        assert!(program.matches(&packet), "port {port} should be in range");
    }

    let bytes = 7999u16.to_be_bytes();
    packet[34] = bytes[0];
    packet[35] = bytes[1];
    let bytes = 1u16.to_be_bytes();
    packet[36] = bytes[0];
    packet[37] = bytes[1];
    assert!(
        !program.matches(&packet),
        "7999 is outside 8000-8008 and dst port 1 shouldn't match either"
    );
}

#[test]
fn unbalanced_parens_report_an_error() {
    let err = compile("(tcp port 80", LinkType::Ethernet, KEEP_WHOLE_PACKET).unwrap_err();
    assert_eq!(err.tag, ErrorTag::UnbalancedParens);
}

#[test]
fn invalid_ipv4_literal_reports_a_offset() {
    let src = "host 999.1.1.1";
    let err = compile(src, LinkType::Ethernet, KEEP_WHOLE_PACKET).unwrap_err();
    assert!(matches!(err.tag, ErrorTag::InvalidIPv4Literal(ref t) if t == "999.1.1.1"));
    assert_eq!(&src[err.offset], "999.1.1.1");
}

#[test]
fn port_on_a_non_transport_protocol_is_rejected() {
    let err = compile("arp port 80", LinkType::Ethernet, KEEP_WHOLE_PACKET).unwrap_err();
    assert!(matches!(err.tag, ErrorTag::InvalidPrimitiveCombination(_)));
}

/// A bare `net <ipv6>/33` (no `ip6`, no `dir`) is read as `ip6 src or dst`. The /33 prefix ends one bit into the second 32-bit
/// word, so this exercises both a whole-word compare and a partially masked one.
#[test]
fn ipv6_net_matches_the_prefix() {
    let program = compile("net 2001:db8::/33", LinkType::Ethernet, KEEP_WHOLE_PACKET).unwrap();

    let mut packet = vec![0u8; 54];
    packet[12] = 0x86;
    packet[13] = 0xdd; // ethertype IPv6
    // IPv6 header starts at 14; src address at 14 + 8, dst at 14 + 24.
    let inside = [
        0x20, 0x01, 0x0d, 0xb8, 0x7f, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];
    let outside = [
        0x20, 0x01, 0x0d, 0xb8, 0x80, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];

    packet[22..38].copy_from_slice(&inside);
    packet[38..54].copy_from_slice(&outside);
    assert!(
        program.matches(&packet),
        "src inside the prefix should match"
    );

    packet[22..38].copy_from_slice(&outside);
    packet[38..54].copy_from_slice(&inside);
    assert!(
        program.matches(&packet),
        "dst inside the prefix should match"
    );

    packet[38..54].copy_from_slice(&outside);
    assert!(
        !program.matches(&packet),
        "neither address inside the prefix"
    );

    // The same bytes with an IPv4 ethertype must not match: the ethertype gate is what tells IPv6 apart.
    packet[22..38].copy_from_slice(&inside);
    packet[12] = 0x08;
    packet[13] = 0x00;
    assert!(!program.matches(&packet));
}

/// Linux cooked capture (`any` interface): a 16-byte header with the protocol type at byte 14, so every IPv4/TCP offset is
/// 2 bytes further than on Ethernet.
#[test]
fn linux_sll_tcp_port_80() {
    let program = compile("tcp port 80", LinkType::LinuxSll, KEEP_WHOLE_PACKET).unwrap();

    let mut packet = vec![0u8; 42];
    packet[14] = 0x08;
    packet[15] = 0x00; // protocol type IP
    packet[16] = 0x45; // IHL = 5
    packet[25] = 6; // proto TCP
    packet[36] = 0x00;
    packet[37] = 80; // src port 80
    packet[38] = 0x00;
    packet[39] = 1; // dst port 1
    assert!(program.matches(&packet), "src port 80 should match");

    packet[37] = 2;
    packet[39] = 80;
    assert!(program.matches(&packet), "dst port 80 should match");

    packet[39] = 81;
    assert!(!program.matches(&packet), "no port 80 should not match");

    // The same bytes read as Ethernet must not match: the ethertype is not where Ethernet expects it.
    let ethernet = compile("tcp port 80", LinkType::Ethernet, KEEP_WHOLE_PACKET).unwrap();
    packet[39] = 80;
    assert!(!ethernet.matches(&packet));
}

#[test]
fn linux_sll_host_matches_the_address() {
    let program = compile(
        "ip src host 10.0.0.1",
        LinkType::LinuxSll,
        KEEP_WHOLE_PACKET,
    )
    .unwrap();

    let mut packet = vec![0u8; 36];
    packet[14] = 0x08;
    packet[15] = 0x00;
    packet[28..32].copy_from_slice(&[10, 0, 0, 1]); // ip_base 16 + src offset 12
    assert!(program.matches(&packet));

    packet[31] = 2;
    assert!(!program.matches(&packet));
}

/// Raw has no link-layer header: the IPv4 header is at byte 0, and (until IPv6 exists) every packet is taken to be IPv4.
#[test]
fn raw_tcp_port_80() {
    let program = compile("tcp port 80", LinkType::Raw, KEEP_WHOLE_PACKET).unwrap();

    let mut packet = vec![0u8; 28];
    packet[0] = 0x45; // IPv4, IHL = 5
    packet[9] = 6; // proto TCP
    packet[20] = 0x00;
    packet[21] = 80; // src port 80
    packet[22] = 0x00;
    packet[23] = 1; // dst port 1
    assert!(program.matches(&packet), "src port 80 should match");

    packet[21] = 2;
    packet[23] = 80;
    assert!(program.matches(&packet), "dst port 80 should match");

    packet[23] = 81;
    assert!(!program.matches(&packet), "no port 80 should not match");
}

#[test]
fn raw_host_matches_the_address() {
    let program = compile("ip dst host 10.0.0.1", LinkType::Raw, KEEP_WHOLE_PACKET).unwrap();

    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[16..20].copy_from_slice(&[10, 0, 0, 1]); // dst address
    assert!(program.matches(&packet));

    packet[19] = 2;
    assert!(!program.matches(&packet));
}

/// `arp` is identified by its ethertype, which a Raw link layer doesn't have.
#[test]
fn arp_is_rejected_on_raw() {
    let err = compile("arp host 10.0.0.1", LinkType::Raw, KEEP_WHOLE_PACKET).unwrap_err();
    assert!(matches!(err.tag, ErrorTag::InvalidPrimitiveCombination(_)));
}

/// A deliberately huge OR chain to exercise the jt/jf displacement-overflow path end to end, through the public API.
#[test]
fn a_sufficiently_large_or_chain_overflows_jump_displacement() {
    let filter = (0..200)
        .map(|i| format!("port {}", 1000 + i))
        .collect::<Vec<_>>()
        .join(" or ");
    let err = compile(&filter, LinkType::Ethernet, KEEP_WHOLE_PACKET).unwrap_err();
    assert!(matches!(err.tag, ErrorTag::JumpDisplacementOverflow { .. }));
}
