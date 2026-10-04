//! The parsed Abstract Syntax Tree (AST) for a pcap-filter expression.
//!
//! Every node carries a [`Offset`] back into the source text, so a [`crate::CompileError`] raised anywhere downstream can point at the exact text responsible.

use crate::error::Offset;
use alloc::boxed::Box;

/// A boolean expression over [`Primitive`]s and [`EtherPrimitive`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Expr {
    Primitive(Primitive),
    Ether(EtherPrimitive),
    Not(Box<Expr>, Offset),
    And(Box<Expr>, Box<Expr>, Offset),
    Or(Box<Expr>, Box<Expr>, Offset),
}

/// One `[proto] [dir] type value` primitive, as written - before default expansion. `proto`/`dir` are `None` exactly when the user left them out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Primitive {
    pub proto: Option<ProtoTag>,
    pub dir: Option<DirTag>,
    pub ty: PrimType,
    pub offset: Offset,
}

/// A `proto` keyword the parser accepts as *typed* input.
///
/// This is deliberately smaller than the set of protocols codegen.rs (future component) would deals with: `rarp` and `sctp` are
/// real protocols in this crate's model, but libpcap only ever reaches them via default expansion
/// (bare `host` implies `ip or arp or rarp`; bare `port` implies `tcp or udp or sctp`) - a user
/// cannot type `rarp host 1.2.3.4` or `sctp port 80` directly in the MVP grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtoTag {
    Ip,
    Ip6,
    Arp,
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirTag {
    Src,
    Dst,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PrimType {
    Host(AddrLit),
    /// The prefix length, if the literal had an explicit `/n`. `None` means "no explicit prefix was written".
    Net(AddrLit, Option<u8>),
    Port(u16),
    PortRange(u16, u16),
}

/// An address literal.
///
/// Both variants hold the address in network (big-endian) bit order as one integer, so the top bits are the network prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AddrLit {
    V4(u32),
    V6(u128),
}

/// A `ether host <mac>` / `ether [src|dst] [host] <mac>` / `ether proto <name-or-number>` /
/// `ether broadcast`/`broadcast` / `ether multicast`/`multicast` primitive.
///
/// Deliberately not a [`Primitive`]: none of these ever take a `proto` qualifier (there's no
/// encapsulating protocol to name - a MAC address means the same thing whatever's inside the
/// frame), and there's no default-expansion over alternate protocols the way bare `host`/`port`
/// get in `desugar.rs` - a leaf here is already fully resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EtherPrimitive {
    pub kind: EtherKind,
    pub offset: Offset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EtherKind {
    /// `ether host`/`ether src [host]`/`ether dst [host]`. `None` means "src or dst"
    /// (bidirectional, dst checked first - matching libpcap's own generated code).
    Host(MacAddr, Option<DirTag>),
    /// `ether proto <name-or-number>`: true iff the frame's ethertype equals this value.
    Proto(u16),
    /// `ether broadcast`/bare `broadcast`: the destination MAC is the all-ones broadcast address.
    Broadcast,
    /// `ether multicast`/bare `multicast`: the destination MAC's multicast bit (the low bit of its
    /// first byte) is set. Note this also matches the broadcast address, same as real libpcap's
    /// own generated code (verified against `tcpdump -d 'multicast'`) - it does not exclude it.
    Multicast,
}

/// A 6-byte Ethernet hardware address, in the order it appears on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MacAddr(pub [u8; 6]);
