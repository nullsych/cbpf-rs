//! The parsed Abstract Syntax Tree (AST) for a pcap-filter expression.
//!
//! Every node carries a [`Offset`] back into the source text, so a [`crate::CompileError`] raised anywhere downstream can point at the exact text responsible.

use crate::error::Offset;

/// A boolean expression over [`Primitive`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Expr {
    Primitive(Primitive),
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
/// Note: IPv6 text is recognized (so `ip6 host ::1` parses) but isn't implemented in this MVP yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AddrLit {
    V4(u32),
    V6,
}
