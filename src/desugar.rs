//! Desugaring user input e.g. "host 1.2.3.4" to `canonical` form "(ip or arp or rarp) and (src or dst) host 1.2.3.4".
//!
//! Default expansion: turns a parsed [`Primitive`] (with any of `proto`/`dir` possibly missing) into
//! an [`ExpandedExpr`] with concrete protocol and direction, so it matching libpcap's
//! own defaulting rules, e.g.:
//!
//! - No `proto`: `host`/`net` default to `ip or arp or rarp`; `port`/`portrange` default to
//!   `tcp or udp or sctp`.
//! - No `dir`: defaults to `src or dst`.
//!
//! `Not`/`And`/`Or` nodes pass through structurally unchanged - only `Primitive` leaves expand.

use crate::ast::{DirTag, Expr, PrimType, Primitive, ProtoTag};
use crate::error::Offset;

/// The full protocol set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompiledProto {
    Ip,
    Ip6,
    Arp,
    Rarp,
    Tcp,
    Udp,
    Icmp,
    Sctp,
}

impl From<ProtoTag> for CompiledProto {
    fn from(p: ProtoTag) -> Self {
        match p {
            ProtoTag::Ip => CompiledProto::Ip,
            ProtoTag::Ip6 => CompiledProto::Ip6,
            ProtoTag::Arp => CompiledProto::Arp,
            ProtoTag::Tcp => CompiledProto::Tcp,
            ProtoTag::Udp => CompiledProto::Udp,
            ProtoTag::Icmp => CompiledProto::Icmp,
        }
    }
}

/// A primitive with proto/dir fully resolved
#[derive(Debug, Clone)]
pub(crate) struct CompiledPrimitive {
    pub proto: CompiledProto,
    pub dir: DirTag,
    pub ty: PrimType,
    pub offset: Offset,
}

#[derive(Debug, Clone)]
pub(crate) enum ExpandedExpr {
    Leaf(CompiledPrimitive),
    Not(Box<ExpandedExpr>),
    And(Box<ExpandedExpr>, Box<ExpandedExpr>),
    Or(Box<ExpandedExpr>, Box<ExpandedExpr>),
}

pub(crate) fn expand(expr: &Expr) -> ExpandedExpr {
    match expr {
        Expr::Primitive(p) => expand_primitive(p),
        Expr::Not(inner, _) => ExpandedExpr::Not(Box::new(expand(inner))),
        Expr::And(l, r, _) => ExpandedExpr::And(Box::new(expand(l)), Box::new(expand(r))),
        Expr::Or(l, r, _) => ExpandedExpr::Or(Box::new(expand(l)), Box::new(expand(r))),
    }
}

fn expand_primitive(p: &Primitive) -> ExpandedExpr {
    let protos: Vec<CompiledProto> = match p.proto {
        Some(proto) => vec![CompiledProto::from(proto)],
        None => match p.ty {
            PrimType::Host(_) | PrimType::Net(_, _) => {
                vec![CompiledProto::Ip, CompiledProto::Arp, CompiledProto::Rarp]
            }
            PrimType::Port(_) | PrimType::PortRange(_, _) => {
                vec![CompiledProto::Tcp, CompiledProto::Udp, CompiledProto::Sctp]
            }
        },
    };
    let dirs: [DirTag; 2] = [DirTag::Src, DirTag::Dst];
    let dirs: &[DirTag] = match p.dir {
        Some(ref d) => core::slice::from_ref(d),
        None => &dirs,
    };

    let mut leaves = Vec::with_capacity(protos.len() * dirs.len());
    for &proto in &protos {
        for &dir in dirs {
            leaves.push(ExpandedExpr::Leaf(CompiledPrimitive {
                proto,
                dir,
                ty: p.ty.clone(),
                offset: p.offset.clone(),
            }));
        }
    }
    or_reduce(leaves)
}

fn or_reduce(leaves: Vec<ExpandedExpr>) -> ExpandedExpr {
    let mut iter = leaves.into_iter();
    // Non-empty by construction: `protos` and `dirs` in `expand_primitive` are never empty, so there's always at least one leaf.
    let mut acc = iter
        .next()
        .expect("expand_primitive always produces at least one leaf");
    for leaf in iter {
        acc = ExpandedExpr::Or(Box::new(acc), Box::new(leaf));
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::AddrLit;

    /// Renders an `ExpandedExpr` compactly for test assertions - spans aren't compared (a leaf's
    /// offset always equals the source `Primitive`'s offset at this stage, so comparing it adds nothing
    /// but noise to a hand-written expected string).
    fn render(e: &ExpandedExpr) -> String {
        match e {
            ExpandedExpr::Leaf(p) => {
                let proto = match p.proto {
                    CompiledProto::Ip => "ip",
                    CompiledProto::Ip6 => "ip6",
                    CompiledProto::Arp => "arp",
                    CompiledProto::Rarp => "rarp",
                    CompiledProto::Tcp => "tcp",
                    CompiledProto::Udp => "udp",
                    CompiledProto::Icmp => "icmp",
                    CompiledProto::Sctp => "sctp",
                };
                let dir = match p.dir {
                    DirTag::Src => "src",
                    DirTag::Dst => "dst",
                };
                let ty = match &p.ty {
                    PrimType::Host(AddrLit::V4(a)) => format!("host={a:#x}"),
                    PrimType::Host(AddrLit::V6) => String::from("host=v6"),
                    PrimType::Net(AddrLit::V4(a), pfx) => format!("net={a:#x}/{pfx:?}"),
                    PrimType::Net(AddrLit::V6, _) => String::from("net=v6"),
                    PrimType::Port(n) => format!("port={n}"),
                    PrimType::PortRange(lo, hi) => format!("portrange={lo}-{hi}"),
                };
                format!("{proto}&{dir} {ty}")
            }
            ExpandedExpr::Not(inner) => format!("!{}", render(inner)),
            ExpandedExpr::And(l, r) => format!("({} & {})", render(l), render(r)),
            ExpandedExpr::Or(l, r) => format!("({} | {})", render(l), render(r)),
        }
    }

    fn expand_src(src: &str) -> String {
        let tokens = crate::lexer::lex(src).unwrap();
        let ast = crate::parser::parse(&tokens).unwrap();
        render(&expand(&ast))
    }

    #[test]
    fn proto_and_dir_both_given_expands_to_nothing() {
        assert_eq!(expand_src("tcp src port 80"), "tcp&src port=80");
    }

    #[test]
    fn proto_given_dir_missing_expands_to_dir_or() {
        // This is the canonical "tcp port 80" shape: a single OR over dir, proto held fixed - the
        // one case `codegen.rs` can special-case to a shared prefix (see the module doc comment
        // above).
        assert_eq!(
            expand_src("tcp port 80"),
            "(tcp&src port=80 | tcp&dst port=80)"
        );
    }

    #[test]
    fn dir_given_proto_missing_host_expands_to_ip_arp_rarp() {
        assert_eq!(
            expand_src("src host 1.2.3.4"),
            "((ip&src host=0x1020304 | arp&src host=0x1020304) | rarp&src host=0x1020304)"
        );
    }

    #[test]
    fn dir_given_proto_missing_port_expands_to_tcp_udp_sctp() {
        assert_eq!(
            expand_src("src port 80"),
            "((tcp&src port=80 | udp&src port=80) | sctp&src port=80)"
        );
    }

    #[test]
    fn both_missing_is_the_full_cartesian_product() {
        let rendered = expand_src("host 1.2.3.4");
        // 3 protos x 2 dirs = 6 leaves, folded left-to-right.
        assert_eq!(rendered.matches("host=0x1020304").count(), 6);
        assert!(rendered.starts_with("(((((ip&src"));
    }

    #[test]
    fn not_and_or_pass_through_structurally() {
        assert_eq!(
            expand_src("tcp src port 80 and not udp dst port 53"),
            "(tcp&src port=80 & !udp&dst port=53)"
        );
    }
}
