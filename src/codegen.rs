//! Generate cBPF from desugared expression.
//!
//!

use crate::ast::{AddrLit, DirTag, PrimType};
use crate::desugar::{CompiledPrimitive, CompiledProto, ExpandedExpr};
use crate::error::{CompileError, ErrorTag, Offset};
use crate::irep::{IrBuilder, IrOp2, IrProgram, Label};
use crate::linktype::LinkType;

const ETH_TYPE_IP: u32 = 0x0800;
const ETH_TYPE_ARP: u32 = 0x0806;
const ETH_TYPE_RARP: u32 = 0x8035;
const ETH_TYPE_IPV6: u32 = 0x86dd;

const IP_PROTO_ICMP: u32 = 1;
const IP_PROTO_TCP: u32 = 6;
const IP_PROTO_UDP: u32 = 17;
const IP_PROTO_SCTP: u32 = 132;

// IPv4 header field offsets, relative to `ip_base`.
const IP_FLAGS_FRAG_OFFSET: u32 = 6;
const IP_PROTO_OFFSET: u32 = 9;
const IP_SRC_OFFSET: u32 = 12;
const IP_DST_OFFSET: u32 = 16;
/// The 13-bit fragment-offset field, ignoring the 3 reserved/DF/MF bits above it: nonzero means
/// "not the first fragment".
const FRAG_MASK: u32 = 0x1fff;

// IPv6 header field offsets, relative to `ip_base` (fixed 40-byte header: 4 version/class/flow + 2 length + 1 next header +
// 1 hop limit, then the two 16-byte addresses).
const IP6_SRC_OFFSET: u32 = 8;
const IP6_DST_OFFSET: u32 = 24;

// ARP packet field offsets, relative to `ip_base` (standard Ethernet/IPv4 ARP: 2 hw-type +
// 2 proto-type + 1 hw-len + 1 proto-len + 2 opcode = 8, then 6-byte sender hw addr).
const ARP_SENDER_PA_OFFSET: u32 = 14;
const ARP_TARGET_PA_OFFSET: u32 = 24;

// TCP/UDP header offsets, added to `ip_base` (see `emit_port_terminal` for why this - not an offset
// from the TCP header's own start - is correct).
const PORT_SRC_REL: u32 = 0;
const PORT_DST_REL: u32 = 2;

/// Link-layer offsets plus the in-progress instruction stream, threaded through every codegen
/// function. See the module doc comment for why this is a struct rather than a global lookup.
struct Ctx<'a> {
    b: &'a mut IrBuilder,
    ip_base: u32,
    /// Offset of the ethertype field, or `None` for link types without one (Raw), where the packet is assumed to be IPv4.
    eth_field: Option<u32>,
}

/// Control branch for labels.
#[derive(Clone, Copy)]
struct Branch {
    on_true: Label,
    on_false: Label,
}

impl Branch {
    fn swapped(self) -> Branch {
        Branch {
            on_true: self.on_false,
            on_false: self.on_true,
        }
    }
}

/// Generate main cBPF from desugared expression.
/// Note: generate() supports [`LinkType::Ethernet`], [`LinkType::LinuxSll`] and [`LinkType::Raw`].
/// Raw packets have no ethertype field, so they are assumed to be IPv4 and the ethertype gate is skipped
/// (until IPv6 is implemented, there is nothing else they could be).
pub(crate) fn generate(
    expr: &ExpandedExpr,
    link_type: LinkType,
    snaplen: u32,
) -> Result<IrProgram, CompileError> {
    // get base and offset
    let info = link_type.l3_offset_info();

    // prepare intermediate representation
    let mut builder = IrBuilder::new();
    let accept = builder.new_label(); // ret snaplen
    let reject = builder.new_label(); // ret 0
    // encapsulate IR in context to move forward
    let mut ctx = Ctx {
        b: &mut builder,
        ip_base: info.ip_base,
        eth_field: info.ethertype_offset,
    };

    // ? in case of IPv6
    compile_expr(
        expr,
        &mut ctx,
        Branch {
            on_true: accept,
            on_false: reject,
        },
    )?;

    // The expression only referred to `accept`/`reject` by name; now that it is fully emitted, pin
    // them to the two return blocks at the very end of the program.
    //
    // e.g. `ip src host 10.0.0.1`, accept = 4, reject = 5:
    //
    //   0: ldh [12]
    //   1: jeq #0x800,      true -> cont,   false -> reject
    //   2: ld  [26]
    //   3: jeq #0x0a000001, true -> accept, false -> reject
    //   4: ret snaplen      ; accept
    //   5: ret 0            ; reject
    builder.place(accept);
    builder.emit(IrOp2::Ret(snaplen), 0..0);
    builder.place(reject);
    builder.emit(IrOp2::Ret(0), 0..0);

    // `finish()` and the later resolution pass replace the label names with instruction indices:
    //
    //   0: ldh [12]
    //   1: jeq #0x800,      jt 2, jf 5
    //   2: ld  [26]
    //   3: jeq #0x0a000001, jt 4, jf 5
    //   4: ret snaplen
    //   5: ret 0
    Ok(builder.finish())
}

/// Compiles an expression in continuation-passing style: control ends up at `branch.on_true` or `branch.on_false` depending on the result, so `and`/`or`/`not` need no materialized boolean.
///
/// - `not` swaps the branch targets.
/// - `and` routes the left side's true edge to a fresh label placed before the right side.
/// - `or` does the same with the false edge, except for a `src`/`dst` pair of leaves, which is delegated to [`compile_dir_pair`] so the shared gates are emitted once.
fn compile_expr(e: &ExpandedExpr, ctx: &mut Ctx, branch: Branch) -> Result<(), CompileError> {
    match e {
        ExpandedExpr::Leaf(p) => compile_primitive(p, ctx, branch),
        ExpandedExpr::Not(inner) => compile_expr(inner, ctx, branch.swapped()),
        ExpandedExpr::And(l, r) => {
            let mid = ctx.b.new_label();
            compile_expr(
                l,
                ctx,
                Branch {
                    on_true: mid,
                    on_false: branch.on_false,
                },
            )?;

            ctx.b.place(mid);
            compile_expr(r, ctx, branch)
        }
        ExpandedExpr::Or(l, r) => {
            // special case -- an OR between two leaves that differ only in `dir` is exactly what a bare `src`/`dst` default expansion produces, and it's the one shape
            // where we can share the whole prefix instead of compiling each side fully independently
            if let (ExpandedExpr::Leaf(p1), ExpandedExpr::Leaf(p2)) = (l.as_ref(), r.as_ref())
                && differs_only_in_dir(p1, p2)
            {
                return compile_dir_pair(p1, p2, ctx, branch);
            }

            let mid = ctx.b.new_label();

            compile_expr(
                l,
                ctx,
                Branch {
                    on_true: branch.on_true,
                    on_false: mid,
                },
            )?;

            ctx.b.place(mid);
            compile_expr(r, ctx, branch)
        }
    }
}

/// Whether two primitives are identical except for direction (same protocol and type, different
/// `src`/`dst`) - the shape that a bare `src`/`dst` expansion produces.
fn differs_only_in_dir(p1: &CompiledPrimitive, p2: &CompiledPrimitive) -> bool {
    p1.proto == p2.proto && p1.dir != p2.dir && p1.ty == p2.ty
}

/// The prefix length of a `net` literal written without `/n`: the whole address.
fn full_prefix(addr: &AddrLit) -> u8 {
    match addr {
        AddrLit::V4(_) => 32,
        AddrLit::V6(_) => 128,
    }
}

/// Compiles a single primitive, dispatching on its type: `host`/`net` to [`compile_addr`] (a
/// missing prefix means /32), `port`/`portrange` to [`compile_port`] (a single port is the range
/// `p..=p`).
fn compile_primitive(
    p: &CompiledPrimitive,
    ctx: &mut Ctx,
    branch: Branch,
) -> Result<(), CompileError> {
    match &p.ty {
        PrimType::Host(addr) => compile_addr(p, ctx, addr, None, branch),
        PrimType::Net(addr, prefix) => compile_addr(
            p,
            ctx,
            addr,
            Some(prefix.unwrap_or(full_prefix(addr))),
            branch,
        ),
        PrimType::Port(port) => compile_port(p, ctx, *port, *port, branch),
        PrimType::PortRange(lo, hi) => compile_port(p, ctx, *lo, *hi, branch),
    }
}

/// Compiles `p1 or p2` where the two primitives differ only in direction. The ethertype/protocol
/// (and, for ports, fragment and header-length) prologue is emitted once and both directions are
/// checked after it, instead of duplicating it as a generic `or` would. `p1` is tried first.
fn compile_dir_pair(
    p1: &CompiledPrimitive,
    p2: &CompiledPrimitive,
    ctx: &mut Ctx,
    branch: Branch,
) -> Result<(), CompileError> {
    match &p1.ty {
        PrimType::Host(addr) => compile_addr_pair(p1, p2, ctx, addr, None, branch),
        PrimType::Net(addr, prefix) => compile_addr_pair(
            p1,
            p2,
            ctx,
            addr,
            Some(prefix.unwrap_or(full_prefix(addr))),
            branch,
        ),
        PrimType::Port(port) => compile_port_pair(p1, p2, ctx, *port, *port, branch),
        PrimType::PortRange(lo, hi) => compile_port_pair(p1, p2, ctx, *lo, *hi, branch),
    }
}

/// Where a `host`/`net` check's ethertype gate, optional IP-protocol gate, and address offsets live
/// for a given protocol.
struct AddrGates {
    ethertype: u32,
    ip_proto: Option<u32>,
    src_offset: u32,
    dst_offset: u32,
}

/// Maps a protocol to the gates and address offsets used by `host`/`net` checks.
///
/// # Errors
///
/// `ip6` is not implemented yet, and `sctp` has no host/net addressing.
fn addr_gates(proto: CompiledProto, offset: &Offset) -> Result<AddrGates, CompileError> {
    Ok(match proto {
        CompiledProto::Ip => AddrGates {
            ethertype: ETH_TYPE_IP,
            ip_proto: None,
            src_offset: IP_SRC_OFFSET,
            dst_offset: IP_DST_OFFSET,
        },
        CompiledProto::Tcp => AddrGates {
            ethertype: ETH_TYPE_IP,
            ip_proto: Some(IP_PROTO_TCP),
            src_offset: IP_SRC_OFFSET,
            dst_offset: IP_DST_OFFSET,
        },
        CompiledProto::Udp => AddrGates {
            ethertype: ETH_TYPE_IP,
            ip_proto: Some(IP_PROTO_UDP),
            src_offset: IP_SRC_OFFSET,
            dst_offset: IP_DST_OFFSET,
        },
        CompiledProto::Icmp => AddrGates {
            ethertype: ETH_TYPE_IP,
            ip_proto: Some(IP_PROTO_ICMP),
            src_offset: IP_SRC_OFFSET,
            dst_offset: IP_DST_OFFSET,
        },
        CompiledProto::Arp => AddrGates {
            ethertype: ETH_TYPE_ARP,
            ip_proto: None,
            src_offset: ARP_SENDER_PA_OFFSET,
            dst_offset: ARP_TARGET_PA_OFFSET,
        },
        CompiledProto::Rarp => AddrGates {
            ethertype: ETH_TYPE_RARP,
            ip_proto: None,
            src_offset: ARP_SENDER_PA_OFFSET,
            dst_offset: ARP_TARGET_PA_OFFSET,
        },
        // IPv6 addresses take the four-word path in `compile_addr6`; only an IPv4 literal ends up here.
        CompiledProto::Ip6 => {
            return Err(CompileError::new(
                offset.clone(),
                ErrorTag::InvalidPrimitiveCombination(
                    "'ip6' needs an IPv6 address, not an IPv4 one",
                ),
            ));
        }
        // Structurally unreachable today (desugar never produces Sctp for Host/Net, and the parser
        // never lets a user type "sctp" as a proto), but handled rather than `unreachable!()`'d in
        // case that ever changes.
        CompiledProto::Sctp => {
            return Err(CompileError::new(
                offset.clone(),
                ErrorTag::InvalidPrimitiveCombination(
                    "'sctp' has no host/net addressing; it's a transport protocol, usable only with 'port'/'portrange'",
                ),
            ));
        }
    })
}

/// Compiles a `host`/`net` primitive: the ethertype (and IP-protocol) gates, then the address
/// comparison. `prefix` of `None` is an exact host match; `Some(n)` masks the packet address to
/// `n` bits and compares it against the equally masked target.
fn compile_addr(
    p: &CompiledPrimitive,
    ctx: &mut Ctx,
    addr: &AddrLit,
    prefix: Option<u8>,
    branch: Branch,
) -> Result<(), CompileError> {
    let addr_val = match addr {
        AddrLit::V4(a) => *a,
        AddrLit::V6(a) => return compile_addr6(p, None, ctx, *a, prefix, branch),
    };
    let gates = addr_gates(p.proto, &p.offset)?;
    ensure_ethertype_available(ctx, &gates, &p.offset)?;
    let offset = p.offset.clone();
    emit_ethertype_and_proto_gates(
        ctx,
        gates.ethertype,
        gates.ip_proto,
        offset.clone(),
        branch.on_false,
    );

    let mask = prefix.map(netmask);
    let target = match mask {
        Some(m) => addr_val & m,
        None => addr_val,
    };
    emit_addr_terminal(ctx, &gates, p.dir, mask, target, offset, branch);
    Ok(())
}

/// Like [`compile_addr`], but for a `src`/`dst` pair: the gates are emitted once, then `p1`'s
/// direction is checked and, if it fails, `p2`'s. Both primitives must share proto and address.
fn compile_addr_pair(
    p1: &CompiledPrimitive,
    p2: &CompiledPrimitive,
    ctx: &mut Ctx,
    addr: &AddrLit,
    prefix: Option<u8>,
    branch: Branch,
) -> Result<(), CompileError> {
    let addr_val = match addr {
        AddrLit::V4(a) => *a,
        AddrLit::V6(a) => return compile_addr6(p1, Some(p2), ctx, *a, prefix, branch),
    };
    let gates = addr_gates(p1.proto, &p1.offset)?;
    ensure_ethertype_available(ctx, &gates, &p1.offset)?;
    let offset = p1.offset.clone();
    emit_ethertype_and_proto_gates(
        ctx,
        gates.ethertype,
        gates.ip_proto,
        offset.clone(),
        branch.on_false,
    );

    let mask = prefix.map(netmask);
    let target = match mask {
        Some(m) => addr_val & m,
        None => addr_val,
    };

    let mid = ctx.b.new_label();
    emit_addr_terminal(
        ctx,
        &gates,
        p1.dir,
        mask,
        target,
        offset.clone(),
        Branch {
            on_true: branch.on_true,
            on_false: mid,
        },
    );
    ctx.b.place(mid);
    emit_addr_terminal(ctx, &gates, p2.dir, mask, target, offset, branch);
    Ok(())
}

/// Compiles an IPv6 `host`/`net`: the IPv6 ethertype gate, then the address compared as four 32-bit words (`prefix` defaults to
/// all 128 bits). With `second` set, this is a `src`/`dst` pair sharing the gate, `first` being tried before it.
fn compile_addr6(
    first: &CompiledPrimitive,
    second: Option<&CompiledPrimitive>,
    ctx: &mut Ctx,
    addr: u128,
    prefix: Option<u8>,
    branch: Branch,
) -> Result<(), CompileError> {
    let offset = first.offset.clone();
    if first.proto != CompiledProto::Ip6 {
        return Err(CompileError::new(
            offset,
            ErrorTag::InvalidPrimitiveCombination("an IPv6 address needs 'ip6' (or no protocol)"),
        ));
    }
    let gates = AddrGates {
        ethertype: ETH_TYPE_IPV6,
        ip_proto: None,
        src_offset: IP6_SRC_OFFSET,
        dst_offset: IP6_DST_OFFSET,
    };
    ensure_ethertype_available(ctx, &gates, &offset)?;
    emit_ethertype_and_proto_gates(ctx, gates.ethertype, None, offset.clone(), branch.on_false);

    let prefix = u32::from(prefix.unwrap_or(128));
    match second {
        None => emit_addr6_terminal(ctx, &gates, first.dir, addr, prefix, offset, branch),
        Some(second) => {
            let mid = ctx.b.new_label();
            emit_addr6_terminal(
                ctx,
                &gates,
                first.dir,
                addr,
                prefix,
                offset.clone(),
                Branch {
                    on_true: branch.on_true,
                    on_false: mid,
                },
            );
            ctx.b.place(mid);
            emit_addr6_terminal(ctx, &gates, second.dir, addr, prefix, offset, branch);
        }
    }
    Ok(())
}

/// Emits the IPv6 comparison for one direction: for each 32-bit word the `prefix` reaches, `ld; [and mask;] jeq`. Any mismatch goes to
/// `on_false`; a match falls through to the next word, and the last word's match goes to `on_true`. Words past the prefix are not
/// examined, so `/0` compares nothing and always matches.
fn emit_addr6_terminal(
    ctx: &mut Ctx,
    gates: &AddrGates,
    dir: DirTag,
    addr: u128,
    prefix: u32,
    offset: Offset,
    branch: Branch,
) {
    let step = match dir {
        DirTag::Src => gates.src_offset,
        DirTag::Dst => gates.dst_offset,
    };
    let words = prefix.div_ceil(32);
    if words == 0 {
        ctx.b.emit(
            IrOp2::Jmp {
                target: branch.on_true,
            },
            offset,
        );
        return;
    }
    for i in 0..words {
        // Word `i` covers address bits `32*i .. 32*i + 32` counted from the most significant end.
        let shift = 96 - 32 * i;
        let word = (addr >> shift) as u32;
        let bits_in_prefix = (prefix - 32 * i).min(32);
        let mask = netmask(bits_in_prefix as u8);
        let last = i == words - 1;
        let next = if last {
            branch.on_true
        } else {
            ctx.b.new_label()
        };

        ctx.b
            .emit(IrOp2::LdwAbs(ctx.ip_base + step + 4 * i), offset.clone());
        if mask != u32::MAX {
            ctx.b.emit(IrOp2::AndK(mask), offset.clone());
        }
        ctx.b.emit(
            IrOp2::Jeq {
                imm: word & mask,
                jt: next,
                jf: branch.on_false,
            },
            offset.clone(),
        );
        if !last {
            ctx.b.place(next);
        }
    }
}

/// Emits the final address check: load the src/dst address word, apply `mask` (skipped when it is
/// absent or all ones), and `jeq` against `target` with the branch targets.
fn emit_addr_terminal(
    ctx: &mut Ctx,
    gates: &AddrGates,
    dir: DirTag,
    mask: Option<u32>,
    target: u32,
    offset: Offset,
    branch: Branch,
) {
    let step = match dir {
        DirTag::Src => gates.src_offset,
        DirTag::Dst => gates.dst_offset,
    };
    let ip_base = ctx.ip_base;
    ctx.b.emit(IrOp2::LdwAbs(ip_base + step), offset.clone());
    if let Some(m) = mask
        && m != u32::MAX
    {
        ctx.b.emit(IrOp2::AndK(m), offset.clone());
    }
    ctx.b.emit(
        IrOp2::Jeq {
            imm: target,
            jt: branch.on_true,
            jf: branch.on_false,
        },
        offset,
    );
}

/// Returns the IP protocol number for a port-bearing protocol (tcp, udp, sctp); any other
/// protocol is an invalid combination with `port`/`portrange`.
fn port_proto_num(proto: CompiledProto, offset: &Offset) -> Result<u32, CompileError> {
    match proto {
        CompiledProto::Tcp => Ok(IP_PROTO_TCP),
        CompiledProto::Udp => Ok(IP_PROTO_UDP),
        CompiledProto::Sctp => Ok(IP_PROTO_SCTP),
        _ => Err(CompileError::new(
            offset.clone(),
            ErrorTag::InvalidPrimitiveCombination(
                "'port'/'portrange' only apply to tcp, udp, or sctp",
            ),
        )),
    }
}

/// Compiles a `port`/`portrange` primitive over the inclusive range `lo..=hi`: ethertype and
/// protocol gates, the not-a-later-fragment gate, loading the IP header length into `X`, then the
/// port comparison.
fn compile_port(
    p: &CompiledPrimitive,
    ctx: &mut Ctx,
    lo: u16,
    hi: u16,
    branch: Branch,
) -> Result<(), CompileError> {
    let proto_num = port_proto_num(p.proto, &p.offset)?;
    let offset = p.offset.clone();
    emit_ethertype_and_proto_gates(
        ctx,
        ETH_TYPE_IP,
        Some(proto_num),
        offset.clone(),
        branch.on_false,
    );
    emit_not_fragment_gate(ctx, offset.clone(), branch.on_false);
    let ip_base = ctx.ip_base;
    ctx.b.emit(IrOp2::LdxMsh(ip_base), offset.clone());
    emit_port_terminal(ctx, p.dir, lo, hi, offset, branch);
    Ok(())
}

/// Like [`compile_port`], but for a `src`/`dst` pair: the prologue (gates, fragment check,
/// `ldx_msh`) is emitted once, then `p1`'s direction is checked and, if it fails, `p2`'s.
fn compile_port_pair(
    p1: &CompiledPrimitive,
    p2: &CompiledPrimitive,
    ctx: &mut Ctx,
    lo: u16,
    hi: u16,
    branch: Branch,
) -> Result<(), CompileError> {
    let proto_num = port_proto_num(p1.proto, &p1.offset)?;
    let offset = p1.offset.clone();
    emit_ethertype_and_proto_gates(
        ctx,
        ETH_TYPE_IP,
        Some(proto_num),
        offset.clone(),
        branch.on_false,
    );
    emit_not_fragment_gate(ctx, offset.clone(), branch.on_false);
    let ip_base = ctx.ip_base;
    ctx.b.emit(IrOp2::LdxMsh(ip_base), offset.clone());

    let mid = ctx.b.new_label();
    emit_port_terminal(
        ctx,
        p1.dir,
        lo,
        hi,
        offset.clone(),
        Branch {
            on_true: branch.on_true,
            on_false: mid,
        },
    );
    ctx.b.place(mid);
    emit_port_terminal(ctx, p2.dir, lo, hi, offset, branch);
    Ok(())
}

/// Ports only exist in a packet's first fragment; libpcap always guards port checks against later
/// fragments carrying no transport header, and so do we - skipping this is the classic way to
/// diverge from the oracle only on fragmented traffic.
fn emit_not_fragment_gate(ctx: &mut Ctx, offset: Offset, on_false: Label) {
    let ip_base = ctx.ip_base;
    ctx.b.emit(
        IrOp2::LdhAbs(ip_base + IP_FLAGS_FRAG_OFFSET),
        offset.clone(),
    );
    let not_fragment = ctx.b.new_label();
    ctx.b.emit(
        IrOp2::Jset {
            imm: FRAG_MASK,
            jt: on_false,
            jf: not_fragment,
        },
        offset,
    );
    ctx.b.place(not_fragment);
}

/// Loads the src/dst port and compares it, assuming `X` already holds the IPv4 header length (from a
/// preceding `ldx_msh(ip_base)`).
///
/// `k = ip_base + {PORT_SRC_REL,PORT_DST_REL}` here, not an offset from the TCP/UDP header's own
/// start: `X` (set by `ldx_msh`) holds only the *header length* (e.g. 20), not the header length
/// plus `ip_base`, so `ip_base` has to be folded into this instruction's `k` instead - which is
/// exactly what makes this indirect load's `k` operand, not `X` itself, the thing a future `vlan`
/// primitive would need to shift by 4.
fn emit_port_terminal(
    ctx: &mut Ctx,
    dir: DirTag,
    lo: u16,
    hi: u16,
    offset: Offset,
    branch: Branch,
) {
    let port_rel = match dir {
        DirTag::Src => PORT_SRC_REL,
        DirTag::Dst => PORT_DST_REL,
    };
    let ip_base = ctx.ip_base;
    ctx.b
        .emit(IrOp2::LdhInd(ip_base + port_rel), offset.clone());
    if lo == hi {
        ctx.b.emit(
            IrOp2::Jeq {
                imm: lo as u32,
                jt: branch.on_true,
                jf: branch.on_false,
            },
            offset,
        );
    } else {
        // port >= lo && port <= hi. cBPF has no "less than", so "<=" is synthesized from BPF_JGT
        // with jt/jf swapped: "not (port > hi)".
        let after_lo = ctx.b.new_label();
        ctx.b.emit(
            IrOp2::Jge {
                imm: lo as u32,
                jt: after_lo,
                jf: branch.on_false,
            },
            offset.clone(),
        );
        ctx.b.place(after_lo);
        ctx.b.emit(
            IrOp2::Jgt {
                imm: hi as u32,
                jt: branch.on_false,
                jf: branch.on_true,
            },
            offset,
        );
    }
}

/// `arp`/`rarp`/`ip6` are identified by their ethertype alone, so they can't be expressed on a link type that has none.
fn ensure_ethertype_available(
    ctx: &Ctx,
    gates: &AddrGates,
    offset: &Offset,
) -> Result<(), CompileError> {
    if ctx.eth_field.is_none() && gates.ethertype != ETH_TYPE_IP {
        return Err(CompileError::new(
            offset.clone(),
            ErrorTag::InvalidPrimitiveCombination(
                "'arp'/'rarp'/'ip6' need a link layer with an ethertype field; this link type has none",
            ),
        ));
    }
    Ok(())
}

/// Emits the ethertype check and, if `ip_proto` is given, the IP-protocol check. Any mismatch
/// jumps to `on_false`; on success execution falls through to whatever is emitted next.
fn emit_ethertype_and_proto_gates(
    ctx: &mut Ctx,
    ethertype: u32,
    ip_proto: Option<u32>,
    offset: Offset,
    on_false: Label,
) {
    let ip_base = ctx.ip_base;
    // No ethertype field (Raw): nothing to check, the packet is taken to be IPv4.
    if let Some(eth_field) = ctx.eth_field {
        gate_ldh_eq(ctx, eth_field, ethertype, offset.clone(), on_false);
    }
    if let Some(proto_num) = ip_proto {
        gate_ldb_eq(ctx, ip_base + IP_PROTO_OFFSET, proto_num, offset, on_false);
    }
}

/// Emits `load; jeq imm, <continue>, on_false` and places `<continue>` immediately, so whatever the
/// caller emits next lands right after this gate passes.
fn gate_ldh_eq(ctx: &mut Ctx, jump: u32, imm: u32, offset: Offset, on_false: Label) {
    ctx.b.emit(IrOp2::LdhAbs(jump), offset.clone());
    let cont = ctx.b.new_label();
    ctx.b.emit(
        IrOp2::Jeq {
            imm,
            jt: cont,
            jf: on_false,
        },
        offset,
    );
    ctx.b.place(cont);
}

/// Byte-wide counterpart of [`gate_ldh_eq`]: `ldb [jump]; jeq imm, <continue>, on_false`.
fn gate_ldb_eq(ctx: &mut Ctx, jump: u32, imm: u32, offset: Offset, on_false: Label) {
    ctx.b.emit(IrOp2::LdbAbs(jump), offset.clone());
    let cont = ctx.b.new_label();
    ctx.b.emit(
        IrOp2::Jeq {
            imm,
            jt: cont,
            jf: on_false,
        },
        offset,
    );
    ctx.b.place(cont);
}

/// Converts a prefix length (0..=32) to a netmask, e.g. `24` -> `0xffff_ff00`. `0` gives an empty
/// mask (handled separately because shifting a `u32` by 32 would overflow).
fn netmask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::irep::{IrInsn, IrOp};

    const SNAPLEN: u32 = 0xFFFF_FFFF;

    fn get_expanded(src: &str) -> ExpandedExpr {
        let tokens = crate::lexer::lex(src).unwrap();
        let expr = crate::parser::parse(&tokens).unwrap();
        crate::desugar::expand(&expr)
    }

    fn get_gen(src: &str) -> IrProgram {
        generate(&get_expanded(src), LinkType::Ethernet, SNAPLEN).expect("codegen")
    }

    /// Real instructions only, `Mark`s are zero-width and hold no index of their own.
    fn ops(p: &IrProgram) -> Vec<IrOp2> {
        p.stream
            .iter()
            .filter_map(|it| match it {
                IrOp::Real(IrInsn { op, .. }) => Some(*op),
                IrOp::Mark(_) => None,
            })
            .collect()
    }

    fn label_positions(p: &IrProgram) -> Vec<Option<usize>> {
        let mut pos = vec![None; p.num_labels];
        let mut emitted = 0usize;
        for it in &p.stream {
            match it {
                IrOp::Real(_) => emitted += 1,
                IrOp::Mark(l) => {
                    assert!(pos[l.index()].is_none(), "label {} placed twice", l.index());
                    pos[l.index()] = Some(emitted);
                }
            }
        }
        pos
    }

    /// Renders the program with labels resolved to instruction indices, in `tcpdump -d` style.
    fn render(p: &IrProgram) -> String {
        let pos = label_positions(p);
        let at = |l: Label| pos[l.index()].expect("label placed");
        let mut out = String::new();
        for (i, op) in ops(p).iter().enumerate() {
            let line = match *op {
                IrOp2::LdhAbs(k) => format!("ldh      [{k}]"),
                IrOp2::LdbAbs(k) => format!("ldb      [{k}]"),
                IrOp2::LdwAbs(k) => format!("ld       [{k}]"),
                IrOp2::LdxMsh(k) => format!("ldxb     4*([{k}]&0xf)"),
                IrOp2::LdhInd(k) => format!("ldh      [x + {k}]"),
                IrOp2::AndK(k) => format!("and      #{k:#x}"),
                IrOp2::Jeq { imm, jt, jf } => {
                    format!("jeq      #{imm:#x}  jt {} jf {}", at(jt), at(jf))
                }
                IrOp2::Jgt { imm, jt, jf } => {
                    format!("jgt      #{imm:#x}  jt {} jf {}", at(jt), at(jf))
                }
                IrOp2::Jge { imm, jt, jf } => {
                    format!("jge      #{imm:#x}  jt {} jf {}", at(jt), at(jf))
                }
                IrOp2::Jset { imm, jt, jf } => {
                    format!("jset     #{imm:#x}  jt {} jf {}", at(jt), at(jf))
                }
                IrOp2::Jmp { target } => format!("ja       {}", at(target)),
                IrOp2::Ret(k) => format!("ret      #{k}"),
            };
            out.push_str(&format!("({i:03}) {line}\n"));
        }
        out
    }

    /// The canonical filter, pinned instruction for instruction. Any change to lowering,
    /// gate order or sharing shows up here as a readable diff instead of a silent behaviour
    /// change and this listing is ~comparable to `tcpdump -d 'tcp port 80'` (if IPv4 only).
    #[test]
    fn tcp_port_80() {
        let expected = "\
(000) ldh      [12]
(001) jeq      #0x800  jt 2 jf 12
(002) ldb      [23]
(003) jeq      #0x6  jt 4 jf 12
(004) ldh      [20]
(005) jset     #0x1fff  jt 12 jf 6
(006) ldxb     4*([14]&0xf)
(007) ldh      [x + 14]
(008) jeq      #0x50  jt 11 jf 9
(009) ldh      [x + 16]
(010) jeq      #0x50  jt 11 jf 12
(011) ret      #4294967295
(012) ret      #0
";
        assert_eq!(render(&get_gen("tcp port 80")), expected);
    }

    /// Same filter over Linux cooked capture: everything shifts by the 2 extra header bytes (ethertype at 14, `ip_base` 16).
    #[test]
    fn tcp_port_80_linux_sll() {
        let program =
            generate(&get_expanded("tcp port 80"), LinkType::LinuxSll, SNAPLEN).expect("codegen");
        let expected = "\
(000) ldh      [14]
(001) jeq      #0x800  jt 2 jf 12
(002) ldb      [25]
(003) jeq      #0x6  jt 4 jf 12
(004) ldh      [22]
(005) jset     #0x1fff  jt 12 jf 6
(006) ldxb     4*([16]&0xf)
(007) ldh      [x + 16]
(008) jeq      #0x50  jt 11 jf 9
(009) ldh      [x + 18]
(010) jeq      #0x50  jt 11 jf 12
(011) ret      #4294967295
(012) ret      #0
";
        assert_eq!(render(&program), expected);
    }

    /// Raw has no link-layer header: no ethertype gate, and every offset is relative to byte 0.
    #[test]
    fn tcp_port_80_raw() {
        let program =
            generate(&get_expanded("tcp port 80"), LinkType::Raw, SNAPLEN).expect("codegen");
        let expected = "\
(000) ldb      [9]
(001) jeq      #0x6  jt 2 jf 10
(002) ldh      [6]
(003) jset     #0x1fff  jt 10 jf 4
(004) ldxb     4*([0]&0xf)
(005) ldh      [x + 0]
(006) jeq      #0x50  jt 9 jf 7
(007) ldh      [x + 2]
(008) jeq      #0x50  jt 9 jf 10
(009) ret      #4294967295
(010) ret      #0
";
        assert_eq!(render(&program), expected);
    }

    /// `arp` is defined by its ethertype, which Raw doesn't have.
    #[test]
    fn arp_host_is_rejected_on_raw() {
        let exp = get_expanded("arp host 10.0.0.1");
        assert!(matches!(
            generate(&exp, LinkType::Raw, SNAPLEN).unwrap_err().tag,
            ErrorTag::InvalidPrimitiveCombination(_)
        ));
    }

    #[test]
    fn ip6_src_host() {
        // Same listing as `tcpdump -d 'ip6 src host 2001:db8::1'`, up to the `ret` value (snaplen).
        let expected = "\
(000) ldh      [12]
(001) jeq      #0x86dd  jt 2 jf 11
(002) ld       [22]
(003) jeq      #0x20010db8  jt 4 jf 11
(004) ld       [26]
(005) jeq      #0x0  jt 6 jf 11
(006) ld       [30]
(007) jeq      #0x0  jt 8 jf 11
(008) ld       [34]
(009) jeq      #0x1  jt 10 jf 11
(010) ret      #4294967295
(011) ret      #0
";
        assert_eq!(render(&get_gen("ip6 src host 2001:db8::1")), expected);
    }

    /// A prefix ending inside a word masks only that word, and the words after it are not compared at all.
    /// A /33 needs two words: all of the first, and the top bit of the second (dst words are at 14 + 24 = 38 and 42).
    #[test]
    fn ip6_net_prefix_ending_inside_a_word() {
        let expected = "\
(000) ldh      [12]
(001) jeq      #0x86dd  jt 2 jf 8
(002) ld       [38]
(003) jeq      #0x20010db8  jt 4 jf 8
(004) ld       [42]
(005) and      #0x80000000
(006) jeq      #0x0  jt 7 jf 8
(007) ret      #4294967295
(008) ret      #0
";
        assert_eq!(render(&get_gen("ip6 dst net 2001:db8::/33")), expected);
    }

    #[test]
    fn ip6_net_prefix_on_a_word_boundary_needs_no_mask() {
        let listing = render(&get_gen("ip6 src net 2001:db8::/32"));
        assert!(
            !listing.contains("and"),
            "a /32 is exactly one whole word:\n{listing}"
        );
        assert!(listing.contains("ld       [22]"));
        assert!(!listing.contains("[26]"));
    }

    /// `/0` matches every IPv6 packet: only the ethertype gate remains, then an unconditional jump to accept.
    #[test]
    fn ip6_net_zero_prefix_matches_every_ipv6_packet() {
        let expected = "\
(000) ldh      [12]
(001) jeq      #0x86dd  jt 2 jf 4
(002) ja       3
(003) ret      #4294967295
(004) ret      #0
";
        assert_eq!(render(&get_gen("ip6 src net ::/0")), expected);
    }

    #[test]
    fn ip6_net_full_prefix_equals_host() {
        assert_eq!(
            render(&get_gen("ip6 dst net ::1/128")),
            render(&get_gen("ip6 dst host ::1"))
        );
    }

    /// The bare `host` form expands to `ip6 src or ip6 dst`, which must share one ethertype gate.
    #[test]
    fn bare_ip6_host_shares_the_ethertype_gate() {
        let listing = render(&get_gen("host ::1"));
        assert_eq!(listing.matches("ldh      [12]").count(), 1, "{listing}");
        assert_eq!(listing.matches("#0x86dd").count(), 1, "{listing}");
        assert!(listing.contains("ld       [22]"), "src words:\n{listing}");
        assert!(listing.contains("ld       [38]"), "dst words:\n{listing}");
    }

    #[test]
    fn ip6_host_on_linux_sll_shifts_by_two_bytes() {
        let program = generate(
            &get_expanded("ip6 src host ::1"),
            LinkType::LinuxSll,
            SNAPLEN,
        )
        .expect("codegen");
        let listing = render(&program);
        assert!(listing.starts_with("(000) ldh      [14]\n(001) jeq      #0x86dd"));
        assert!(listing.contains("ld       [24]")); // ip_base 16 + 8
    }

    #[test]
    fn ipv6_address_needs_the_ip6_protocol() {
        for src in ["ip host ::1", "arp host ::1", "ip src net ::1/64"] {
            let exp = get_expanded(src);
            assert!(
                matches!(
                    generate(&exp, LinkType::Ethernet, SNAPLEN).unwrap_err().tag,
                    ErrorTag::InvalidPrimitiveCombination(_)
                ),
                "{src}"
            );
        }
    }

    #[test]
    fn ip6_rejects_an_ipv4_address() {
        let exp = get_expanded("ip6 host 1.2.3.4");
        assert!(matches!(
            generate(&exp, LinkType::Ethernet, SNAPLEN).unwrap_err().tag,
            ErrorTag::InvalidPrimitiveCombination(_)
        ));
    }

    /// Raw has no ethertype to tell IPv6 from IPv4 with, so an `ip6` primitive can't be compiled for it yet.
    #[test]
    fn ip6_is_rejected_on_raw() {
        let exp = get_expanded("ip6 host ::1");
        assert!(matches!(
            generate(&exp, LinkType::Raw, SNAPLEN).unwrap_err().tag,
            ErrorTag::InvalidPrimitiveCombination(_)
        ));
    }
}
