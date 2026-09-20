//! The concrete cBPF instruction, e.g. `struct sock_filter` and its `tcpdump -d`-related [`Display`](core::fmt::Display) implementation.

use core::fmt;

// BPF instruction class (low 3 bits of `code`).
const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;

// BPF_SIZE (bits 3-4). BPF_W (word, 4 bytes) is the default, value 0.
const BPF_W: u16 = 0x00;
const BPF_H: u16 = 0x08;
const BPF_B: u16 = 0x10;

// BPF_MODE (top 3 bits for BPF_LD/BPF_LDX).
const BPF_ABS: u16 = 0x20;
const BPF_IND: u16 = 0x40;
const BPF_MSH: u16 = 0xa0;

// BPF_OP for BPF_JMP.
const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;

// BPF_OP for BPF_ALU. Only BPF_AND is needed, for masking an address down to a network prefix (`net a.b.c.d/n`).
const BPF_ALU: u16 = 0x04;
const BPF_AND: u16 = 0x50;

// BPF_SRC: BPF_K (immediate) is 0 and is the only source MVP codegen uses for conditional jumps and ALU ops.
const BPF_K: u16 = 0x00;

/// `ret`'s `k` value that means "keep the whole packet".
///
/// This is cBPF's own convention: the kernel (and `matches`/`run`, see [`crate::Program`]) treat any accepting `ret` as "keep the first `k` bytes",
/// and `0xFFFF_FFFF` bytes is effectively "all of it" since no real packet is that long.
pub const KEEP_WHOLE_PACKET: u32 = 0xFFFF_FFFF;

/// One classic BPF instruction.
///
/// Deliberately `#[repr(C)]` and field-for-field identical to the kernel's
///
/// `struct sock_filter
/// {
///     __u16 code;
///      __u8 jt;
///     __u8 jf;
///     __u32 k;
/// }`.
///
/// That makes attaching a compiled [`crate::Program`] to a socket (the `attach` feature) a pointer cast with no marshaling, and it
/// means `jt`/`jf` here are already the raw relative displacements a real `tcpdump -d` prints - nothing needs to be recomputed for [`Display`](fmt::Display).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl Insn {
    /// `ldh [k]` - load the half-word at absolute offset `k`.
    pub(crate) fn ldh_abs(k: u32) -> Self {
        Insn {
            code: BPF_LD | BPF_H | BPF_ABS,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// `ldb [k]` - load the byte at absolute offset `k`.
    pub(crate) fn ldb_abs(k: u32) -> Self {
        Insn {
            code: BPF_LD | BPF_B | BPF_ABS,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// `ld [k]` - load the word (4 bytes) at absolute offset `k`. Used for IPv4 addresses.
    pub(crate) fn ldw_abs(k: u32) -> Self {
        Insn {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// `ldxb 4*([k]&0xf)` - load the low nibble of the byte at offset `k`, multiply by four, store in X.
    /// This is how a variable-length IPv4 header's length is turned into a byte offset to the payload.
    pub(crate) fn ldx_msh(k: u32) -> Self {
        Insn {
            code: BPF_LDX | BPF_B | BPF_MSH,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// `ldh [x + k]` - load the half-word at `X + k`.
    pub(crate) fn ldh_ind(k: u32) -> Self {
        Insn {
            code: BPF_LD | BPF_H | BPF_IND,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// `jeq #k, jt, jf` - `jt`/`jf` are relative displacements, already resolved.
    pub(crate) fn jeq(k: u32, jt: u8, jf: u8) -> Self {
        Insn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt,
            jf,
            k,
        }
    }

    pub(crate) fn jgt(k: u32, jt: u8, jf: u8) -> Self {
        Insn {
            code: BPF_JMP | BPF_JGT | BPF_K,
            jt,
            jf,
            k,
        }
    }

    pub(crate) fn jge(k: u32, jt: u8, jf: u8) -> Self {
        Insn {
            code: BPF_JMP | BPF_JGE | BPF_K,
            jt,
            jf,
            k,
        }
    }

    pub(crate) fn jset(k: u32, jt: u8, jf: u8) -> Self {
        Insn {
            code: BPF_JMP | BPF_JSET | BPF_K,
            jt,
            jf,
            k,
        }
    }

    /// `ja k` - unconditional jump. Unlike conditional jumps, the displacement lives in the 32-bit
    /// `k` field, so it never overflows the way `jt`/`jf` can.
    pub(crate) fn jmp(k: u32) -> Self {
        Insn {
            code: BPF_JMP | BPF_JA,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// `ret #k`.
    pub(crate) fn ret(k: u32) -> Self {
        Insn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// `and #k` - `A = A & k`. The one ALU instruction MVP codegen needs, for masking an address down to a `net a.b.c.d/n` prefix.
    pub(crate) fn and_k(k: u32) -> Self {
        Insn {
            code: BPF_ALU | BPF_AND | BPF_K,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// Decode `code` into a typed operation. Shared by [`Display`](fmt::Display) (via [`fmt_insn`]) and the interpreter ([`crate::vm`]) so the opcode bit patterns are matched in exactly one place.
    /// `Op::Unknown` covers any `struct sock_filter` bit pattern this crate's codegen never emits (the full cBPF ISA has more instructions than current implementation) - the VM treats it as
    /// "reject", never as a panic.
    pub(crate) fn decode(self) -> Op {
        match self.code {
            c if c == BPF_LD | BPF_H | BPF_ABS => Op::LdhAbs(self.k),
            c if c == BPF_LD | BPF_B | BPF_ABS => Op::LdbAbs(self.k),
            c if c == BPF_LD | BPF_W | BPF_ABS => Op::LdwAbs(self.k),
            c if c == BPF_LD | BPF_H | BPF_IND => Op::LdhInd(self.k),
            c if c == BPF_LDX | BPF_B | BPF_MSH => Op::LdxMsh(self.k),
            c if c == BPF_ALU | BPF_AND | BPF_K => Op::AluAndK(self.k),
            c if c == BPF_JMP | BPF_JA => Op::Ja(self.k),
            c if c == BPF_JMP | BPF_JEQ | BPF_K => Op::Jeq(self.k),
            c if c == BPF_JMP | BPF_JGT | BPF_K => Op::Jgt(self.k),
            c if c == BPF_JMP | BPF_JGE | BPF_K => Op::Jge(self.k),
            c if c == BPF_JMP | BPF_JSET | BPF_K => Op::Jset(self.k),
            c if c == BPF_RET | BPF_K => Op::Ret(self.k),
            _ => Op::Unknown,
        }
    }

    fn is_conditional_jump(self) -> bool {
        matches!(
            self.decode(),
            Op::Jeq(_) | Op::Jgt(_) | Op::Jge(_) | Op::Jset(_)
        )
    }
}

/// A decoded [`Insn`]. See [`Insn::decode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    LdhAbs(u32),
    LdbAbs(u32),
    LdwAbs(u32),
    LdhInd(u32),
    LdxMsh(u32),
    AluAndK(u32),
    Ja(u32),
    Jeq(u32),
    Jgt(u32),
    Jge(u32),
    Jset(u32),
    Ret(u32),
    Unknown,
}

/// Renders one instruction the way `tcpdump -d` does, given its own index (for the `(NNN)` prefix) so conditional jumps can print absolute
/// target indices the way tcpdump does, instead of raw displacements.
///
/// Format mirrors libpcap's `bpf_image()`: non-jump and unconditional-jump instructions are `"(%03d) %-8s %s"`;
/// conditional jumps are `"(%03d) %-8s %-16s jt %d\tjf %d"`.
pub(crate) fn fmt_insn(f: &mut fmt::Formatter<'_>, insn: Insn, index: usize) -> fmt::Result {
    let (mnemonic, operand) = describe(insn, index);
    if insn.is_conditional_jump() {
        let jt = index + 1 + insn.jt as usize;
        let jf = index + 1 + insn.jf as usize;
        write!(
            f,
            "({index:03}) {mnemonic:<8} {operand:<16} jt {jt}\tjf {jf}"
        )
    } else {
        write!(f, "({index:03}) {mnemonic:<8} {operand}")
    }
}

fn describe(insn: Insn, index: usize) -> (&'static str, alloc::string::String) {
    use alloc::format;

    match insn.decode() {
        Op::LdhAbs(k) => ("ldh", format!("[{k}]")),
        Op::LdbAbs(k) => ("ldb", format!("[{k}]")),
        Op::LdwAbs(k) => ("ld", format!("[{k}]")),
        Op::LdhInd(k) => ("ldh", format!("[x + {k}]")),
        Op::LdxMsh(k) => ("ldxb", format!("4*([{k}]&0xf)")),
        Op::AluAndK(k) => ("and", format!("#0x{k:x}")),
        Op::Ja(k) => ("ja", format!("{}", index + 1 + k as usize)),
        Op::Jeq(k) => ("jeq", format!("#0x{k:x}")),
        Op::Jgt(k) => ("jgt", format!("#0x{k:x}")),
        Op::Jge(k) => ("jge", format!("#0x{k:x}")),
        Op::Jset(k) => ("jset", format!("#0x{k:x}")),
        Op::Ret(k) => ("ret", format!("#0x{k:x}")),
        Op::Unknown => ("unimp", format!("0x{:x}", insn.code)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    // These are pinned against libpcap's well-known `bpf_image()` format (`"(%03d) %-8s %s"` / `"(%03d) %-8s %-16s jt %d\tjf %d"`),
    // reconstructed from the widely mirrored bpf_image.c source. Re-check against a live `tcpdump -d` run when one is available
    // and adjust here if the local libpcap version prints anything differently.
    struct Line(Insn, usize, &'static str);

    fn render(insn: Insn, index: usize) -> alloc::string::String {
        struct Wrap(Insn, usize);
        impl fmt::Display for Wrap {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt_insn(f, self.0, self.1)
            }
        }
        format!("{}", Wrap(insn, index))
    }

    #[test]
    fn matches_tcpdump_format() {
        let cases = [
            Line(Insn::ldh_abs(12), 0, "(000) ldh      [12]"),
            Line(
                Insn::jeq(0x800, 1, 6),
                1,
                "(001) jeq      #0x800           jt 3\tjf 8",
            ),
            Line(Insn::ldb_abs(23), 2, "(002) ldb      [23]"),
            Line(Insn::ldx_msh(14), 3, "(003) ldxb     4*([14]&0xf)"),
            Line(Insn::ldh_ind(14), 4, "(004) ldh      [x + 14]"),
            Line(Insn::ldw_abs(26), 9, "(009) ld       [26]"),
            Line(Insn::and_k(0xffffff00), 10, "(010) and      #0xffffff00"),
            Line(
                Insn::jset(0x1fff, 0, 3),
                5,
                "(005) jset     #0x1fff          jt 6\tjf 9",
            ),
            Line(Insn::jmp(2), 6, "(006) ja       9"),
            Line(
                Insn::ret(KEEP_WHOLE_PACKET),
                7,
                "(007) ret      #0xffffffff",
            ),
            Line(Insn::ret(0), 8, "(008) ret      #0x0"),
        ];
        for Line(insn, index, expected) in cases {
            assert_eq!(render(insn, index), expected);
        }
    }
}
