//! Two-pass assembler - from symbolic [`crate::irep`] to concrete [`Insn`]s.
//!

use crate::error::{CompileError, ErrorTag, Offset};
use crate::insn::Insn;
use crate::irep::{IrInsn, IrOp, IrOp2, IrProgram, Label};
use alloc::vec;
use alloc::vec::Vec;

pub(crate) fn assemble(program: IrProgram) -> Result<Vec<Insn>, CompileError> {
    let IrProgram { stream, num_labels } = program;

    // Pass A
    let mut offsets: Vec<Option<u32>> = vec![None; num_labels];
    let mut real: Vec<IrInsn> = Vec::with_capacity(stream.len());
    for op in stream {
        match op {
            IrOp::Mark(label) => offsets[label.index()] = Some(real.len() as u32),
            IrOp::Real(insn) => real.push(insn),
        }
    }

    // Pass B
    real.iter()
        .enumerate()
        .map(|(idx, insn)| lower(idx, insn, &offsets))
        .collect()
}

/// Resolves a conditional jump's target into a `jt`/`jf` displacement.
fn resolve_branch(
    idx: usize,
    label: Label,
    offsets: &[Option<u32>],
    offset: &Offset,
) -> Result<u8, CompileError> {
    let displacement = displacement_from(idx, label, offsets);
    u8::try_from(displacement).map_err(|_| {
        CompileError::new(
            offset.clone(),
            ErrorTag::JumpDisplacementOverflow {
                inst_index: idx,
                displacement: displacement as u32,
            },
        )
    })
}

/// Resolves an unconditional jump's target into `ja`'s 32-bit `k` - this never overflows the way a
/// conditional branch's 8-bit `jt`/`jf` can.
fn resolve_jmp(idx: usize, label: Label, offsets: &[Option<u32>]) -> u32 {
    displacement_from(idx, label, offsets) as u32
}

fn displacement_from(idx: usize, label: Label, offsets: &[Option<u32>]) -> usize {
    let target = offsets[label.index()]
        .expect("every Label reaching backpatch was placed exactly once by codegen")
        as usize;
    let next = idx + 1;
    debug_assert!(
        target >= next,
        "codegen invariant violated: CPS lowering never emits a backward jump"
    );
    target - next
}

fn lower(idx: usize, insn: &IrInsn, offsets: &[Option<u32>]) -> Result<Insn, CompileError> {
    Ok(match insn.op {
        IrOp2::LdhAbs(k) => Insn::ldh_abs(k),
        IrOp2::LdbAbs(k) => Insn::ldb_abs(k),
        IrOp2::LdwAbs(k) => Insn::ldw_abs(k),
        IrOp2::LdxMsh(k) => Insn::ldx_msh(k),
        IrOp2::LdhInd(k) => Insn::ldh_ind(k),
        IrOp2::AndK(k) => Insn::and_k(k),
        IrOp2::Jeq { imm, jt, jf } => {
            let jt = resolve_branch(idx, jt, offsets, &insn.offset)?;
            let jf = resolve_branch(idx, jf, offsets, &insn.offset)?;
            Insn::jeq(imm, jt, jf)
        }
        IrOp2::Jgt { imm, jt, jf } => {
            let jt = resolve_branch(idx, jt, offsets, &insn.offset)?;
            let jf = resolve_branch(idx, jf, offsets, &insn.offset)?;
            Insn::jgt(imm, jt, jf)
        }
        IrOp2::Jge { imm, jt, jf } => {
            let jt = resolve_branch(idx, jt, offsets, &insn.offset)?;
            let jf = resolve_branch(idx, jf, offsets, &insn.offset)?;
            Insn::jge(imm, jt, jf)
        }
        IrOp2::Jset { imm, jt, jf } => {
            let jt = resolve_branch(idx, jt, offsets, &insn.offset)?;
            let jf = resolve_branch(idx, jf, offsets, &insn.offset)?;
            Insn::jset(imm, jt, jf)
        }
        IrOp2::Jmp { target } => Insn::jmp(resolve_jmp(idx, target, offsets)),
        IrOp2::Ret(k) => Insn::ret(k),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::irep::IrBuilder;

    #[test]
    fn resolves_a_simple_forward_jump() {
        let mut b = IrBuilder::new();
        let jt = b.new_label();
        let jf = b.new_label();
        b.emit(IrOp2::Jeq { imm: 80, jt, jf }, 0..1);
        b.emit(IrOp2::LdbAbs(0), 0..1); // instruction 1: skipped when jt taken
        b.place(jt);
        b.emit(IrOp2::Ret(1), 0..1); // instruction 2
        b.place(jf);
        b.emit(IrOp2::Ret(0), 0..1); // instruction 3

        let insns = assemble(b.finish()).unwrap();
        assert_eq!(insns[0], Insn::jeq(80, 1, 2));
    }

    #[test]
    fn displacement_of_exactly_255_succeeds() {
        // jf resolves immediately (displacement 0); jt has to cross exactly 255 filler instructions
        // to land at the boundary this instruction set allows.
        let mut b = IrBuilder::new();
        let jt = b.new_label();
        let jf = b.new_label();
        b.emit(IrOp2::Jeq { imm: 1, jt, jf }, 0..1);
        b.place(jf);
        for _ in 0..255 {
            b.emit(IrOp2::LdbAbs(0), 0..1);
        }
        b.place(jt);
        b.emit(IrOp2::Ret(1), 0..1);

        let insns = assemble(b.finish()).unwrap();
        assert_eq!(insns[0], Insn::jeq(1, 255, 0));
    }

    #[test]
    fn displacement_of_256_is_a_compile_error() {
        // Same shape, but one filler instruction further - 256 crosses the boundary and must be
        // rejected, not silently truncated.
        let mut b = IrBuilder::new();
        let jt = b.new_label();
        let jf = b.new_label();
        let offset = 5..9;
        b.emit(IrOp2::Jeq { imm: 1, jt, jf }, offset.clone());
        b.place(jt);
        for _ in 0..256 {
            b.emit(IrOp2::LdbAbs(0), 0..1);
        }
        b.place(jf);
        b.emit(IrOp2::Ret(0), 0..1);

        let err = assemble(b.finish()).unwrap_err();
        assert_eq!(err.offset, offset);
        assert_eq!(
            err.tag,
            ErrorTag::JumpDisplacementOverflow {
                inst_index: 0,
                displacement: 256
            }
        );
    }

    #[test]
    fn multi_label_or_chain_shape() {
        // Mirrors what codegen's Or-lowering produces: p1 true -> accept;
        // p1 false -> try p2; p2 true -> accept; p2 false -> reject.
        let mut b = IrBuilder::new();
        let accept = b.new_label();
        let reject = b.new_label();
        let mid = b.new_label();

        b.emit(
            IrOp2::Jeq {
                imm: 1,
                jt: accept,
                jf: mid,
            },
            0..1,
        ); // 0
        b.place(mid);
        b.emit(
            IrOp2::Jeq {
                imm: 2,
                jt: accept,
                jf: reject,
            },
            0..1,
        ); // 1
        b.place(accept);
        b.emit(IrOp2::Ret(u32::MAX), 0..1); // 2
        b.place(reject);
        b.emit(IrOp2::Ret(0), 0..1); // 3

        let insns = assemble(b.finish()).unwrap();
        assert_eq!(insns[0], Insn::jeq(1, 1, 0)); // accept is insn 2 (disp 1), mid is insn 1 (disp 0)
        assert_eq!(insns[1], Insn::jeq(2, 0, 1)); // accept is insn 2 (disp 0), reject is insn 3 (disp 1)
    }

    #[test]
    fn unconditional_jump_uses_k_not_jt_jf() {
        let mut b = IrBuilder::new();
        let target = b.new_label();
        b.emit(IrOp2::Jmp { target }, 0..1);
        b.emit(IrOp2::LdbAbs(0), 0..1);
        b.place(target);
        b.emit(IrOp2::Ret(0), 0..1);

        let insns = assemble(b.finish()).unwrap();
        assert_eq!(insns[0], Insn::jmp(1));
    }
}
