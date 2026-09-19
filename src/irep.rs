//! Intermediate representation with symbolic jump targets.
//!

use crate::error::Offset;

/// An opaque handle to a not-yet-resolved instruction offset. Allocated by [`IrBuilder::new_label`],
/// and must be placed exactly once with [`IrBuilder::place`] before `backpatch::assemble` runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Label(u32);

impl Label {
    pub(crate) fn index(self) -> usize {
        self.0 as usize
    }
}

/// One item in the IR stream: either a real instruction, or a zero-width marker recording "this
/// label resolves to whatever `Real` instruction comes next".
#[derive(Debug)]
pub(crate) enum IrOp {
    Real(IrInsn),
    Mark(Label),
}

#[derive(Debug)]
pub(crate) struct IrInsn {
    pub op: IrOp2,
    pub offset: Offset,
}

/// The operations codegen needs - deliberately not the full cBPF ISA (no store/scratch-memory
/// instructions, no ALU ops beyond the one `and` masking needs). Conditional jumps carry `Label`s
/// instead of raw displacements; everything else is already in its final form.
#[derive(Clone, Copy, Debug)]
pub(crate) enum IrOp2 {
    LdhAbs(u32),
    LdbAbs(u32),
    LdwAbs(u32),
    LdxMsh(u32),
    LdhInd(u32),
    AndK(u32),
    Jeq {
        imm: u32,
        jt: Label,
        jf: Label,
    },
    Jgt {
        imm: u32,
        jt: Label,
        jf: Label,
    },
    Jge {
        imm: u32,
        jt: Label,
        jf: Label,
    },
    Jset {
        imm: u32,
        jt: Label,
        jf: Label,
    },
    /// Unconditional jump. Not emitted by MVP codegen's CPS lowering (every `place`d label already
    /// sits exactly where control falls through to), but `backpatch.rs` supports it for
    /// completeness - a future codegen change (e.g. `vlan` re-entering shared code) may want it.
    /// Exercised directly by `backpatch`'s own unit tests.
    #[allow(dead_code)]
    Jmp {
        target: Label,
    },
    Ret(u32),
}

#[derive(Debug)]
pub(crate) struct IrBuilder {
    stream: Vec<IrOp>,
    num_labels: u32,
}

impl IrBuilder {
    pub(crate) fn new() -> Self {
        IrBuilder {
            stream: Vec::new(),
            num_labels: 0,
        }
    }

    /// Allocate a new, not-yet-placed label.
    pub(crate) fn new_label(&mut self) -> Label {
        let label = Label(self.num_labels);
        self.num_labels += 1;
        label
    }

    /// Mark the current position in the stream as where `label` resolves to.
    pub(crate) fn place(&mut self, label: Label) {
        self.stream.push(IrOp::Mark(label));
    }

    pub(crate) fn emit(&mut self, op: IrOp2, offset: Offset) {
        self.stream.push(IrOp::Real(IrInsn { op, offset }));
    }

    /// Consume the builder, handing `backpatch::assemble` both the stream and how many labels it
    /// needs room for.
    pub(crate) fn finish(self) -> IrProgram {
        IrProgram {
            stream: self.stream,
            num_labels: self.num_labels as usize,
        }
    }
}

#[derive(Debug)]
pub(crate) struct IrProgram {
    pub stream: Vec<IrOp>,
    pub num_labels: usize,
}
