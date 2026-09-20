//! Produce a finished and validated cBPF program.
//!

use crate::insn::{Insn, fmt_insn};
use crate::vm;
use alloc::vec::Vec;
use core::fmt;

/// A compiled, validated cBPF program.
#[derive(Debug)]
pub struct Program {
    insns: Vec<Insn>,
}

impl Program {
    /// Wrap already-backpatched instructions.
    pub(crate) fn from_validated(insns: Vec<Insn>) -> Self {
        Program { insns }
    }

    /// The compiled instructions, in execution order.
    pub fn instructions(&self) -> &[Insn] {
        &self.insns
    }

    /// Run this program against a packet, cBPF-style: returns the number of bytes of `packet` the kernel would keep. `0` means reject.
    pub fn run(&self, packet: &[u8]) -> u32 {
        vm::run(&self.insns, packet)
    }

    /// Sugar for `run(packet) != 0`.
    pub fn matches(&self, packet: &[u8]) -> bool {
        self.run(packet) != 0
    }
}

impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, insn) in self.insns.iter().enumerate() {
            if index > 0 {
                writeln!(f)?;
            }
            fmt_insn(f, *insn, index)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::KEEP_WHOLE_PACKET;

    #[test]
    fn matches_is_sugar_for_run_nonzero() {
        let program = Program::from_validated(alloc::vec![Insn::ret(KEEP_WHOLE_PACKET)]);
        assert!(program.matches(&[1, 2, 3]));

        let program = Program::from_validated(alloc::vec![Insn::ret(0)]);
        assert!(!program.matches(&[1, 2, 3]));
    }

    #[test]
    fn display_joins_instructions_with_newlines() {
        let program =
            Program::from_validated(alloc::vec![Insn::ldh_abs(12), Insn::ret(KEEP_WHOLE_PACKET)]);
        let rendered = format!("{program}");
        assert_eq!(rendered, "(000) ldh      [12]\n(001) ret      #0xffffffff");
    }
}
