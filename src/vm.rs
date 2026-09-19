//! A small cBPF virtual machine (interpreter). Used by [`crate::Program::run`].
//!
//! Details: emulates the real kernel/libpcap BPF interpreter's contract closely enough, e.g.:
//!
//! - `ret`'s `k` is returned raw and unclamped, even past `packet.len()` - clamping to the actual captured length is the capture layer's job, not the BPF program's.
//!
//! - Any out-of-bounds load, or a jump landing outside the program, causes the packet to be rejected (return `0`) rather than a panic --
//!   same as the kernel verifier's runtime behavior, and it keeps this interpreter `unsafe`-free.

use crate::insn::{Insn, Op};

/// It runs a cBPF program against a packet and returns the program's status: the `k` of the `ret` it reaches (how many bytes to keep; `0` means reject).
///
/// The machine has an accumulator `a` and an index register `x`, both starting at `0`, and a program counter starting at the first instruction.
/// Loads read big-endian values from `packet` into `a` (or, for `ldx_msh`, the IP header length into `x`); jumps move `pc` relative to the
/// next instruction. The `ret` ends execution.
///
/// Note: never panics on malformed input. An out-of-bounds load, a jump past the end of the program, falling off the end without a `ret`, or an unknown opcode all return `0` (reject).
pub(crate) fn run(insns: &[Insn], packet: &[u8]) -> u32 {
    let mut a: u32 = 0;
    let mut x: u32 = 0;
    let mut pc: usize = 0;

    loop {
        let Some(insn) = insns.get(pc) else {
            // Ran off the end of the program (or a jump landed past it)
            // without hitting a `ret` - reject rather than panic.
            return 0;
        };

        match insn.decode() {
            Op::LdhAbs(k) => match read_u16(packet, k as usize) {
                Some(v) => a = v,
                None => return 0,
            },
            Op::LdbAbs(k) => match read_u8(packet, k as usize) {
                Some(v) => a = v,
                None => return 0,
            },
            Op::LdhInd(k) => {
                let Some(offset) = (x as usize).checked_add(k as usize) else {
                    return 0;
                };
                match read_u16(packet, offset) {
                    Some(v) => a = v,
                    None => return 0,
                }
            }
            Op::LdwAbs(k) => match read_u32(packet, k as usize) {
                Some(v) => a = v,
                None => return 0,
            },
            Op::LdxMsh(k) => match read_u8(packet, k as usize) {
                Some(byte) => x = (byte & 0x0f) * 4,
                None => return 0,
            },
            Op::AluAndK(k) => a &= k,
            Op::Ja(k) => {
                pc = match step(pc, k) {
                    Some(next) => next,
                    None => return 0,
                };
                continue;
            }
            Op::Jeq(k) => {
                pc = branch(pc, insn, a == k);
                continue;
            }
            Op::Jgt(k) => {
                pc = branch(pc, insn, a > k);
                continue;
            }
            Op::Jge(k) => {
                pc = branch(pc, insn, a >= k);
                continue;
            }
            Op::Jset(k) => {
                pc = branch(pc, insn, a & k != 0);
                continue;
            }
            Op::Ret(k) => return k,
            Op::Unknown => return 0,
        }
        pc += 1;
    }
}

fn branch(pc: usize, insn: &Insn, taken: bool) -> usize {
    let disp = if taken { insn.jt } else { insn.jf };
    pc + 1 + disp as usize
}

fn step(pc: usize, k: u32) -> Option<usize> {
    (pc + 1).checked_add(k as usize)
}

fn read_u8(packet: &[u8], offset: usize) -> Option<u32> {
    packet.get(offset).map(|&b| b as u32)
}

fn read_u16(packet: &[u8], offset: usize) -> Option<u32> {
    let bytes = packet.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]) as u32)
}

fn read_u32(packet: &[u8], offset: usize) -> Option<u32> {
    let bytes = packet.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::KEEP_WHOLE_PACKET;

    #[test]
    fn ret_k_is_raw_and_unclamped() {
        let insns = [Insn::ret(KEEP_WHOLE_PACKET)];
        assert_eq!(run(&insns, &[1, 2, 3]), KEEP_WHOLE_PACKET);

        let insns = [Insn::ret(9999)];
        assert_eq!(
            run(&insns, &[1, 2, 3]),
            9999,
            "ret's k must not be clamped to packet.len()"
        );
    }

    #[test]
    fn ret_zero_rejects() {
        let insns = [Insn::ret(0)];
        assert_eq!(run(&insns, &[1, 2, 3]), 0);
    }

    #[test]
    fn out_of_bounds_abs_load_rejects_without_panicking() {
        let insns = [Insn::ldh_abs(100), Insn::ret(KEEP_WHOLE_PACKET)];
        assert_eq!(run(&insns, &[1, 2, 3]), 0);
    }

    #[test]
    fn out_of_bounds_ind_load_rejects_without_panicking() {
        // x is 0 here (never set), so this reads packet[9999..10001].
        let insns = [Insn::ldh_ind(9999), Insn::ret(KEEP_WHOLE_PACKET)];
        assert_eq!(run(&insns, &[1, 2, 3]), 0);
    }

    #[test]
    fn jump_past_end_of_program_rejects_without_panicking() {
        let insns = [Insn::jmp(50)];
        assert_eq!(run(&insns, &[]), 0);
    }

    #[test]
    fn unknown_opcode_rejects_without_panicking() {
        let insns = [Insn {
            code: 0xffff,
            jt: 0,
            jf: 0,
            k: 0,
        }];
        assert_eq!(run(&insns, &[]), 0);
    }

    #[test]
    fn ldx_msh_extracts_ip_header_length() {
        // packet[14]'s low nibble is the IHL (IP header length in 32-bit words);
        // ldx_msh(14) should put IHL*4 == 20 into X, so a later `[x + 0]` read lands on packet[20..22].
        let mut packet = [0u8; 22];
        packet[14] = 0x45; // version=4, IHL=5 -> X becomes 20
        packet[20] = 0x00;
        packet[21] = 0x50; // port 80, big-endian
        let insns = [
            Insn::ldx_msh(14),
            Insn::ldh_ind(0),
            Insn::jeq(80, 0, 1),
            Insn::ret(KEEP_WHOLE_PACKET),
            Insn::ret(0),
        ];
        assert_eq!(run(&insns, &packet), KEEP_WHOLE_PACKET);
    }

    #[test]
    fn conditional_jump_targets_are_relative_to_the_next_instruction() {
        // jeq matches -> jt=0 (fall through to ret 1), jf=1 (skip ret 1, hit ret 2)
        let insns = [
            Insn::ldb_abs(0),
            Insn::jeq(5, 0, 1),
            Insn::ret(1),
            Insn::ret(2),
        ];
        assert_eq!(run(&insns, &[5]), 1);
        assert_eq!(run(&insns, &[6]), 2);
    }
}
