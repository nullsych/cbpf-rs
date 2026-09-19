//! `cbpf-rs` compiles pcap-filter (tcpdump/libpcap "primitive") expressions into classic BPF (cBPF)
//! bytecode, and can run that bytecode against a packet with a small built-in interpreter.
//!
//! ```
//! use cbpf_rs::{compile, LinkType, KEEP_WHOLE_PACKET};
//!
//! let program = compile("tcp port 80", LinkType::Ethernet, KEEP_WHOLE_PACKET).unwrap();
//! println!("{program}");
//! ```

mod ast;
mod backpatch;
mod codegen;
mod desugar;
mod error;
mod insn;
mod irep;
mod lexer;
mod linktype;
mod parser;
mod program;
mod vm;

pub use error::{CompileError, ErrorTag};
pub use insn::{Insn, KEEP_WHOLE_PACKET};
pub use linktype::LinkType;
pub use program::Program;

/// Compile a pcap-filter expression into a cBPF [`Program`].
///
/// `link_type` determines the link-layer header the packet is assumed to start with (and therefore the offset of the first byte past it).
/// `snaplen` is the value returned by the accepting `ret` instruction - pass `0xFFFF_FFFF` ([`KEEP_WHOLE_PACKET`]) to keep the whole packet,
/// matching `tcpdump -s 0`.
pub fn compile(src: &str, link_type: LinkType, snaplen: u32) -> Result<Program, CompileError> {
    let tokens = lexer::lex(src)?;
    let ast = parser::parse(&tokens)?;
    let expanded = desugar::expand(&ast);
    let ir = codegen::generate(&expanded, link_type, snaplen)?;
    let insns = backpatch::assemble(ir)?;

    Ok(program::Program::from_validated(insns))
}
