//! `cbpf-rs` compiles pcap-filter (tcpdump/libpcap "primitive") expressions into classic BPF (cBPF)
//! bytecode, and can run that bytecode against a packet with a small built-in interpreter.

mod ast;
mod desugar;
mod error;
mod lexer;
mod linktype;
mod parser;

pub use error::{CompileError, ErrorTag};
pub use linktype::LinkType;

// TODO: when all pipeline would be ready
// Compile a pcap-filter expression into a cBPF.
// pub fn compile(src: &str, link_type: LinkType, snaplen: u32) /* -> Result ... */
// {
// From e.g. "tcp port 80" we gain [Word("tcp"), Word("port"), Word("80"), Eof]
// let tokens = lexer::lex(src)?;
// ...
//
// }
