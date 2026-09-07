//! `cbpf-rs` compiles pcap-filter (tcpdump/libpcap "primitive") expressions into classic BPF (cBPF)
//! bytecode, and can run that bytecode against a packet with a small built-in interpreter.
//!
//! ```
//! use cbpf_rs::{compile, LinkType, KEEP_WHOLE_PACKET};
//!
//! let program = compile("tcp port 80", LinkType::Ethernet, KEEP_WHOLE_PACKET).unwrap();
//! println!("{program}");
//! ```

mod error;
mod lexer;
mod linktype;

pub use error::{CompileError, ErrorKind};
pub use linktype::LinkType;

// TODO: when all pipelint would be ready
// Compile a pcap-filter expression into a cBPF.
// pub fn compile(src: &str, link_type: LinkType, snaplen: u32) /* -> Result ... */
// {
// From e.g. "tcp port 80" we gain [Word("tcp"), Word("port"), Word("80"), Eof]
// let tokens = lexer::lex(src)?;
// ...
//
// }
