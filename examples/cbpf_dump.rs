//! `cbpf_dump` is a manual-testing helper: compile a pcap-filter expression and print the resulting cBPF program in `tcpdump -d` style,
//! so it's easy to track the diff btw `tcpdump -d`/`tcpdump -ddd` that runs on the same filter.
//!
//! ```text
//! cargo run --example cbpf_dump -- 'tcp port 80'
//! ```

use cbpf_rs::{KEEP_WHOLE_PACKET, LinkType, compile};
use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let filter = env::args().skip(1).collect::<Vec<_>>().join(" ");

    if filter.is_empty() {
        eprintln!("Usage: cargo run --example cbpf_dump -- '<pcap-filter expression>'");
        return ExitCode::FAILURE;
    }

    match compile(&filter, LinkType::Ethernet, KEEP_WHOLE_PACKET) {
        Ok(program) => {
            println!("{program}");
            ExitCode::SUCCESS
        }

        Err(err) => {
            eprintln!("error: {err}");
            eprintln!("  {filter}");
            let width = err.offset.end.saturating_sub(err.offset.start).max(1);
            eprintln!("  {}{}", " ".repeat(err.offset.start), "^".repeat(width));
            ExitCode::FAILURE
        }
    }
}
