# 🦀 cbpf-rs

A Rust compiler from pcap-filter (`tcpdump`/`libpcap` "primitive") expressions to classic BPF (cBPF) bytecode, plus a small interpreter to run that bytecode against a packet.

```rust
use cbpf_rs::{compile, LinkType, KEEP_WHOLE_PACKET};

let program = compile("tcp port 80", LinkType::Ethernet, KEEP_WHOLE_PACKET)?;
println!("{program}");
```

```
(000) ldh      [12]
(001) jeq      #0x800           jt 2	jf 12
(002) ldb      [23]
(003) jeq      #0x6             jt 4	jf 12
(004) ldh      [20]
(005) jset     #0x1fff          jt 12	jf 6
(006) ldxb     4*([14]&0xf)
(007) ldh      [x + 14]
(008) jeq      #0x50            jt 11	jf 9
(009) ldh      [x + 16]
(010) jeq      #0x50            jt 11	jf 12
(011) ret      #0xffffffff
(012) ret      #0x0
```

## `no_std`

The compiler and the interpreter are `no_std` + `alloc`; `std` is a default-on feature that can be turned off (`default-features = false`).

## Attaching to a real socket

The `attach` feature (Linux, pulls in `libc`) adds `cbpf_rs::attach`, a thin wrapper over `setsockopt(SOL_SOCKET, SO_ATTACH_FILTER)`. It is the only place in this crate that uses `unsafe` - every other module, including the interpreter, is safe Rust.

That's possible because `Insn` is `#[repr(C)]` 😊, and field-for-field identical to the kernel's `struct sock_filter`, so handing a compiled program to the kernel is a pointer cast, not per-instruction marshaling.

## Manual testing

Use [cbpf_dump](examples/cbpf_dump.rs) util with *pcap-filter expression* (e.g. **tcp port 80**) as an argument to compile it and print the resulting cBPF:

```sh
$ cargo run --quiet --example cbpf_dump -- 'tcp port 80'
(000) ldh      [12]
(001) jeq      #0x800           jt 2    jf 12
(002) ldb      [23]
(003) jeq      #0x6             jt 4    jf 12
(004) ldh      [20]
(005) jset     #0x1fff          jt 12   jf 6
(006) ldxb     4*([14]&0xf)
(007) ldh      [x + 14]
(008) jeq      #0x50            jt 11   jf 9
(009) ldh      [x + 16]
(010) jeq      #0x50            jt 11   jf 12
(011) ret      #0xffffffff
(012) ret      #0x0
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

## Authors

Maintained by [nullsych](https://github.com/nullsych).