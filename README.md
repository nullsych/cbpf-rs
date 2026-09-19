# 🦀 cbpf-rs

A Rust compiler from pcap-filter (tcpdump/libpcap "primitive") expressions to classic BPF (cBPF) bytecode, plus a small interpreter to run that bytecode against a packet.

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

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

## Authors

Maintained by [nullsych](https://github.com/nullsych).