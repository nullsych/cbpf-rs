# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `attach` module (Linux only, behind the `attach` cargo feature): `attach(sock_fd, &program)`
  attaches a compiled `Program` to a live socket via `setsockopt(SO_ATTACH_FILTER)`, so the
  kernel filters the packets read from it. Programs with more than `u16::MAX` instructions are
  rejected with `InvalidInput`; OS failures are returned as `io::Error`.
- Tests for `attach` over loopback UDP (no root needed): the kernel keeps matching and drops
  non-matching datagrams, and bad or non-socket descriptors are reported as OS errors.

## [0.1.0]

First functional release: compiles pcap-filter expressions into classic BPF (cBPF) bytecode.

### Added

- `compile(src, link_type, snaplen)`: compiles a pcap-filter expression into a `Program`.
- Lexer, recursive-descent parser and desugaring of user input into libpcap's canonical form,
  with source offsets carried through to `CompileError`.
- Filter primitives: `host`, `net` (with prefix length), `port` and `portrange`, qualified by
  `src`/`dst` and by protocol (`ip`, `tcp`, `udp`, `icmp`, `arp`, `rarp`), combined with
  `and`, `or` and `not`.
- IPv4 code generation for Ethernet, including the ethertype and IP-protocol gates and the
  not-a-later-fragment check for port filters, matching libpcap's behaviour on fragmented traffic.
- Shared prologue for bare `src`/`dst` pairs instead of duplicating gates on each side of the `or`.
- Two-pass assembler (label resolution into `jt`/`jf` displacements) producing `Insn` values.
- `Program`, with a `Display` listing in `tcpdump -d` style, and a built-in cBPF interpreter to
  run a program against a packet without leaving Rust.
- `LinkType` (`Ethernet`, `LinuxSll`, `Raw`) with conversion from and to `LINKTYPE_*` numbers.
- `KEEP_WHOLE_PACKET` constant, equivalent to `tcpdump -s 0`.
- `cbpf_dump` example for comparing the output with `tcpdump -d`.

### Limitations

- Only `LinkType::Ethernet` can be compiled; other link types return
  `ErrorTag::UnsupportedLinkType`.
- IPv6 (`ip6`, IPv6 address literals) is not implemented yet and returns
  `ErrorTag::Unimplemented`.

[Unreleased]: https://github.com/nullsych/cbpf-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/nullsych/cbpf-rs/releases/tag/v0.1.0
