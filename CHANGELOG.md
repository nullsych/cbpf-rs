# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- IPv6 `host` and `net` primitives: `ip6 [src|dst] host <addr>`, `ip6 [src|dst] net <addr>/<0..=128>`,
  and the bare `host`/`net` forms with an IPv6 address (which mean `ip6`, not `ip or arp or rarp`).
  Addresses accept the usual textual forms (`::`, compressed zeros, `::ffff:1.2.3.4`). The address
  is compared as four 32-bit words; a prefix ending inside a word masks that word and the words
  past the prefix are not read. The generated code matches `tcpdump -d` for `ip6 host`.
- `ErrorTag::InvalidIPv6Literal`, returned for text that is not a valid IPv6 address or prefix.
- Differential tests against `tcpdump` for IPv6 addresses and prefix lengths.
- `tcp`/`udp`/`portrange` primitives now also match IPv6 traffic, the way real libpcap's own
  generated code does: a filter like `tcp port 80` never has to mention IPv6 to match it. The
  IPv6 side checks the header's immediate next-header field rather than walking the extension
  header chain (matching libpcap's own behavior), so a packet with an intervening extension
  header (e.g. a Fragment header) is never matched, first fragment included.
- `LinkType::Raw` (no ethertype field) now tells IPv4 and IPv6 apart using the header's version
  nibble, so `ip6 host`/`net` and IPv6-matching `port`/`portrange` filters compile there too, and
  `ip`/`port` filters no longer accidentally match a stray IPv6 packet.
- `examples/kernel_diff.rs`: a standalone, root-required tool (not run by `cargo test`) that attaches
  this crate's compiled program and libpcap's own (via `tcpdump -ddd`) to two `AF_PACKET` sockets on
  `lo`, injects hand-built frames, and compares which one the real Linux kernel classic-BPF engine let
  through - a cross-check beyond `tests/differential.rs`, which never leaves userspace.

### Changed

- IPv6 address literals are no longer reported as `ErrorTag::Unimplemented`; they are compiled.
  An IPv6 address combined with an IPv4-only protocol (`ip host ::1`, `tcp host ::1`) or an IPv4
  address with `ip6` is an `ErrorTag::InvalidPrimitiveCombination`. `arp`/`rarp` are still rejected
  on `LinkType::Raw`: unlike IPv4/IPv6, they have no version-nibble equivalent to gate on.
- The bytecode generated for `tcp`/`udp`/`portrange` primitives (including on `LinkType::Raw`) has
  changed shape to add the IPv6 branch and, on Raw, the version-nibble gate; `Program::matches`
  behavior for actual IPv4 traffic is unchanged (see `tests/differential.rs`).

## [0.1.3] - 2026-09-26

### Added

- `LinkType::Raw` support in `compile()`: filters can now be compiled for packets that start
  directly at the IP header (DLT 101). Raw has no ethertype field, so the ethertype gate is
  skipped and packets are assumed to be IPv4 until IPv6 is implemented.

### Changed

- `compile()` with `LinkType::Raw` now returns a program instead of
  `ErrorTag::UnsupportedLinkType`, so no link type is rejected any more. `arp`/`rarp` filters on
  `Raw` return `ErrorTag::InvalidPrimitiveCombination`, since those protocols are identified by
  their ethertype.

## [0.1.2] - 2026-09-20

### Added

- `no_std` support: the compiler and the interpreter build as `no_std` + `alloc`. `std` is a default-on cargo feature; disable it with `default-features = false`. The `attach` feature still requires `std`.
- `LinkType::LinuxSll` support in `compile()`: filters can now be compiled for Linux cooked captures (the `any` pseudo-interface), where the protocol type sits at byte 14 and the IP header starts at byte 16. Covered by codegen and black-box tests.

### Changed

- `compile()` with `LinkType::LinuxSll` now returns a program instead of
  `ErrorTag::UnsupportedLinkType`. Only `LinkType::Raw` is still rejected, because it has no
  ethertype field to gate on.

## [0.1.1] - 2026-09-19

### Added

- `attach` module (Linux only, behind the `attach` cargo feature): `attach(sock_fd, &program)`
  attaches a compiled `Program` to a live socket via `setsockopt(SO_ATTACH_FILTER)`, so the
  kernel filters the packets read from it. Programs with more than `u16::MAX` instructions are
  rejected with `InvalidInput`; OS failures are returned as `io::Error`.
- Tests for `attach` over loopback UDP (no root needed): the kernel keeps matching and drops
  non-matching datagrams, and bad or non-socket descriptors are reported as OS errors.
- Black-box tests of the public `compile()` entry point (`tests/black_box.rs`): the pinned
  `tcp port 80` listing, `src`/`dst` expansion, fragmented packets never matching a port
  primitive, `net` prefix masking, `and`/`or`/`not` with parentheses, inclusive `portrange`
  bounds, and error reporting (unbalanced parentheses, invalid IPv4 literal offsets, `port` on a
  non-transport protocol, IPv6 literals, non-Ethernet link types, jump displacement overflow).
- Differential tests against a real `tcpdump` (`tests/differential.rs`): accept/reject decisions
  on IPv4 packets are compared with `tcpdump -r` for `port`, `host`/`net`, `portrange`, fragments
  and boolean connectives. The tests are skipped when `tcpdump` is not installed. Disassembly
  text is deliberately not compared: libpcap also emits an IPv6 branch that this crate does not.

## [0.1.0] - 2026-09-19

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

[Unreleased]: https://github.com/nullsych/cbpf-rs/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/nullsych/cbpf-rs/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/nullsych/cbpf-rs/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/nullsych/cbpf-rs/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/nullsych/cbpf-rs/releases/tag/v0.1.0
