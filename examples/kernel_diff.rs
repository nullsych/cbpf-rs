//! A standalone, root-required differential test against the *real* Linux kernel.
//!
//! The tool attaches this crate's compiled program to one `AF_PACKET` raw socket and
//! libpcap's own compiled program (via `tcpdump -ddd`, so no libpcap FFI is needed) to a second
//! one, both bound to `lo`, injects a hand-made Ethernet frames, and compares which
//! socket actually received each one - i.e. whether the real kernel filter, not our `vm.rs`,
//! agrees with libpcap.
//!
//! Run it explicitly, after building with the `attach` feature:
//!
//! ```text
//! sudo -E cargo run --example kernel_diff --features attach
//! ```

#[cfg(all(target_os = "linux", feature = "attach"))]
fn main() -> std::process::ExitCode {
    linux::main()
}

#[cfg(not(all(target_os = "linux", feature = "attach")))]
fn main() {
    eprintln!(
        "kernel_diff needs Linux and `--features attach` (it talks to a real AF_PACKET socket)."
    );
    std::process::exit(1);
}

#[cfg(all(target_os = "linux", feature = "attach"))]
mod linux {
    use cbpf_rs::{Insn, KEEP_WHOLE_PACKET, LinkType, compile};
    use std::error::Error;
    use std::ffi::CString;
    use std::io;
    use std::mem;
    use std::net::Ipv6Addr;
    use std::os::unix::io::RawFd;
    use std::process::{Command, ExitCode};
    use std::time::Duration;

    const ETH_P_IPV4: u16 = 0x0800;
    const ETH_P_IPV6: u16 = 0x86dd;
    /// How long to wait for a frame to arrive on a socket before deciding its filter rejected it.
    /// Loopback delivery is effectively immediate; this only has to survive scheduler jitter.
    const RECV_TIMEOUT: Duration = Duration::from_millis(200);

    /// One (filter, frame) case. `label` is only for the report; the oracle is whatever `tcpdump
    /// -ddd` compiles `filter` to, not a hardcoded expectation - so a case can't silently go stale
    /// the way a hand-maintained "should_match: bool" field could.
    struct Case {
        filter: &'static str,
        label: &'static str,
        frame: Vec<u8>,
    }

    pub(super) fn main() -> ExitCode {
        let version = Command::new("tcpdump").arg("--version").output();
        let Ok(version) = version else {
            eprintln!(
                "tcpdump not found on PATH; this tool needs it for libpcap's real compiled bytecode."
            );
            return ExitCode::FAILURE;
        };
        // `tcpdump --version` writes its version line to stderr, not stdout.
        let version_line = String::from_utf8_lossy(&version.stderr);
        let version_line = version_line.lines().next().unwrap_or("(unknown version)");
        println!("using {version_line}\n");

        let cases = build_cases();
        let total = cases.len();
        let mut disagreements = 0usize;
        let mut infra_errors = 0usize;

        for (i, case) in cases.iter().enumerate() {
            println!("{}", "─".repeat(78));
            println!("[{}/{total}] {} — {}", i + 1, case.filter, case.label);
            println!("{}", "─".repeat(78));

            match run_case(case) {
                Ok(true) => println!("  => AGREE: both sockets made the same call\n"),
                Ok(false) => {
                    println!(
                        "  => DISAGREE: cbpf-rs and the kernel-attached libpcap bytecode differ\n"
                    );
                    disagreements += 1;
                }
                Err(e) => {
                    println!("  => ERROR: could not run this case: {e}\n");
                    infra_errors += 1;
                }
            }
        }

        println!("{}", "═".repeat(78));
        println!(
            "{total} case(s), {disagreements} disagreement(s), {infra_errors} infrastructure error(s)"
        );
        if infra_errors > 0 {
            eprintln!(
                "\nSome cases couldn't run at all - are you root? AF_PACKET/SOCK_RAW needs CAP_NET_RAW."
            );
        }
        if disagreements > 0 || infra_errors > 0 {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        }
    }

    /// Compiles `case.filter` both ways, injects `case.frame` on `lo`, and reports whether the two
    /// kernel-attached programs agreed on it. Prints every step as it happens: what socket or file
    /// descriptor is being opened, what bytes are going over the wire, and what each side decided.
    fn run_case(case: &Case) -> Result<bool, Box<dyn Error>> {
        print!("  1. compile with cbpf-rs ... ");
        let ours = compile(case.filter, LinkType::Ethernet, KEEP_WHOLE_PACKET)?;
        let our_len = ours.instructions().len();
        println!("ok, {our_len} instruction(s):");
        for line in ours.to_string().lines() {
            println!("       {line}");
        }

        print!(
            "  2. compile with `tcpdump -ddd -y EN10MB '{}'` ... ",
            case.filter
        );
        let (theirs, their_raw) = tcpdump_compile(case.filter)?;
        println!("ok, {} instruction(s):", theirs.len());
        println!("       (code, jt, jf, k) - the raw `struct sock_filter` tcpdump printed:");
        for line in their_raw.lines() {
            println!("         {line}");
        }

        // Resolve "lo", open the 3 AF_PACKET/SOCK_RAW sockets bound to it (ours, libpcap's, and a
        // filter-less one to inject the frame), attach both filters via SO_ATTACH_FILTER, and give
        // the two filtered sockets a receive timeout - silently; step 3 below is what matters.
        let ifindex = if_nametoindex("lo")?;
        let sock_a = raw_socket_on(ifindex)?; // ours
        let sock_b = raw_socket_on(ifindex)?; // libpcap's
        let sock_tx = raw_socket_on(ifindex)?; // injector, no filter attached
        cbpf_rs::attach::attach(sock_a, &ours)?;
        attach_raw(sock_b, &theirs)?;
        set_recv_timeout(sock_a, RECV_TIMEOUT)?;
        set_recv_timeout(sock_b, RECV_TIMEOUT)?;

        println!("  3. inject {} byte(s) on fd {sock_tx}:", case.frame.len());
        println!("       {}", hex_dump(&case.frame));
        send_on(sock_tx, ifindex, &case.frame)?;
        println!("     `lo` loops the frame back to every raw socket bound to it, cbpf-rs's and");
        println!(
            "     tcpdump's included - now waiting up to {}ms on each:",
            RECV_TIMEOUT.as_millis()
        );

        let accepted_by_ours = recv_one(sock_a)?;
        println!(
            "       fd {sock_a} (cbpf-rs) ... {}",
            if accepted_by_ours {
                "ACCEPTED (frame received)"
            } else {
                "REJECTED (timed out)"
            }
        );
        let accepted_by_theirs = recv_one(sock_b)?;
        println!(
            "       fd {sock_b} (tcpdump) ... {}",
            if accepted_by_theirs {
                "ACCEPTED (frame received)"
            } else {
                "REJECTED (timed out)"
            }
        );

        for fd in [sock_a, sock_b, sock_tx] {
            unsafe { libc::close(fd) };
        }
        Ok(accepted_by_ours == accepted_by_theirs)
    }

    /// Formats `bytes` as space-separated hex pairs, wrapped at 16 bytes per line (indented to line
    /// up under the caller's own indentation).
    fn hex_dump(bytes: &[u8]) -> String {
        bytes
            .chunks(16)
            .map(|chunk| {
                chunk
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect::<Vec<_>>()
            .join("\n       ")
    }

    /// Runs `tcpdump -ddd -y EN10MB <filter>` and parses its output (a count line, then one `code jt
    /// jf k` line per instruction - the same numbers a `struct sock_filter` holds) directly into
    /// [`Insn`]s. This is how this tool gets libpcap's *real* compiled bytecode without linking
    /// libpcap itself.
    /// Returns libpcap's compiled bytecode both as [`Insn`]s (to attach) and as the raw `-ddd` text
    /// (to print, so the exact numbers this tool fed into `SO_ATTACH_FILTER` are visible, not just
    /// trusted).
    fn tcpdump_compile(filter: &str) -> Result<(Vec<Insn>, String), Box<dyn Error>> {
        let output = Command::new("tcpdump")
            .args(["-ddd", "-y", "EN10MB", filter])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "tcpdump rejected '{filter}': {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        let text = String::from_utf8(output.stdout)?;
        let mut lines = text.lines();
        let count: usize = lines
            .next()
            .ok_or("empty tcpdump -ddd output")?
            .trim()
            .parse()?;
        let mut insns = Vec::with_capacity(count);
        for line in lines {
            let nums: Vec<&str> = line.split_whitespace().collect();
            let [code, jt, jf, k] = nums[..] else {
                return Err(format!("unexpected tcpdump -ddd line: '{line}'").into());
            };
            insns.push(Insn {
                code: code.parse()?,
                jt: jt.parse()?,
                jf: jf.parse()?,
                k: k.parse()?,
            });
        }
        if insns.len() != count {
            return Err(format!(
                "tcpdump -ddd said {count} instructions but printed {}",
                insns.len()
            )
            .into());
        }
        Ok((insns, text))
    }

    /// The same `SO_ATTACH_FILTER` call as [`cbpf_rs::attach::attach`], but for a raw instruction
    /// slice rather than a [`cbpf_rs::Program`] - there's no public way to wrap arbitrary
    /// (non-`compile()`-produced) instructions in a `Program`, and there doesn't need to be just for
    /// this tool: `Insn` is `#[repr(C)]` and layout-identical to `struct sock_filter` (documented on
    /// [`Insn`] itself), so this is exactly [`cbpf_rs::attach::attach`]'s own body with `&Program`
    /// swapped for `&[Insn]`.
    fn attach_raw(sock_fd: RawFd, insns: &[Insn]) -> io::Result<()> {
        let len: u16 = insns
            .len()
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many instructions"))?;
        let fprog = libc::sock_fprog {
            len,
            filter: insns.as_ptr() as *mut libc::sock_filter,
        };
        // SAFETY: same contract as `cbpf_rs::attach::attach` - `sock_fd` is a live socket owned by
        // this function's caller for the whole call, and `fprog` points at `insns`, which outlives it.
        let ret = unsafe {
            libc::setsockopt(
                sock_fd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &fprog as *const libc::sock_fprog as *const libc::c_void,
                mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn if_nametoindex(name: &str) -> io::Result<u32> {
        let cname = CString::new(name).expect("interface name has no interior NUL");
        // SAFETY: `cname` is a valid, NUL-terminated C string for the whole call.
        let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if index == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(index)
        }
    }

    /// Opens an `AF_PACKET`/`SOCK_RAW` socket bound to `ifindex`, seeing (and, for the injector,
    /// able to send) every ethertype (`ETH_P_ALL`) - `SOCK_RAW`, not `SOCK_DGRAM`, so the socket
    /// sees/sends the link-layer header verbatim, matching what a program compiled for
    /// [`LinkType::Ethernet`] expects at its fixed offsets. Needs `CAP_NET_RAW`.
    fn raw_socket_on(ifindex: u32) -> io::Result<RawFd> {
        // SAFETY: a plain `socket(2)` call; the result is checked below before use.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                htons_c_int(libc::ETH_P_ALL),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let addr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as libc::c_ushort,
            sll_protocol: libc::htons(libc::ETH_P_ALL as u16),
            sll_ifindex: ifindex as libc::c_int,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        // SAFETY: `addr` is a valid `sockaddr_ll` of the size `bind` is told to expect, and `fd` was
        // just created above.
        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }
        Ok(fd)
    }

    /// `libc::ETH_P_ALL` is a `c_int`; `socket(2)`'s protocol argument wants it network-byte-order in
    /// the low 16 bits, same as `sll_protocol` - `libc::htons` only takes `u16`, so this narrows first.
    fn htons_c_int(proto: libc::c_int) -> libc::c_int {
        libc::htons(proto as u16) as libc::c_int
    }

    fn set_recv_timeout(fd: RawFd, timeout: Duration) -> io::Result<()> {
        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: timeout.subsec_micros() as libc::suseconds_t,
        };
        // SAFETY: `tv` is a valid `timeval` of the size `setsockopt` is told to expect.
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Sends `frame` (a complete Ethernet frame, header included - `SOCK_RAW` never adds one) out
    /// `ifindex`. `lo` loops every frame it transmits straight back into its receive path, and
    /// `AF_PACKET` fans a received frame out to every raw socket bound to that interface, so this
    /// single send reaches both `sock_a` and `sock_b` in [`run_case`].
    fn send_on(fd: RawFd, ifindex: u32, frame: &[u8]) -> io::Result<()> {
        let addr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as libc::c_ushort,
            sll_protocol: libc::htons(libc::ETH_P_ALL as u16),
            sll_ifindex: ifindex as libc::c_int,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        // SAFETY: `frame`/`addr` are valid for the whole call, with `addr`'s size matching what's passed.
        let ret = unsafe {
            libc::sendto(
                fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// `true` if a frame arrived before [`RECV_TIMEOUT`] (the filter accepted it), `false` on a
    /// timeout (rejected it); any other error is passed through.
    fn recv_one(fd: RawFd) -> io::Result<bool> {
        let mut buf = [0u8; 256];
        // SAFETY: `buf` is a valid, appropriately-sized buffer for the whole call.
        let ret = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if ret >= 0 {
            Ok(true)
        } else {
            let err = io::Error::last_os_error();
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) {
                Ok(false)
            } else {
                Err(err)
            }
        }
    }

    // ---- Frame builders -------------------------------------------------------------------------
    //
    // Deliberately standalone rather than shared with `tests/differential.rs`'s `Pkt`/`Pkt6`: this
    // tool builds full 14-byte-header-included Ethernet frames to `sendto` directly, not the
    // pcap-file bodies those build for `tcpdump -r`, so the byte layouts (offsets, lengths) are
    // similar but not the same type.

    /// A minimal Ethernet + IPv4 + TCP/UDP frame (all-zero MACs; `lo` doesn't care).
    fn eth_ipv4(ip_proto: u8, src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut f = vec![0u8; 14 + 20 + 8];
        f[12..14].copy_from_slice(&ETH_P_IPV4.to_be_bytes());
        f[14] = 0x45; // version 4, IHL 5
        f[23] = ip_proto;
        f[26..30].copy_from_slice(&src);
        f[30..34].copy_from_slice(&dst);
        f[34..36].copy_from_slice(&src_port.to_be_bytes());
        f[36..38].copy_from_slice(&dst_port.to_be_bytes());
        f
    }

    /// Like [`eth_ipv4`], but with the 13-bit fragment-offset field set to `units_of_8_bytes` (so a
    /// nonzero value marks it as a non-first fragment - see `codegen.rs`'s `emit_not_fragment_gate`).
    fn eth_ipv4_fragment(
        ip_proto: u8,
        src: [u8; 4],
        dst: [u8; 4],
        units_of_8_bytes: u16,
    ) -> Vec<u8> {
        let mut f = eth_ipv4(ip_proto, src, dst, 4000, 80);
        f[20..22].copy_from_slice(&units_of_8_bytes.to_be_bytes());
        f
    }

    /// A minimal Ethernet + IPv4 host/net frame, no transport header needed.
    fn eth_ipv4_bare(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut f = vec![0u8; 14 + 20];
        f[12..14].copy_from_slice(&ETH_P_IPV4.to_be_bytes());
        f[14] = 0x45;
        f[26..30].copy_from_slice(&src);
        f[30..34].copy_from_slice(&dst);
        f
    }

    /// A minimal Ethernet + IPv6 + TCP/UDP frame.
    fn eth_ipv6(next_header: u8, src: &str, dst: &str, src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut f = vec![0u8; 14 + 40 + 8];
        f[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
        f[14] = 0x60; // version 6
        f[20] = next_header;
        f[21] = 64; // hop limit
        f[22..38].copy_from_slice(&src.parse::<Ipv6Addr>().unwrap().octets());
        f[38..54].copy_from_slice(&dst.parse::<Ipv6Addr>().unwrap().octets());
        f[54..56].copy_from_slice(&src_port.to_be_bytes());
        f[56..58].copy_from_slice(&dst_port.to_be_bytes());
        f
    }

    /// A minimal Ethernet + IPv6 host/net frame, no transport header needed.
    fn eth_ipv6_bare(src: &str, dst: &str) -> Vec<u8> {
        let mut f = vec![0u8; 14 + 40];
        f[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
        f[14] = 0x60;
        f[20] = 59; // "no next header"
        f[21] = 64;
        f[22..38].copy_from_slice(&src.parse::<Ipv6Addr>().unwrap().octets());
        f[38..54].copy_from_slice(&dst.parse::<Ipv6Addr>().unwrap().octets());
        f
    }

    const TCP: u8 = 6;
    const UDP: u8 = 17;

    fn build_cases() -> Vec<Case> {
        vec![
            Case {
                filter: "tcp port 80",
                label: "IPv4 dst port 80",
                frame: eth_ipv4(TCP, [10, 0, 0, 1], [10, 0, 0, 2], 4000, 80),
            },
            Case {
                filter: "tcp port 80",
                label: "IPv4 src port 80",
                frame: eth_ipv4(TCP, [10, 0, 0, 1], [10, 0, 0, 2], 80, 4000),
            },
            Case {
                filter: "tcp port 80",
                label: "IPv4, neither port is 80",
                frame: eth_ipv4(TCP, [10, 0, 0, 1], [10, 0, 0, 2], 4000, 4001),
            },
            Case {
                filter: "tcp port 80",
                label: "IPv4 non-first fragment must not match",
                frame: eth_ipv4_fragment(TCP, [10, 0, 0, 1], [10, 0, 0, 2], 1),
            },
            Case {
                filter: "tcp port 80",
                label: "IPv6 dst port 80 (the headline 'level 2' case)",
                frame: eth_ipv6(TCP, "2001:db8::1", "2001:db8::2", 4000, 80),
            },
            Case {
                filter: "tcp port 80",
                label: "IPv6, wrong next header (UDP, not TCP)",
                frame: eth_ipv6(UDP, "2001:db8::1", "2001:db8::2", 4000, 80),
            },
            Case {
                filter: "udp port 53",
                label: "IPv4 dst port 53",
                frame: eth_ipv4(UDP, [10, 0, 0, 1], [8, 8, 8, 8], 4000, 53),
            },
            Case {
                filter: "portrange 8000-8010",
                label: "IPv4, port inside the range",
                frame: eth_ipv4(TCP, [10, 0, 0, 1], [10, 0, 0, 2], 4000, 8004),
            },
            Case {
                filter: "portrange 8000-8010",
                label: "IPv4, port outside the range",
                frame: eth_ipv4(TCP, [10, 0, 0, 1], [10, 0, 0, 2], 4000, 8011),
            },
            Case {
                filter: "ip host 10.0.0.1",
                label: "IPv4 host, matches as src",
                frame: eth_ipv4_bare([10, 0, 0, 1], [10, 0, 0, 2]),
            },
            Case {
                filter: "net 10.0.0.0/8",
                label: "IPv4 net, inside /8",
                frame: eth_ipv4_bare([10, 250, 1, 2], [192, 168, 0, 1]),
            },
            Case {
                filter: "net 10.0.0.0/8",
                label: "IPv4 net, outside /8",
                frame: eth_ipv4_bare([11, 0, 0, 1], [192, 168, 0, 1]),
            },
            Case {
                filter: "ip6 host 2001:db8::1",
                label: "IPv6 host, matches as src",
                frame: eth_ipv6_bare("2001:db8::1", "fe80::9"),
            },
            Case {
                filter: "ip6 net 2001:db8::/32",
                label: "IPv6 net, inside /32",
                frame: eth_ipv6_bare("2001:db8:1234::1", "fe80::9"),
            },
            Case {
                filter: "ip6 net 2001:db8::/32",
                label: "IPv6 net, outside /32",
                frame: eth_ipv6_bare("2001:db9::1", "fe80::9"),
            },
        ]
    }
}
