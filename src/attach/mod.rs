//! Attaching a compiled [`Program`] to a live Linux socket, via `setsockopt(SOL_SOCKET, SO_ATTACH_FILTER)`.
//!

use crate::Program;
use core::mem;
use std::io;
use std::os::unix::io::RawFd;

/// Attach `program` to `sock_fd` so the kernel starts filtering packets read from that socket through it.
///
/// `sock_fd` must name an open, valid socket file descriptor; this function neither creates nor takes ownership of one.
pub fn attach(sock_fd: RawFd, program: &Program) -> io::Result<()> {
    let insns = program.instructions();
    let len: u16 = insns.len().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "program has more than u16::MAX instructions",
        )
    })?;

    let fprog = libc::sock_fprog {
        len,
        // `Insn` is `#[repr(C)]` and layout-identical to `libc::sock_filter` (`code: u16, jt: u8, jf: u8, k: u32`),
        // so this is a plain pointer cast - no copying or field-by-field conversion.
        filter: insns.as_ptr() as *mut libc::sock_filter,
    };

    // SAFETY: `sock_fd` is asserted by the caller to be a valid, open socket descriptor, matching `setsockopt`'s contract.
    // `fprog.filter` points into `insns`, which is borrowed from `program` and so stays alive for the whole call,
    // and `fprog.len` is exactly `insns.len()`, matching what `SO_ATTACH_FILTER` will read.
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

// cargo test --features attach attach
#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::{Insn, KEEP_WHOLE_PACKET};
    use std::fs::File;
    use std::net::UdpSocket;
    use std::os::unix::io::AsRawFd;
    use std::time::Duration;

    /// Accepts a datagram only if its first payload byte is `b'A'`.
    /// An UDP socket's filter sees the datagram starting at the UDP header, so the payload begins at offset 8.
    fn accept_payload_a() -> Program {
        Program::from_validated(vec![
            Insn::ldb_abs(8),
            Insn::jeq(b'A' as u32, 0, 1),
            Insn::ret(KEEP_WHOLE_PACKET),
            Insn::ret(0),
        ])
    }

    /// A pair of loopback UDP sockets: the receiver (with a short read timeout) and a sender already connected to it.
    fn udp_pair() -> (UdpSocket, UdpSocket) {
        let rx = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        rx.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        tx.connect(rx.local_addr().unwrap()).unwrap();
        (rx, tx)
    }

    #[test]
    fn attach_succeeds_on_a_real_socket() {
        let (rx, _tx) = udp_pair();
        attach(rx.as_raw_fd(), &accept_payload_a()).expect("attach");
    }

    #[test]
    fn attached_filter_drops_non_matching_and_keeps_matching_packets() {
        let (rx, tx) = udp_pair();
        attach(rx.as_raw_fd(), &accept_payload_a()).expect("attach");

        // Sent first, must be dropped by the kernel; only the `A` datagram may come through.
        tx.send(b"Bxxx").unwrap();
        tx.send(b"Axxx").unwrap();

        let mut buf = [0u8; 16];
        let n = rx
            .recv(&mut buf)
            .expect("the matching datagram is delivered");
        assert_eq!(&buf[..n], b"Axxx");

        let err = rx
            .recv(&mut buf)
            .expect_err("the non-matching datagram was dropped");
        assert!(matches!(
            err.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
    }

    #[test]
    fn invalid_fd_is_reported_as_an_os_error() {
        let err = attach(-1, &accept_payload_a()).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EBADF));
    }

    #[test]
    fn non_socket_fd_is_reported_as_an_os_error() {
        let file = File::open("/dev/null").unwrap();
        let err = attach(file.as_raw_fd(), &accept_payload_a()).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENOTSOCK));
    }

    #[test]
    fn program_longer_than_u16_max_is_rejected_before_the_syscall() {
        let insns = (0..=u16::MAX as usize).map(|_| Insn::ret(0)).collect();
        let program = Program::from_validated(insns);
        // The fd is never touched: the length check fails first, so even -1 gives InvalidInput.
        let err = attach(-1, &program).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
