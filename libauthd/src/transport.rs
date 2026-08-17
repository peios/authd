//! Moving messages over a Unix socket, and a token file descriptor with them.
//!
//! Two jobs the codec deliberately does not do: framing a message off a stream,
//! and passing a file descriptor. Both are easy to get subtly wrong, and both
//! are needed identically by an authority and a client — so they live here
//! once, rather than twice in two crates that sit on opposite sides of a trust
//! boundary.
//!
//! Everything here is parameterised by a [`Framing`], so PGSS Logon and PSI
//! share it. A reader must be told which protocol it is reading; that is not a
//! nuisance but the point, since the magic check is what stops a socket plugged
//! into the wrong daemon from half-working.
//!
//! ## Received buffers are always [`Secret`]
//!
//! [`recv_message`] returns a self-wiping buffer even for messages that carry
//! nothing sensitive. A reader cannot know what it is holding until it has
//! decoded it, and by then an ordinary buffer would already exist. Wiping
//! unconditionally costs a memset per message and removes the question.
//!
//! ## Received descriptors are always `O_CLOEXEC`
//!
//! [`recv_message_with_fd`] passes `MSG_CMSG_CLOEXEC`, so a token descriptor
//! cannot survive into an `exec`'d program by default. This matters directly:
//! `login` receives a token, installs it, and execs a shell — and a leaked
//! token descriptor in that shell would be a handle onto the user's identity
//! that outlives the code entitled to hold it. Making it the kernel's job
//! rather than a `close()` we must remember is the difference between a
//! property and an intention.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

use crate::frame::{Framing, WireError, decode_header};
use crate::secret::Secret;

/// Enough for any protocol's header. Both are well under this; the constant
/// exists so the header can be read into the stack rather than a heap buffer.
const MAX_HEADER_BYTES: usize = 32;

/// Write a complete message.
pub fn send_message(sock: &UnixStream, message: &[u8]) -> io::Result<()> {
    (&mut &*sock).write_all(message)
}

/// Write a complete message with a file descriptor attached as `SCM_RIGHTS`.
///
/// The descriptor rides with the message's first byte, so a peer that reads any
/// of the message receives it.
pub fn send_message_with_fd(
    sock: &UnixStream,
    message: &[u8],
    fd: BorrowedFd<'_>,
) -> io::Result<()> {
    if message.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot attach a descriptor to an empty message",
        ));
    }

    // Ancillary buffer for exactly one descriptor.
    let mut control = [0u8; unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) } as usize];

    let mut iov = libc::iovec {
        iov_base: message.as_ptr() as *mut libc::c_void,
        iov_len: message.len(),
    };

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.len() as _;

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut libc::c_int, fd.as_raw_fd());
    }

    let sent = unsafe { libc::sendmsg(sock.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    // sendmsg may write fewer bytes than asked. The descriptor went with the
    // first byte, so the remainder is ordinary data.
    let sent = sent as usize;
    if sent < message.len() {
        (&mut &*sock).write_all(&message[sent..])?;
    }
    Ok(())
}

/// Read one complete message of `framing`'s protocol, framed by its own
/// `total_len`.
pub fn recv_message(framing: &Framing, sock: &UnixStream) -> io::Result<Secret> {
    let mut buf = recv_header(framing, sock, None)?;
    fill_body(framing, sock, &mut buf)?;
    Ok(buf)
}

/// Read one complete message, collecting a descriptor if the peer attached one.
pub fn recv_message_with_fd(
    framing: &Framing,
    sock: &UnixStream,
) -> io::Result<(Secret, Option<OwnedFd>)> {
    let mut received = None;
    let mut buf = recv_header(framing, sock, Some(&mut received))?;
    fill_body(framing, sock, &mut buf)?;
    Ok((buf, received))
}

/// Read the header, allocate for the whole message, and return the buffer with
/// the header already in place.
///
/// When `fd_out` is supplied this uses `recvmsg`, so any `SCM_RIGHTS` the peer
/// attached to the message's first byte is collected here.
fn recv_header(
    framing: &Framing,
    sock: &UnixStream,
    fd_out: Option<&mut Option<OwnedFd>>,
) -> io::Result<Secret> {
    debug_assert!(framing.header_bytes <= MAX_HEADER_BYTES);
    let mut storage = [0u8; MAX_HEADER_BYTES];
    let header = &mut storage[..framing.header_bytes];

    match fd_out {
        None => (&mut &*sock).read_exact(header)?,
        Some(slot) => {
            let mut control =
                [0u8; unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) } as usize];
            let mut iov = libc::iovec {
                iov_base: header.as_mut_ptr() as *mut libc::c_void,
                iov_len: header.len(),
            };
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = control.len() as _;

            // MSG_CMSG_CLOEXEC: a token descriptor must not survive exec.
            let got = unsafe {
                libc::recvmsg(
                    sock.as_raw_fd(),
                    &mut msg,
                    libc::MSG_CMSG_CLOEXEC | libc::MSG_WAITALL,
                )
            };
            if got < 0 {
                return Err(io::Error::last_os_error());
            }
            if (got as usize) < header.len() {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }

            unsafe {
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                if !cmsg.is_null()
                    && (*cmsg).cmsg_level == libc::SOL_SOCKET
                    && (*cmsg).cmsg_type == libc::SCM_RIGHTS
                {
                    let raw = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const libc::c_int);
                    *slot = Some(OwnedFd::from_raw_fd(raw));
                }
            }
        }
    }

    let (_, total_len) = decode_header(framing, header).map_err(wire_to_io)?;
    let mut buf = Secret::zeroed(total_len);
    buf.expose_mut()[..framing.header_bytes].copy_from_slice(header);
    Ok(buf)
}

fn fill_body(framing: &Framing, sock: &UnixStream, buf: &mut Secret) -> io::Result<()> {
    let total = buf.len();
    if total > framing.header_bytes {
        (&mut &*sock).read_exact(&mut buf.expose_mut()[framing.header_bytes..total])?;
    }
    Ok(())
}

fn wire_to_io(error: WireError) -> io::Error {
    let message = match error {
        WireError::BadMagic => "not a message of this protocol",
        WireError::UnsupportedVersion(_) => "unsupported protocol version",
        WireError::TooLong => "message exceeds the protocol maximum",
        _ => "malformed message header",
    };
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psi;
    use crate::wire::{
        self, AccessGranted, CredentialType, IdentifierType, LogonStart, LogonType,
        decode_access_granted, decode_logon_start, encode_access_granted, encode_logon_start,
    };
    use std::os::fd::AsFd;

    fn start() -> LogonStart {
        LogonStart {
            logon_type: LogonType::Interactive,
            identifier_type: IdentifierType::Username,
            identifier: b"jack".to_vec(),
            tty: Some("/dev/console".into()),
            remote_host: None,
            supported_credential_types: vec![CredentialType::Password],
        }
    }

    #[test]
    fn message_round_trips_over_a_socket() {
        let (a, b) = UnixStream::pair().expect("socketpair");
        send_message(&a, &encode_logon_start(&start()).unwrap()).expect("send");
        let received = recv_message(&wire::FRAMING, &b).expect("recv");
        let decoded = decode_logon_start(received.expose()).expect("decode");
        assert_eq!(decoded.identifier, b"jack");
    }

    /// A twenty-byte PSI header must be framed as correctly as a twelve-byte
    /// PGSS Logon one — the transport reads `framing.header_bytes`, not a
    /// constant.
    #[test]
    fn psi_messages_round_trip_over_a_socket() {
        let (a, b) = UnixStream::pair().expect("socketpair");
        let message = psi::encode_authenticate(
            9,
            &psi::Authenticate {
                start: start(),
                originator: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
            },
        )
        .unwrap();

        send_message(&a, &message).expect("send");
        let received = recv_message(&psi::FRAMING, &b).expect("recv");
        assert_eq!(
            psi::decode_envelope(received.expose()).unwrap().conversation,
            9
        );
        assert_eq!(
            psi::decode_authenticate(received.expose())
                .unwrap()
                .start
                .identifier,
            b"jack"
        );
    }

    /// Reading with the wrong protocol's framing must fail, not silently
    /// misparse. This is the guarantee the distinct magics exist to provide.
    #[test]
    fn a_message_read_with_the_wrong_framing_is_rejected() {
        let (a, b) = UnixStream::pair().expect("socketpair");
        send_message(&a, &encode_logon_start(&start()).unwrap()).expect("send");
        let error = recv_message(&psi::FRAMING, &b).expect_err("must reject");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn descriptor_travels_with_its_message() {
        let (a, b) = UnixStream::pair().expect("socketpair");
        // Any descriptor will do; a socketpair end is convenient and cheap.
        let (pipe_r, _pipe_w) = UnixStream::pair().expect("socketpair");

        let granted = encode_access_granted(&AccessGranted { session_id: 4242, ..Default::default() }).unwrap();
        send_message_with_fd(&a, &granted, pipe_r.as_fd()).expect("send with fd");

        let (received, fd) = recv_message_with_fd(&wire::FRAMING, &b).expect("recv with fd");
        let decoded = decode_access_granted(received.expose()).expect("decode");
        assert_eq!(decoded.session_id, 4242);
        assert!(fd.is_some(), "descriptor must arrive with the message");
    }

    #[test]
    fn received_descriptor_is_cloexec() {
        let (a, b) = UnixStream::pair().expect("socketpair");
        let (pipe_r, _pipe_w) = UnixStream::pair().expect("socketpair");

        let granted = encode_access_granted(&AccessGranted { session_id: 1, ..Default::default() }).unwrap();
        send_message_with_fd(&a, &granted, pipe_r.as_fd()).expect("send with fd");
        let (_, fd) = recv_message_with_fd(&wire::FRAMING, &b).expect("recv with fd");

        let fd = fd.expect("descriptor");
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0, "fcntl failed");
        assert_eq!(
            flags & libc::FD_CLOEXEC,
            libc::FD_CLOEXEC,
            "a token descriptor must not survive exec"
        );
    }

    #[test]
    fn absent_descriptor_is_reported_as_none() {
        let (a, b) = UnixStream::pair().expect("socketpair");
        let granted = encode_access_granted(&AccessGranted { session_id: 7, ..Default::default() }).unwrap();
        send_message(&a, &granted).expect("send");

        let (_, fd) = recv_message_with_fd(&wire::FRAMING, &b).expect("recv");
        assert!(fd.is_none());
    }

    #[test]
    fn garbage_header_is_rejected() {
        let (a, b) = UnixStream::pair().expect("socketpair");
        send_message(&a, b"XXXXXXXXXXXX").expect("send");
        let error = recv_message(&wire::FRAMING, &b).expect_err("must reject");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
