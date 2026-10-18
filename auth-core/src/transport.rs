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

// SAFETY: CMSG_SPACE computes storage size; the argument is one descriptor.
const CONTROL_BYTES: usize = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) } as usize;

/// A byte buffer whose alignment is explicitly that of an ancillary header.
#[repr(C)]
union ControlBuffer<const N: usize> {
    bytes: [u8; N],
    alignment: libc::cmsghdr,
}

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
    let mut control = ControlBuffer {
        bytes: [0; CONTROL_BYTES],
    };

    let mut iov = libc::iovec {
        iov_base: message.as_ptr() as *mut libc::c_void,
        iov_len: message.len(),
    };

    // SAFETY: zero initializes the optional pointers and lengths; required fields follow.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = (&mut control as *mut ControlBuffer<CONTROL_BYTES>).cast();
    msg.msg_controllen = CONTROL_BYTES as _;

    // SAFETY: control is aligned for cmsghdr and has CMSG_SPACE bytes for one FD.
    // The borrowed descriptor stays open throughout sendmsg.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut libc::c_int, fd.as_raw_fd());
    }

    // SAFETY: message, control, and iov stay valid for the duration of the call.
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
///
/// Reject extra descriptors, unexpected ancillary data, and truncated input.
/// Close every received descriptor if the message cannot be returned successfully.
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
        Some(slot) => *slot = recv_header_with_fd(sock, header)?,
    }

    let (_, total_len) = decode_header(framing, header).map_err(wire_to_io)?;
    let mut buf = Secret::zeroed(total_len);
    buf.expose_mut()[..framing.header_bytes].copy_from_slice(header);
    Ok(buf)
}

/// Adopt every received descriptor before any framing or truncation check.
fn recv_header_with_fd(sock: &UnixStream, header: &mut [u8]) -> io::Result<Option<OwnedFd>> {
    let mut control = ControlBuffer {
        bytes: [0; CONTROL_BYTES],
    };
    let mut iov = libc::iovec {
        iov_base: header.as_mut_ptr().cast(),
        iov_len: header.len(),
    };
    // SAFETY: zero initializes optional pointers and lengths; required fields follow.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = (&mut control as *mut ControlBuffer<CONTROL_BYTES>).cast();
    message.msg_controllen = CONTROL_BYTES as _;
    // SAFETY: all buffers are writable, correctly aligned, and live through the call.
    // MSG_CMSG_CLOEXEC prevents received descriptors from surviving exec.
    let received = unsafe {
        libc::recvmsg(
            sock.as_raw_fd(),
            &mut message,
            libc::MSG_CMSG_CLOEXEC | libc::MSG_WAITALL,
        )
    };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: recvmsg initialized message and the ancillary data in control.
    // Ownership is transferred exactly once, before any early error return.
    let descriptor = unsafe { take_descriptor(&message) }?;
    if (received as usize) < header.len() {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(descriptor)
}

/// Take ownership of the descriptors in a successful recvmsg result.
///
/// # Safety
///
/// The message must reference live, aligned ancillary storage filled by recvmsg.
/// No descriptor in it can have been adopted or closed already.
unsafe fn take_descriptor(message: &libc::msghdr) -> io::Result<Option<OwnedFd>> {
    let mut descriptor = None;
    let mut unexpected = false;
    // SAFETY: the caller supplies kernel-initialized ancillary storage. CMSG_NXTHDR
    // bounds traversal. Every SCM_RIGHTS integer is a newly owned, valid descriptor.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let payload = (*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                for index in 0..payload / size_of::<libc::c_int>() {
                    let raw = std::ptr::read_unaligned(
                        libc::CMSG_DATA(header).cast::<libc::c_int>().add(index),
                    );
                    let received = OwnedFd::from_raw_fd(raw);
                    if descriptor.is_some() {
                        unexpected = true;
                    } else {
                        descriptor = Some(received);
                    }
                }
            } else {
                unexpected = true;
            }
            header = libc::CMSG_NXTHDR(message, header);
        }
    }
    if unexpected || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected ancillary data",
        ));
    }
    Ok(descriptor)
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
            required_credential_type: None,
            ssh_binding: None,

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
            psi::decode_envelope(received.expose())
                .unwrap()
                .conversation,
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

        let granted = encode_access_granted(&AccessGranted {
            session_id: 4242,
            ..Default::default()
        })
        .unwrap();
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

        let granted = encode_access_granted(&AccessGranted {
            session_id: 1,
            ..Default::default()
        })
        .unwrap();
        send_message_with_fd(&a, &granted, pipe_r.as_fd()).expect("send with fd");
        let (_, fd) = recv_message_with_fd(&wire::FRAMING, &b).expect("recv with fd");

        let fd = fd.expect("descriptor");
        // SAFETY: fd is live and F_GETFD takes no additional argument.
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
        let granted = encode_access_granted(&AccessGranted {
            session_id: 7,
            ..Default::default()
        })
        .unwrap();
        send_message(&a, &granted).expect("send");

        let (_, fd) = recv_message_with_fd(&wire::FRAMING, &b).expect("recv");
        assert!(fd.is_none());
    }

    /// Send duplicate references to the same socket endpoint. The peer reaches
    /// EOF only once the receiver has closed every received reference.
    fn send_descriptors(sock: &UnixStream, payload: &[u8], fd: BorrowedFd<'_>, count: usize) {
        const TEST_CONTROL_BYTES: usize = 128;
        let mut control = ControlBuffer {
            bytes: [0; TEST_CONTROL_BYTES],
        };
        let descriptor_bytes = (count * size_of::<libc::c_int>()) as u32;
        // SAFETY: this computes the ancillary storage requirement for count FDs.
        let control_bytes = unsafe { libc::CMSG_SPACE(descriptor_bytes) } as usize;
        assert!(control_bytes <= TEST_CONTROL_BYTES);
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        };
        // SAFETY: zero initializes optional message fields; buffers are set below.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = (&mut control as *mut ControlBuffer<TEST_CONTROL_BYTES>).cast();
        message.msg_controllen = control_bytes as _;
        // SAFETY: the aligned control buffer has space for every descriptor, and
        // fd remains borrowed throughout sendmsg. All buffers outlive the call.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(descriptor_bytes) as _;
            for index in 0..count {
                std::ptr::write_unaligned(
                    libc::CMSG_DATA(header).cast::<libc::c_int>().add(index),
                    fd.as_raw_fd(),
                );
            }
            assert_eq!(
                libc::sendmsg(sock.as_raw_fd(), &message, libc::MSG_NOSIGNAL),
                payload.len() as isize,
            );
        }
    }

    fn rejected_message_closes_descriptors(payload: &[u8], count: usize, kind: io::ErrorKind) {
        let (sender, receiver) = UnixStream::pair().expect("message socketpair");
        let (descriptor, mut peer) = UnixStream::pair().expect("descriptor socketpair");
        send_descriptors(&sender, payload, descriptor.as_fd(), count);
        drop(descriptor);
        drop(sender);
        let error = recv_message_with_fd(&wire::FRAMING, &receiver).expect_err("invalid message");
        assert_eq!(error.kind(), kind);
        peer.set_nonblocking(true).expect("nonblocking peer");
        assert_eq!(
            peer.read(&mut [0])
                .expect("a leaked descriptor keeps the peer open"),
            0,
        );
    }

    #[test]
    fn multiple_descriptors_are_rejected_and_closed() {
        let payload = encode_logon_start(&start()).expect("valid message");
        rejected_message_closes_descriptors(&payload, 2, io::ErrorKind::InvalidData);
    }

    #[test]
    fn truncated_ancillary_data_is_rejected_and_closed() {
        let payload = encode_logon_start(&start()).expect("valid message");
        rejected_message_closes_descriptors(&payload, 8, io::ErrorKind::InvalidData);
    }

    #[test]
    fn short_header_closes_received_descriptor() {
        rejected_message_closes_descriptors(b"P", 1, io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn malformed_header_closes_received_descriptor() {
        rejected_message_closes_descriptors(b"XXXXXXXXXXXX", 1, io::ErrorKind::InvalidData);
    }

    #[test]
    fn short_body_closes_received_descriptor() {
        let payload = encode_logon_start(&start()).expect("valid message");
        rejected_message_closes_descriptors(
            &payload[..wire::FRAMING.header_bytes],
            1,
            io::ErrorKind::UnexpectedEof,
        );
    }

    #[test]
    fn garbage_header_is_rejected() {
        let (a, b) = UnixStream::pair().expect("socketpair");
        send_message(&a, b"XXXXXXXXXXXX").expect("send");
        let error = recv_message(&wire::FRAMING, &b).expect_err("must reject");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
