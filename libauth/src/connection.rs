//! Bounded, nonblocking Unix transport. Every received descriptor is owned,
//! including descriptors rejected on malformed or truncated messages.
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use auth_core::Secret;
use auth_core::frame::{Framing, decode_header};

pub(crate) struct Connection {
    socket: OwnedFd,
    connecting: bool,
    framing: Framing,
    outgoing: Secret,
    sent: usize,
    incoming: Secret,
    received: usize,
    token: Option<OwnedFd>,
    pub submitted: bool,
}

impl Connection {
    pub fn open(path: &Path, framing: Framing, outgoing: Secret) -> io::Result<Self> {
        // SAFETY: socket has no pointer arguments; a successful descriptor is
        // immediately transferred to OwnedFd, including all error paths below.
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a newly created descriptor owned by this function.
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: an all-zero sockaddr_un is valid storage for these fields.
        let mut address: libc::sockaddr_un = unsafe { zeroed() };
        let bytes = path.as_os_str().as_bytes();
        if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Unix socket path",
            ));
        }
        address.sun_family = libc::AF_UNIX as _;
        for (target, byte) in address.sun_path.iter_mut().zip(bytes) {
            *target = *byte as _;
        }
        // SAFETY: address is initialized and its stated size is correct.
        let result = unsafe {
            libc::connect(
                raw,
                (&address as *const libc::sockaddr_un).cast(),
                size_of::<libc::sockaddr_un>() as _,
            )
        };
        let connecting = if result == 0 {
            false
        } else {
            let error = io::Error::last_os_error();
            // AF_UNIX EAGAIN means the listener's queue is full, not a pending
            // connection. Report it without replaying the request.
            if error.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(error);
            }
            true
        };
        Ok(Self {
            socket,
            connecting,
            framing,
            outgoing,
            sent: 0,
            incoming: Secret::zeroed(framing.header_bytes),
            received: 0,
            token: None,
            submitted: false,
        })
    }

    pub fn fd(&self) -> i32 {
        self.socket.as_raw_fd()
    }

    pub fn interests(&self) -> i16 {
        if self.connecting || self.sent < self.outgoing.len() {
            libc::POLLOUT
        } else {
            libc::POLLIN
        }
    }

    pub fn send(&mut self, outgoing: Secret) {
        self.outgoing = outgoing;
        self.sent = 0;
    }

    pub fn step(&mut self) -> io::Result<Option<(Secret, Option<OwnedFd>)>> {
        if self.connecting && !self.finish_connect()? {
            return Ok(None);
        }
        if self.sent < self.outgoing.len() {
            let remaining = &self.outgoing.expose()[self.sent..];
            // SAFETY: remaining is readable for the supplied length; send does
            // not retain it. MSG_NOSIGNAL prevents a process-global SIGPIPE.
            let count = unsafe {
                libc::send(
                    self.fd(),
                    remaining.as_ptr().cast(),
                    remaining.len(),
                    libc::MSG_NOSIGNAL,
                )
            };
            if count < 0 {
                return pending_or_error();
            }
            if count == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            self.submitted = true;
            self.sent += count as usize;
            if self.sent < self.outgoing.len() {
                return Ok(None);
            }
            self.outgoing = Secret::empty();
            self.sent = 0;
        }
        self.receive()
    }

    fn finish_connect(&mut self) -> io::Result<bool> {
        let mut event = libc::pollfd {
            fd: self.fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: event is one initialized pollfd; a zero timeout cannot block.
        let ready = unsafe { libc::poll(&mut event, 1, 0) };
        if ready < 0 {
            return pending_or_error().map(|_: Option<()>| false);
        }
        if ready == 0 {
            return Ok(false);
        }
        let mut error: libc::c_int = 0;
        let mut len = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: error and len are writable for their declared sizes.
        if unsafe {
            libc::getsockopt(
                self.fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut error as *mut libc::c_int).cast(),
                &mut len,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        self.connecting = false;
        Ok(true)
    }

    fn receive(&mut self) -> io::Result<Option<(Secret, Option<OwnedFd>)>> {
        let fd = self.fd();
        let remaining = &mut self.incoming.expose_mut()[self.received..];
        let mut iov = libc::iovec {
            iov_base: remaining.as_mut_ptr().cast(),
            iov_len: remaining.len(),
        };
        // usize storage gives cmsghdr its required alignment.
        let mut control = [0usize; 32];
        // SAFETY: a zero msghdr is valid before the buffer fields are assigned.
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = size_of_val(&control);
        // SAFETY: all message buffers are writable and live through this call.
        let count = unsafe { libc::recvmsg(fd, &mut message, libc::MSG_CMSG_CLOEXEC) };
        if count < 0 {
            return pending_or_error();
        }
        let mut descriptors = Vec::new();
        let mut unexpected = false;
        // SAFETY: the kernel initialized ancillary headers inside control.
        // CMSG_NXTHDR bounds traversal; descriptors are adopted before checking
        // protocol validity so a malformed response cannot leak them.
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                if (*header).cmsg_level == libc::SOL_SOCKET
                    && (*header).cmsg_type == libc::SCM_RIGHTS
                {
                    let payload = (*header)
                        .cmsg_len
                        .saturating_sub(libc::CMSG_LEN(0) as usize);
                    for index in 0..payload / size_of::<i32>() {
                        let raw = std::ptr::read_unaligned(
                            libc::CMSG_DATA(header).cast::<i32>().add(index),
                        );
                        descriptors.push(OwnedFd::from_raw_fd(raw));
                    }
                } else {
                    unexpected = true;
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
        }
        if unexpected
            || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
            || descriptors.len() + usize::from(self.token.is_some()) > 1
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected ancillary data",
            ));
        }
        if let Some(token) = descriptors.pop() {
            self.token = Some(token);
        }
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.received += count as usize;
        if self.received < self.incoming.len() {
            return Ok(None);
        }
        let (_, total) = decode_header(&self.framing, self.incoming.expose())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid response header"))?;
        if self.incoming.len() < total {
            let mut body = Secret::zeroed(total);
            body.expose_mut()[..self.received].copy_from_slice(self.incoming.expose());
            self.incoming = body;
            return Ok(None);
        }
        let data = std::mem::replace(
            &mut self.incoming,
            Secret::zeroed(self.framing.header_bytes),
        );
        self.received = 0;
        Ok(Some((data, self.token.take())))
    }
}

fn pending_or_error<T>() -> io::Result<Option<T>> {
    let error = io::Error::last_os_error();
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(None),
        _ => Err(error),
    }
}
