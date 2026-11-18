//! A diagnostic span for the thread serving one PGSS connection.
//!
//! It contains no identity, authority or credential material. Scope restoration
//! prevents accidental reuse when tests or a future worker serve another peer.
use crate::audit::Record;
use std::{
    cell::Cell,
    io,
    os::{fd::BorrowedFd, unix::net::UnixStream},
};

thread_local! { static CURRENT: Cell<Option<[u8;16]>> = const { Cell::new(None) }; }
pub(crate) struct Scope(Option<[u8; 16]>);
impl Scope {
    pub(crate) fn new() -> Self {
        let mut bytes = [0u8; 16];
        // A diagnostic span must not wait for CRNG seeding or change auth policy.
        // SAFETY: bytes is an exclusively borrowed 16-byte output buffer.
        let read =
            unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), libc::GRND_NONBLOCK) };
        let guid = (read == 16).then(|| {
            let mut guid = bytes;
            // PCDS GUID byte layout stores the first three components little endian.
            guid[7] = (guid[7] & 15) | 0x40;
            guid[8] = (guid[8] & 63) | 0x80;
            guid
        });
        Self(CURRENT.replace(guid))
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        CURRENT.set(self.0);
    }
}

pub(crate) fn record() -> Record {
    let mut record = Record::new();
    if let Some(guid) = CURRENT.get() {
        record.bin("object.authentication.operation.guid", &guid);
    }
    record
}

fn decorate(message: &[u8]) -> Option<auth_core::Secret> {
    CURRENT
        .get()
        .and_then(|id| auth_core::correlation::with_operation_guid(message, &id).ok())
}

pub(crate) fn send_message(stream: &UnixStream, message: &[u8]) -> io::Result<()> {
    let decorated = decorate(message);
    // Diagnostic size/randomness failures never change the authentication result.
    auth_core::transport::send_message(stream, decorated.as_ref().map_or(message, |v| v.expose()))
}

pub(crate) fn send_authenticated(
    stream: &UnixStream,
    message: &[u8],
    binding: Option<&auth_core::credential_binding::CredentialBinding>,
) -> io::Result<()> {
    let decorated = decorate(message);
    let message = decorated.as_ref().map_or(message, |v| v.expose());
    let bound = binding
        .map(|binding| auth_core::credential_binding::with_authenticated_binding(message, binding))
        .transpose()
        .map_err(|_| io::Error::other("invalid authenticated credential metadata"))?;
    auth_core::transport::send_message(stream, bound.as_ref().map_or(message, |v| v.expose()))
}
pub(crate) fn send_message_with_fd(
    stream: &UnixStream,
    message: &[u8],
    fd: BorrowedFd<'_>,
) -> io::Result<()> {
    let decorated = decorate(message);
    auth_core::transport::send_message_with_fd(
        stream,
        decorated.as_ref().map_or(message, |v| v.expose()),
        fd,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reply_and_audit_use_the_authoritys_span_not_upstream_metadata() {
        use auth_core::{correlation, wire};
        let _scope = Scope::new();
        let actual = CURRENT.get().unwrap();
        let upstream = correlation::with_operation_guid(
            &wire::encode_credential_request(&wire::CredentialRequest {
                messages: vec![],
                prompts: vec![],
            })
            .unwrap(),
            &[9; 16],
        )
        .unwrap();
        let request = wire::decode_credential_request(upstream.expose()).unwrap();
        let (sender, receiver) = UnixStream::pair().unwrap();
        send_message(&sender, &wire::encode_credential_request(&request).unwrap()).unwrap();
        let received = auth_core::transport::recv_message(&wire::FRAMING, &receiver).unwrap();
        assert_eq!(
            correlation::reply_operation_guid(received.expose()),
            Ok(Some(actual))
        );
        assert_eq!(
            record().get("object.authentication.operation.guid"),
            Some(&crate::audit::Value::Bin(actual.to_vec()))
        );
    }
    #[test]
    fn connection_scopes_restore_and_do_not_leak_to_other_threads() {
        assert!(CURRENT.get().is_none());
        let a = Scope::new();
        let first = CURRENT.get().unwrap();
        {
            let _b = Scope::new();
            assert_ne!(CURRENT.get(), Some(first));
            assert!(
                std::thread::spawn(|| CURRENT.get())
                    .join()
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(CURRENT.get(), Some(first));
        drop(a);
        assert!(CURRENT.get().is_none());
    }
}
