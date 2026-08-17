//! One connection to lpsd, carrying one request.
//!
//! The protocol is one exchange per connection, so this is deliberately not a
//! long-lived client object: it connects, asks, reads the answer, and is
//! dropped. Nothing is retried — a refusal is an answer, and a daemon that is
//! not there will not be there a moment later either.

use std::io;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use libauthd::lps;
use libauthd::transport::{recv_message, send_message};
use libauthd::{LPSD_ADMIN_SOCKET_PATH, Secret, WireError};

/// How long to wait for lpsd to answer.
///
/// Generous, because a password change makes the daemon derive an argon2id
/// verifier — tens of milliseconds — and because the daemon serves logons on
/// the same thread, so a request can legitimately queue behind one.
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Session {
    stream: UnixStream,
}

impl Session {
    pub fn open() -> Result<Self, String> {
        let stream = UnixStream::connect(LPSD_ADMIN_SOCKET_PATH).map_err(|error| {
            match error.kind() {
                // By far the most common failure, and the least self-explanatory
                // — the socket only exists while lpsd is running.
                io::ErrorKind::NotFound => format!(
                    "cannot reach lpsd on {LPSD_ADMIN_SOCKET_PATH}: it does not appear to be running"
                ),
                io::ErrorKind::PermissionDenied => format!(
                    "cannot reach lpsd on {LPSD_ADMIN_SOCKET_PATH}: permission denied"
                ),
                _ => format!("cannot reach lpsd on {LPSD_ADMIN_SOCKET_PATH}: {error}"),
            }
        })?;

        stream
            .set_read_timeout(Some(REPLY_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(SEND_TIMEOUT)))
            .map_err(|error| format!("could not configure the connection: {error}"))?;

        Ok(Self { stream })
    }

    /// Send one request and read the answer.
    ///
    /// A [`lps::MSG_FAILED`] reply is turned into an error here, so every caller
    /// deals with one failure path rather than remembering to check for it.
    pub fn request(&mut self, message: &[u8]) -> Result<Secret, String> {
        send_message(&self.stream, message)
            .map_err(|error| format!("could not send the request: {error}"))?;

        let received = recv_message(&lps::FRAMING, &self.stream).map_err(|error| {
            match error.kind() {
                io::ErrorKind::UnexpectedEof => {
                    "lpsd closed the connection without answering".to_string()
                }
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                    "lpsd did not answer in time".to_string()
                }
                _ => format!("could not read the answer: {error}"),
            }
        })?;

        let (msg_type, _) = lps::decode_type(received.expose())
            .map_err(|error| format!("lpsd sent something unreadable: {error:?}"))?;

        if msg_type == lps::MSG_FAILED {
            let failed = lps::decode_failed(received.expose())
                .map_err(|error| format!("lpsd sent an unreadable refusal: {error:?}"))?;
            return Err(crate::describe(failed.failure, &failed.reason));
        }

        Ok(received)
    }

    /// Decode a reply, blaming the daemon rather than the caller if it will not
    /// parse — by this point the request was accepted, so a decode failure is a
    /// version mismatch or a bug, not bad input.
    pub fn expect<T>(&self, decoded: Result<T, WireError>) -> Result<T, String> {
        decoded.map_err(|error| {
            format!("lpsd's answer was not the one expected ({error:?}); versions may differ")
        })
    }
}
