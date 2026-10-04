//! lpsd's self socket (PSPU §10.11): one's own account, and one's own display
//! name.
//!
//! Every authenticated principal may use it, and no request names anybody:
//! lpsd answers about the user of the caller's token. So [`Own::show`] is the
//! caller's own account — name, display name, credential policy, whether a
//! password is set, and SSH keys — and [`Own::set_display_name`] sets the
//! caller's own display name, with no password asked, since a display name is
//! not a credential.
//!
//! Adding or removing a key is not here: it re-proves the current password,
//! so it goes through the logon socket. See [`crate::credential`].
//!
//! Refusals are PLPS's, as on the admin socket: [`Refusal`], with lpsd's
//! [`Failure`](libauthd::lps::Failure) where it gave one. A caller lpsd holds
//! no account for — SYSTEM, a directory principal — is refused `NotFound`.

use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use libauthd::lps::{self, Failure};
use libauthd::transport::{recv_message, send_message};
use libauthd::{LPSD_SELF_SOCKET_PATH, WireError};

pub use crate::admin::Refusal;
pub use libauthd::credential::Policy;
pub use libauthd::lps::{OwnAccount, OwnKey};

/// lpsd serves the self socket without blocking, with a five-second deadline
/// a connection, so an answer is quick or not coming.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The self socket.
#[derive(Debug, Clone)]
pub struct Own {
    path: PathBuf,
}

impl Default for Own {
    fn default() -> Own {
        Own::new()
    }
}

impl Own {
    /// The self socket where it is: [`LPSD_SELF_SOCKET_PATH`].
    pub fn new() -> Own {
        Own::at(LPSD_SELF_SOCKET_PATH)
    }

    /// A self socket at `path`: for tests, and nothing else.
    pub fn at(path: impl AsRef<Path>) -> Own {
        Own {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// The caller's own account.
    pub fn show(&self) -> Result<OwnAccount, Refusal> {
        let reply = self.ask(lps::encode_show_self())?;
        lps::decode_self(&reply).map_err(unreadable)
    }

    /// Set the caller's own display name; empty clears it. Validated as an
    /// administrator's would be: trimmed, at most 256 bytes, no NUL.
    pub fn set_display_name(&self, display_name: &str) -> Result<(), Refusal> {
        let reply = self.ask(lps::encode_set_display_name(&lps::SetDisplayName {
            display_name: display_name.to_string(),
        }))?;
        lps::decode_done(&reply).map_err(unreadable)
    }

    fn ask(&self, request: Result<Vec<u8>, WireError>) -> Result<Vec<u8>, Refusal> {
        let request = request.map_err(|error| {
            unreached(format!("could not encode the request: {error:?}"))
        })?;
        let at = self.path.display();
        let stream = UnixStream::connect(&self.path).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
                unreached(format!("cannot reach lpsd on {at}: it does not appear to be running"))
            }
            io::ErrorKind::PermissionDenied => Refusal {
                failure: Some(Failure::Denied),
                reason: format!("cannot reach lpsd on {at}: permission denied"),
            },
            _ => unreached(format!("cannot reach lpsd on {at}: {error}")),
        })?;
        stream
            .set_read_timeout(Some(TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(TIMEOUT)))
            .map_err(|error| unreached(format!("could not configure the connection: {error}")))?;
        send_message(&stream, &request)
            .map_err(|error| unreached(format!("could not send the request: {error}")))?;
        let received = recv_message(&lps::FRAMING, &stream).map_err(|error| {
            unreached(match error.kind() {
                io::ErrorKind::UnexpectedEof => {
                    "lpsd closed the connection without answering".to_string()
                }
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                    "lpsd did not answer in time".to_string()
                }
                _ => format!("could not read the answer: {error}"),
            })
        })?;
        let bytes = received.expose().to_vec();
        let (msg_type, _) = lps::decode_type(&bytes).map_err(unreadable)?;
        if msg_type == lps::MSG_FAILED {
            let failed = lps::decode_failed(&bytes).map_err(unreadable)?;
            return Err(Refusal {
                failure: Some(failed.failure),
                reason: failed.reason,
            });
        }
        Ok(bytes)
    }
}

fn unreached(reason: String) -> Refusal {
    Refusal {
        failure: None,
        reason,
    }
}

fn unreadable(error: WireError) -> Refusal {
    unreached(format!("lpsd sent something unreadable: {error:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc;

    /// A stand-in lpsd answering each connection with `answer` of the request.
    fn stand_in(
        answer: impl Fn(&[u8]) -> Vec<u8> + Send + 'static,
    ) -> (Own, PathBuf, mpsc::Receiver<u16>) {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "libauthd-client-own-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("self.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (asked, heard) = mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let Ok(received) = recv_message(&lps::FRAMING, &stream) else {
                    continue;
                };
                let (kind, _) = lps::decode_type(received.expose()).unwrap();
                let _ = asked.send(kind);
                let _ = send_message(&stream, &answer(received.expose()));
            }
        });
        (Own::at(&path), dir, heard)
    }

    fn account() -> OwnAccount {
        OwnAccount {
            name: "alice".into(),
            sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
            display_name: "Alice".into(),
            enabled: true,
            policy: Policy::PasswordOrKey,
            has_password: true,
            keys: Vec::new(),
        }
    }

    #[test]
    fn show_asks_and_returns_the_account() {
        let (own, dir, heard) = stand_in(|_| lps::encode_self(&account()).unwrap());
        assert_eq!(own.show().unwrap(), account());
        assert_eq!(heard.recv().unwrap(), lps::MSG_SHOW_SELF);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn set_display_name_sends_the_name_and_reads_done() {
        let (own, dir, heard) = stand_in(|request| {
            let set = lps::decode_set_display_name(request).unwrap();
            assert_eq!(set.display_name, "Alice Liddell");
            lps::encode_done().unwrap()
        });
        own.set_display_name("Alice Liddell").unwrap();
        assert_eq!(heard.recv().unwrap(), lps::MSG_SET_DISPLAY_NAME);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_refusal_carries_lpsds_failure_and_words() {
        let (own, dir, _heard) = stand_in(|_| {
            lps::encode_failed(&lps::Failed {
                failure: Failure::NotFound,
                reason: "This account is not one this machine holds.".into(),
            })
            .unwrap()
        });
        let refusal = own.show().unwrap_err();
        assert_eq!(refusal.failure, Some(Failure::NotFound));
        assert_eq!(refusal.to_string(), "This account is not one this machine holds.");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_absent_lpsd_is_unreached() {
        let refusal = Own::at("/nonexistent/self.sock").show().unwrap_err();
        assert_eq!(refusal.failure, None);
        assert!(refusal.reason.contains("does not appear to be running"));
    }
}
