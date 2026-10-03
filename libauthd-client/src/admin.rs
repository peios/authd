//! lpsd's admin socket: PLPS, PSPU §10.
//!
//! One request a connection, answered once, with its own reply or with
//! [`lps::MSG_FAILED`]. [`Admin`] opens a connection for each request, so it
//! may be kept for as long as a program likes: nothing it holds goes stale.

use std::fmt;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use libauthd::credential::Policy;
use libauthd::lps::{self, Failure};
use libauthd::transport::{recv_message, send_message};
use libauthd::{LPSD_ADMIN_SOCKET_PATH, Secret, WireError};

/// How long lpsd is given to answer.
///
/// Generous, because a password change makes the daemon derive an argon2id
/// verifier, and because the daemon serves logons on the same thread, so a
/// request can queue behind one.
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a request came to nothing: lpsd's refusal, with its code, or a
/// connection that failed, with none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// lpsd's code, for a caller that branches on it; `None` where lpsd
    /// wasn't reached or its answer couldn't be read.
    pub failure: Option<Failure>,
    /// What went wrong, to be shown rather than interpreted.
    pub reason: String,
}

impl Refusal {
    fn unreached(reason: impl Into<String>) -> Refusal {
        Refusal { failure: None, reason: reason.into() }
    }

    /// Whether lpsd refused the caller, as opposed to the request.
    pub fn denied(&self) -> bool {
        self.failure == Some(Failure::Denied)
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for Refusal {}

/// lpsd's admin socket.
#[derive(Debug, Clone)]
pub struct Admin {
    path: PathBuf,
}

impl Default for Admin {
    fn default() -> Admin {
        Admin::new()
    }
}

impl Admin {
    /// lpsd's admin socket where it is: [`LPSD_ADMIN_SOCKET_PATH`].
    pub fn new() -> Admin {
        Admin::at(LPSD_ADMIN_SOCKET_PATH)
    }

    /// An admin socket at `path`: for tests, and nothing else.
    pub fn at(path: impl AsRef<Path>) -> Admin {
        Admin { path: path.as_ref().to_path_buf() }
    }

    fn connect(&self) -> Result<UnixStream, Refusal> {
        let at = self.path.display();
        let stream = UnixStream::connect(&self.path).map_err(|error| {
            Refusal::unreached(match error.kind() {
                // By far the most common failure, and the least
                // self-explanatory: the socket exists only while lpsd runs.
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
                    format!("cannot reach lpsd on {at}: it does not appear to be running")
                }
                io::ErrorKind::PermissionDenied => format!("cannot reach lpsd on {at}: permission denied"),
                _ => format!("cannot reach lpsd on {at}: {error}"),
            })
        })?;
        stream
            .set_read_timeout(Some(REPLY_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(SEND_TIMEOUT)))
            .map_err(|error| Refusal::unreached(format!("could not configure the connection: {error}")))?;
        Ok(stream)
    }

    /// Sends one request and reads its answer. A refusal comes back as an
    /// error, so that every caller has one failure path.
    pub fn request(&self, message: &[u8]) -> Result<Secret, Refusal> {
        let stream = self.connect()?;
        send_message(&stream, message).map_err(|error| Refusal::unreached(format!("could not send the request: {error}")))?;
        let received = recv_message(&lps::FRAMING, &stream).map_err(|error| {
            Refusal::unreached(match error.kind() {
                io::ErrorKind::UnexpectedEof => "lpsd closed the connection without answering".to_string(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => "lpsd did not answer in time".to_string(),
                _ => format!("could not read the answer: {error}"),
            })
        })?;
        let (msg_type, _) =
            lps::decode_type(received.expose()).map_err(|error| Refusal::unreached(format!("lpsd sent something unreadable: {error:?}")))?;
        if msg_type == lps::MSG_FAILED {
            let failed = lps::decode_failed(received.expose())
                .map_err(|error| Refusal::unreached(format!("lpsd sent an unreadable refusal: {error:?}")))?;
            return Err(Refusal { failure: Some(failed.failure), reason: failed.reason });
        }
        Ok(received)
    }

    /// Sends `message` and decodes the answer with `decode`.
    fn ask<T>(&self, message: Result<Vec<u8>, WireError>, decode: impl FnOnce(&[u8]) -> Result<T, WireError>) -> Result<T, Refusal> {
        let reply = self.request(&encoded(message)?)?;
        expect(decode(reply.expose()))
    }

    /// Sends an encoded request whose answer is only that it was done.
    pub fn done(&self, message: Result<Vec<u8>, WireError>) -> Result<(), Refusal> {
        self.ask(message, lps::decode_done)
    }

    /// Every principal in the store.
    pub fn list(&self) -> Result<Vec<lps::Summary>, Refusal> {
        self.ask(lps::encode_list(), lps::decode_principals)
    }

    /// One principal in full.
    pub fn show(&self, name: &str) -> Result<lps::Detail, Refusal> {
        self.ask(lps::encode_show(&named(name)), lps::decode_principal)
    }

    /// The store's domain SID, which every local principal's SID is under.
    /// The smallest request there is, so also how a program finds out
    /// whether it may administer the store at all.
    pub fn domain(&self) -> Result<Vec<u8>, Refusal> {
        self.ask(lps::encode_domain(), lps::decode_domain_is)
    }

    /// Creates a principal, and answers its RID.
    pub fn add(&self, add: &lps::Add<'_>) -> Result<u32, Refusal> {
        let message = lps::encode_add(add).map_err(|error| Refusal::unreached(format!("could not encode the request: {error:?}")))?;
        let reply = self.request(message.expose())?;
        expect(lps::decode_created(reply.expose()))
    }

    pub fn remove(&self, name: &str) -> Result<(), Refusal> {
        self.done(lps::encode_remove(&named(name)))
    }

    pub fn set_enabled(&self, name: &str, enabled: bool) -> Result<(), Refusal> {
        self.done(lps::encode_set_enabled(&lps::SetEnabled { name: name.into(), enabled }))
    }

    pub fn set_password(&self, name: &str, secret: &[u8]) -> Result<(), Refusal> {
        let message = lps::encode_set_password(&lps::SetPassword { name: name.into(), secret })
            .map_err(|error| Refusal::unreached(format!("could not encode the request: {error:?}")))?;
        let reply = self.request(message.expose())?;
        expect(lps::decode_done(reply.expose()))
    }

    pub fn set_profile(&self, profile: &lps::SetProfile) -> Result<(), Refusal> {
        self.done(lps::encode_set_profile(profile))
    }

    /// Makes `group` (a well-known name, a local group's name, or a SID, as
    /// lpsd resolves it) the principal's primary group.
    pub fn set_primary_group(&self, name: &str, group: &str) -> Result<(), Refusal> {
        self.done(lps::encode_set_primary_group(&membership(name, group)))
    }

    /// Adds the principal to `group`, named as for [`Admin::set_primary_group`].
    pub fn group_add(&self, name: &str, group: &str) -> Result<(), Refusal> {
        self.done(lps::encode_group_add(&membership(name, group)))
    }

    pub fn group_remove(&self, name: &str, group: &str) -> Result<(), Refusal> {
        self.done(lps::encode_group_remove(&membership(name, group)))
    }

    /// Every local group. The well-known groups are authd's, not the store's,
    /// and aren't among them.
    pub fn group_list(&self) -> Result<Vec<lps::GroupSummary>, Refusal> {
        self.ask(lps::encode_group_list(), lps::decode_groups)
    }

    /// Creates a local group, and answers its RID.
    pub fn group_create(&self, name: &str) -> Result<u32, Refusal> {
        self.ask(lps::encode_group_create(&named(name)), lps::decode_created)
    }

    pub fn group_delete(&self, name: &str) -> Result<(), Refusal> {
        self.done(lps::encode_group_delete(&named(name)))
    }

    pub fn set_claim(&self, name: &str, claim: libauthd::Claim) -> Result<(), Refusal> {
        self.done(lps::encode_set_claim(&lps::SetClaim { name: name.into(), claim }))
    }

    pub fn remove_claim(&self, name: &str, claim_name: &str) -> Result<(), Refusal> {
        self.done(lps::encode_remove_claim(&lps::NamedClaim { name: name.into(), claim_name: claim_name.into() }))
    }

    /// The principal's credential policy and its SSH public keys.
    pub fn keys(&self, name: &str) -> Result<(Policy, Vec<lps::KeyInfo>), Refusal> {
        self.ask(lps::encode_key_request(&lps::KeyRequest::List { name: name.into() }), lps::decode_keys)
    }

    pub fn key_add(&self, name: &str, public_key: &str, label: &str) -> Result<(), Refusal> {
        self.done(lps::encode_key_request(&lps::KeyRequest::Add { name: name.into(), public_key: public_key.into(), label: label.into() }))
    }

    pub fn key_remove(&self, name: &str, id: [u8; 16]) -> Result<(), Refusal> {
        self.done(lps::encode_key_request(&lps::KeyRequest::Remove { name: name.into(), id }))
    }

    pub fn set_credential_policy(&self, name: &str, policy: Policy) -> Result<(), Refusal> {
        self.done(lps::encode_key_request(&lps::KeyRequest::Policy { name: name.into(), policy }))
    }
}

fn named(name: &str) -> lps::Named {
    lps::Named { name: name.into() }
}

fn membership(name: &str, group: &str) -> lps::Membership {
    lps::Membership { name: name.into(), group: group.into() }
}

fn encoded(message: Result<Vec<u8>, WireError>) -> Result<Vec<u8>, Refusal> {
    message.map_err(|error| Refusal::unreached(format!("could not encode the request: {error:?}")))
}

/// Decodes an answer, blaming the daemon rather than the caller if it won't
/// parse: by now the request was accepted, so it is a version mismatch or a
/// bug, not bad input.
fn expect<T>(decoded: Result<T, WireError>) -> Result<T, Refusal> {
    decoded.map_err(|error| Refusal::unreached(format!("lpsd's answer was not the one expected ({error:?}); versions may differ")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A stand-in lpsd at a fresh path, answering each connection with
    /// `answer` of what it was sent.
    fn stand_in(answer: impl Fn(&[u8]) -> Vec<u8> + Send + 'static) -> (Admin, PathBuf) {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!("libauthd-client-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("admin.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let Ok(received) = recv_message(&lps::FRAMING, &stream) else { continue };
                let _ = send_message(&stream, &answer(received.expose()));
            }
        });
        (Admin::at(&path), dir)
    }

    #[test]
    fn a_request_is_answered_and_decoded() {
        let (admin, dir) = stand_in(|request| {
            let (msg_type, _) = lps::decode_type(request).unwrap();
            assert_eq!(msg_type, lps::MSG_LIST);
            lps::encode_principals(&[lps::Summary { name: "dana".into(), rid: 1002, enabled: true, groups: 1, unix_id: 1002 }]).unwrap()
        });
        let listed = admin.list().unwrap();
        assert_eq!(listed[0].name, "dana");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_refusal_carries_lpsd_s_code_and_words() {
        let (admin, dir) = stand_in(|_| {
            lps::encode_failed(&lps::Failed { failure: Failure::Denied, reason: "the caller is not an administrator".into() }).unwrap()
        });
        let refused = admin.domain().unwrap_err();
        assert!(refused.denied());
        assert_eq!(refused.to_string(), "the caller is not an administrator");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_daemon_that_is_not_there_says_so() {
        let admin = Admin::at("/nonexistent/lpsd/admin.sock");
        let refused = admin.list().unwrap_err();
        assert_eq!(refused.failure, None);
        assert!(refused.reason.contains("it does not appear to be running"), "{}", refused.reason);
    }

    #[test]
    fn the_wrong_answer_is_blamed_on_the_daemon() {
        let (admin, dir) = stand_in(|_| lps::encode_done().unwrap());
        let refused = admin.list().unwrap_err();
        assert!(refused.reason.contains("versions may differ"), "{}", refused.reason);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
