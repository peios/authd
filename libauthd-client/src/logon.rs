//! The logon socket: ending a logon session, and asking whether one may, as
//! PGSS Logon §2.22 specifies them.
//!
//! Signing in is not here: a logon originator holds a conversation with
//! prompts, which belongs to the program that renders them (`login`, a
//! greeter). This is the part of the socket a program uses without a person
//! typing anything — Task Manager, `logonse`.
//!
//! Each request is a connection of its own, one message each way, as the
//! socket requires. Nothing retries: a refusal is an answer, and ending a
//! session twice is not something to do by accident.
//!
//! # Ending your own session
//!
//! A program that ends the session it runs in is ended with it. The authority
//! answers first, so [`Logon::end_session`] still returns — but its counts are
//! then what the authority found to end rather than what it ended, and the
//! caller has moments to live. Don't plan to do anything after it.

use std::fmt;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use libauthd::LOGON_SOCKET_PATH;
use libauthd::transport::{recv_message, send_message};
use libauthd::wire::{
    self, Denial, FRAMING, MSG_ACCESS_DENIED, MSG_SESSION_END_ALLOWED, MSG_SESSION_ENDED,
    SessionEnd, SessionEndQuery,
};

/// How long the authority is given to answer, unless the caller says.
///
/// Ending a session waits for its processes: a grace period after `SIGTERM`,
/// then `SIGKILL`, for a few rounds. Mainline's authority takes at most about
/// eighteen seconds; this leaves room over that.
const TIMEOUT: Duration = Duration::from_secs(60);

/// What an ended session came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ended {
    /// Processes of the session the authority ended.
    pub ended: u32,
    /// Processes still holding the session that it could not end, or could
    /// not examine. Not zero means the session is still there.
    pub remaining: u32,
}

/// Why a request was not done.
#[derive(Debug)]
pub enum Refusal {
    /// The authority couldn't be reached: no socket, nothing listening, or
    /// the socket's descriptor doesn't admit the caller.
    Unreachable(io::Error),
    /// The request couldn't be sent.
    Unsent(io::Error),
    /// No answer came: the time ran out, or the connection closed. Whether a
    /// `SessionEnd` was acted on is then unknown.
    Unanswered(io::Error),
    /// The answer couldn't be read, or answered another question: the
    /// versions on each side may differ.
    Unreadable(String),
    /// The authority refused. `code` is the denial as sent; `denial` is it,
    /// where this build knows the code. `reason` is for a person to read, and
    /// for nothing to branch on.
    Declined {
        code: u32,
        denial: Option<Denial>,
        reason: String,
    },
}

impl Refusal {
    /// The authority's denial, where it refused with one this build knows.
    pub fn denial(&self) -> Option<Denial> {
        match self {
            Refusal::Declined { denial, .. } => *denial,
            _ => None,
        }
    }

    /// Whether the caller may not do this — as against the authority being
    /// unreachable, or the session being gone. A window greys the action out
    /// on this.
    pub fn not_permitted(&self) -> bool {
        self.denial() == Some(Denial::PermissionDenied)
    }

    /// Whether there was no such session to end: it has ended already.
    pub fn no_such_session(&self) -> bool {
        self.denial() == Some(Denial::NoSuchSession)
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Unreachable(error) | Refusal::Unsent(error) | Refusal::Unanswered(error) => {
                write!(f, "{error}")
            }
            Refusal::Unreadable(why) => {
                write!(
                    f,
                    "authd's answer could not be read ({why}); versions may differ"
                )
            }
            Refusal::Declined { reason, code, .. } if reason.is_empty() => {
                write!(f, "authd refused (denial {code})")
            }
            Refusal::Declined { reason, .. } => f.write_str(reason),
        }
    }
}

impl std::error::Error for Refusal {}

impl From<Refusal> for io::Error {
    fn from(refusal: Refusal) -> io::Error {
        match refusal {
            Refusal::Unreachable(error) | Refusal::Unsent(error) | Refusal::Unanswered(error) => {
                error
            }
            Refusal::Unreadable(_) => {
                io::Error::new(io::ErrorKind::InvalidData, refusal.to_string())
            }
            Refusal::Declined { .. } if refusal.not_permitted() => {
                io::Error::new(io::ErrorKind::PermissionDenied, refusal.to_string())
            }
            Refusal::Declined { .. } if refusal.no_such_session() => {
                io::Error::new(io::ErrorKind::NotFound, refusal.to_string())
            }
            Refusal::Declined { .. } => io::Error::other(refusal.to_string()),
        }
    }
}

/// The logon socket.
#[derive(Debug, Clone)]
pub struct Logon {
    path: PathBuf,
    timeout: Duration,
}

impl Default for Logon {
    fn default() -> Logon {
        Logon::new()
    }
}

impl Logon {
    /// The logon socket where it is: [`LOGON_SOCKET_PATH`].
    pub fn new() -> Logon {
        Logon::at(LOGON_SOCKET_PATH)
    }

    /// A logon socket at `path`: for tests, and nothing else.
    pub fn at(path: impl AsRef<Path>) -> Logon {
        Logon {
            path: path.as_ref().to_path_buf(),
            timeout: TIMEOUT,
        }
    }

    /// The same socket, giving the authority `timeout` to answer. Ending a
    /// session waits for its processes, so a short timeout can leave a caller
    /// not knowing what was done.
    pub fn with_timeout(self, timeout: Duration) -> Logon {
        Logon { timeout, ..self }
    }

    /// Whether the caller may end logon session `id`, asked without ending
    /// it (`SessionEndQuery`). For deciding whether to offer the action.
    pub fn may_end_session(&self, id: u64) -> Result<(), Refusal> {
        let request = wire::encode_session_end_query(&SessionEndQuery {
            logon_session_id: id,
        });
        let answer = self.ask(request)?;
        match answer.kind {
            MSG_SESSION_END_ALLOWED => wire::decode_session_end_allowed(&answer.bytes)
                .map(|_| ())
                .map_err(|error| Refusal::Unreadable(format!("{error:?}"))),
            other => Err(Refusal::Unreadable(format!(
                "it answered with message {other:#06x}"
            ))),
        }
    }

    /// End logon session `id` (`SessionEnd`): the authority ends its
    /// processes, and the kernel destroys it when the last reference goes.
    ///
    /// Returns once the authority has done what it can, which may be some
    /// seconds. See the module documentation for ending one's own session.
    pub fn end_session(&self, id: u64) -> Result<Ended, Refusal> {
        let request = wire::encode_session_end(&SessionEnd {
            logon_session_id: id,
        });
        let answer = self.ask(request)?;
        match answer.kind {
            MSG_SESSION_ENDED => wire::decode_session_ended(&answer.bytes)
                .map(|ended| Ended {
                    ended: ended.ended,
                    remaining: ended.remaining,
                })
                .map_err(|error| Refusal::Unreadable(format!("{error:?}"))),
            other => Err(Refusal::Unreadable(format!(
                "it answered with message {other:#06x}"
            ))),
        }
    }

    /// Send one request on a connection of its own and read the answer. A
    /// denial comes back as [`Refusal::Declined`]; anything else is the
    /// caller's to read.
    fn ask(&self, request: Result<Vec<u8>, libauthd::WireError>) -> Result<Answer, Refusal> {
        let request = request.map_err(|error| {
            Refusal::Unreadable(format!("the request could not be encoded: {error:?}"))
        })?;
        let stream = UnixStream::connect(&self.path).map_err(|error| {
            Refusal::Unreachable(io::Error::new(
                error.kind(),
                format!("cannot reach authd on {}: {error}", self.path.display()),
            ))
        })?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(Refusal::Unreachable)?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(Refusal::Unreachable)?;
        send_message(&stream, &request).map_err(Refusal::Unsent)?;
        let received = recv_message(&FRAMING, &stream).map_err(Refusal::Unanswered)?;
        let bytes = received.expose().to_vec();
        let (kind, _) = wire::decode_header(&bytes)
            .map_err(|error| Refusal::Unreadable(format!("{error:?}")))?;
        if kind == MSG_ACCESS_DENIED {
            // Leniently: a denial code newer than this build is still a
            // refusal, and is reported as one.
            let (code, reason) = wire::decode_access_denied_code(&bytes)
                .map_err(|error| Refusal::Unreadable(format!("{error:?}")))?;
            return Err(Refusal::Declined {
                code,
                denial: Denial::from_u32(code),
                reason,
            });
        }
        Ok(Answer { kind, bytes })
    }
}

struct Answer {
    kind: u16,
    bytes: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use libauthd::wire::{
        AccessDenied, MSG_SESSION_END, MSG_SESSION_END_QUERY, SessionEndAllowed, SessionEnded,
    };
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc;

    /// A stand-in authority at a fresh path. Each connection carries one
    /// request, answered with `answer` of its message type and session id;
    /// what was asked is reported on the channel.
    fn stand_in(
        answer: impl Fn(u16, u64) -> Vec<u8> + Send + 'static,
    ) -> (Logon, PathBuf, mpsc::Receiver<(u16, u64)>) {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "libauthd-client-logon-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("logon.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (asked, heard) = mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let Ok(received) = recv_message(&FRAMING, &stream) else {
                    continue;
                };
                let bytes = received.expose();
                let (kind, _) = wire::decode_header(bytes).unwrap();
                let id = match kind {
                    MSG_SESSION_END => wire::decode_session_end(bytes).unwrap().logon_session_id,
                    MSG_SESSION_END_QUERY => {
                        wire::decode_session_end_query(bytes)
                            .unwrap()
                            .logon_session_id
                    }
                    other => panic!("unexpected request {other:#06x}"),
                };
                let _ = asked.send((kind, id));
                let _ = send_message(&stream, &answer(kind, id));
                // One request a connection: dropping the stream closes it.
            }
        });
        (Logon::at(&path), dir, heard)
    }

    fn denied(denial: Denial, reason: &str) -> Vec<u8> {
        wire::encode_access_denied(&AccessDenied {
            denial,
            reason: reason.into(),
        })
        .unwrap()
    }

    #[test]
    fn a_session_is_ended_and_the_counts_come_back() {
        let (logon, dir, heard) = stand_in(|_, _| {
            wire::encode_session_ended(&SessionEnded {
                ended: 4,
                remaining: 1,
            })
            .unwrap()
        });
        assert_eq!(
            logon.end_session(1042).unwrap(),
            Ended {
                ended: 4,
                remaining: 1
            }
        );
        assert_eq!(heard.recv().unwrap(), (MSG_SESSION_END, 1042));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The question is its own message, never the act with a flag.
    #[test]
    fn asking_is_a_query_and_changes_nothing() {
        let (logon, dir, heard) = stand_in(|kind, _| {
            assert_eq!(
                kind, MSG_SESSION_END_QUERY,
                "a question must not be the act"
            );
            wire::encode_session_end_allowed(&SessionEndAllowed).unwrap()
        });
        logon.may_end_session(77).unwrap();
        assert_eq!(heard.recv().unwrap(), (MSG_SESSION_END_QUERY, 77));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_refusal_says_which() {
        let (logon, dir, _heard) = stand_in(|_, id| match id {
            1 => denied(Denial::PermissionDenied, "You may not end that session."),
            _ => denied(Denial::NoSuchSession, "There is no such session."),
        });
        let refused = logon.may_end_session(1).unwrap_err();
        assert!(
            refused.not_permitted() && !refused.no_such_session(),
            "{refused:?}"
        );
        assert_eq!(refused.to_string(), "You may not end that session.");
        assert_eq!(
            io::Error::from(refused).kind(),
            io::ErrorKind::PermissionDenied
        );

        let gone = logon.end_session(2).unwrap_err();
        assert!(gone.no_such_session(), "{gone:?}");
        assert_eq!(io::Error::from(gone).kind(), io::ErrorKind::NotFound);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A denial newer than this build is still a refusal, with its number,
    /// and never an unreadable answer.
    #[test]
    fn an_unknown_denial_code_is_still_a_refusal() {
        let (logon, dir, _heard) = stand_in(|_, _| {
            let mut bytes = denied(Denial::Internal, "Something newer.");
            // The code is the first field of the body.
            let at = wire::HEADER_BYTES + 4;
            bytes[at..at + 4].copy_from_slice(&77u32.to_le_bytes());
            bytes
        });
        match logon.end_session(5).unwrap_err() {
            Refusal::Declined {
                code,
                denial,
                reason,
            } => {
                assert_eq!((code, denial), (77, None));
                assert_eq!(reason, "Something newer.");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// An answer to the other question is not taken as this one's.
    #[test]
    fn an_answer_of_the_wrong_kind_is_unreadable() {
        let (logon, dir, _heard) =
            stand_in(|_, _| wire::encode_session_end_allowed(&SessionEndAllowed).unwrap());
        assert!(matches!(logon.end_session(5), Err(Refusal::Unreadable(_))));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_absent_authority_is_unreachable() {
        let missing = Logon::at("/nonexistent/logon.sock");
        let refused = missing.may_end_session(1).unwrap_err();
        assert!(matches!(refused, Refusal::Unreachable(_)), "{refused:?}");
        assert!(
            refused
                .to_string()
                .starts_with("cannot reach authd on /nonexistent/logon.sock")
        );
    }

    /// An authority that closes without answering leaves the caller not
    /// knowing, and says so.
    #[test]
    fn a_connection_closed_without_an_answer_is_unanswered() {
        let dir = std::env::temp_dir().join(format!(
            "libauthd-client-logon-silent-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("logon.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let _ = recv_message(&FRAMING, &stream);
            }
        });
        let logon = Logon::at(&path).with_timeout(Duration::from_secs(5));
        assert!(matches!(logon.end_session(5), Err(Refusal::Unanswered(_))));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
