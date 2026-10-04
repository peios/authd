//! Changing one's own credentials on the logon socket: a new password (PGSS
//! Logon §2.20), and adding or removing one's own SSH public keys (§2.23).
//!
//! # A conversation, rendered by the caller
//!
//! Each is a conversation the authority drives. It asks in rounds — the
//! current password, then a new one and its confirmation — and may say things
//! between them, such as why it is asking again. This module carries the
//! rounds; a [`Collector`] answers them. `passwd` answers at a terminal, as
//! the prompts arrive. A window answers from a form it filled first: current,
//! new and confirmation are all typed before anything is sent, and its
//! collector hands them over a round at a time, in order.
//!
//! A pre-filled form can run out. If the authority asks again — the two new
//! passwords did not match, say, and it said so in an `Error` message — the
//! form has nothing more to give, so its collector [abandons](Abandon). The
//! conversation then ends with nothing changed, and the caller gets
//! [`Refusal::Abandoned`] carrying that last `Error` message, which is the
//! sentence to show.
//!
//! # Nothing here knows what a password is
//!
//! The collector is told each prompt's label, whether its answer is secret,
//! and the reference it is answered under, and it returns bytes. Which
//! questions are asked, in how many rounds, and what is acceptable, are the
//! principal source's. Nothing names a principal: the account is the one the
//! caller's token belongs to (§2.20, §2.23), and there is no field to name
//! another.
//!
//! # Outcomes
//!
//! `Ok(())` only on `CredentialChanged`. A [`Refusal`] says whether anything
//! may have changed: only [`Refusal::Unknown`] leaves that open, where the
//! authority went away after the last answer and before saying how it ended.

use std::fmt;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use libauthd::LOGON_SOCKET_PATH;
use libauthd::Secret;
use libauthd::transport::{recv_message_with_fd, send_message};
use libauthd::wire::{
    self, Answer, CredentialChangeStart, CredentialEnrollStart, CredentialResponse,
    CredentialType, Denial, EnrollAction, MSG_ACCESS_DENIED, MSG_CREDENTIAL_CHANGED,
    MSG_CREDENTIAL_REQUEST,
};

pub use libauthd::wire::MessageSeverity;

/// How long the authority is given to send its next message. It waits on the
/// principal source for at most half a minute a round; this leaves room. Time
/// a person spends typing is not counted: nothing is being read then.
const REPLY_TIMEOUT: Duration = Duration::from_secs(90);
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Something the authority wants shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub severity: MessageSeverity,
    pub text: String,
}

/// One thing the authority asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    /// The reference the answer goes back under. Distinct within a
    /// conversation; a prompt asked again comes with a new one or the same
    /// one, as the authority chooses, so tell rounds apart by
    /// [`Round::number`], not by this.
    pub credential_ref: u32,
    /// What to show beside the input, such as "Current password". For a
    /// person to read: never branch on it.
    pub label: String,
    /// Whether the answer must not be echoed. Every prompt this module
    /// passes on is a password, so today always true.
    pub secret: bool,
}

/// One round: what to show, then what to ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Round {
    /// 1 for the first round of the conversation, and up from there.
    pub number: u32,
    /// To show, in order, before the prompts.
    pub messages: Vec<Notice>,
    /// To answer, one answer each, in this order. May be empty: a round that
    /// only says something is answered with no answers.
    pub prompts: Vec<Ask>,
}

/// A collector stopping the conversation instead of answering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Abandon {
    /// Why, for a person: "could not read the password: …", or that the
    /// form's answers ran out.
    pub reason: String,
}

impl Abandon {
    pub fn new(reason: impl Into<String>) -> Abandon {
        Abandon {
            reason: reason.into(),
        }
    }
}

/// Answers the authority's rounds.
///
/// A terminal shows each message and prompts for each answer as it comes; a
/// form returns what it collected beforehand, round by round.
pub trait Collector {
    /// Answer one round: exactly one secret per prompt, in the prompts'
    /// order, or [`Abandon`] to end the conversation with nothing changed.
    fn round(&mut self, round: &Round) -> Result<Vec<Secret>, Abandon>;
}

/// A collector for a form filled before the conversation began: it answers
/// each prompt with the next of `answers`, in order, and abandons when they
/// run out. Messages are not shown; the [`Refusal`] carries the last error.
///
/// Changing a password takes `[current, new, confirmation]`; adding or
/// removing a key, `[current]`.
pub struct Prefilled {
    answers: std::collections::VecDeque<Secret>,
}

impl Prefilled {
    pub fn new(answers: impl IntoIterator<Item = Secret>) -> Prefilled {
        Prefilled {
            answers: answers.into_iter().collect(),
        }
    }
}

impl Collector for Prefilled {
    fn round(&mut self, round: &Round) -> Result<Vec<Secret>, Abandon> {
        if self.answers.len() < round.prompts.len() {
            return Err(Abandon::new(
                "the authority asked for more than was entered",
            ));
        }
        Ok(round
            .prompts
            .iter()
            .filter_map(|_| self.answers.pop_front())
            .collect())
    }
}

/// Why a change did not happen — or, for [`Refusal::Unknown`], may have.
#[derive(Debug)]
pub enum Refusal {
    /// The logon socket couldn't be reached. Nothing was asked.
    Unreachable(io::Error),
    /// The opening couldn't be encoded or sent. Nothing changed.
    Unsent(String),
    /// The authority asked for something this client cannot collect, or sent
    /// a request that does not decode. The conversation was ended; nothing
    /// changed.
    Unrenderable(String),
    /// The collector stopped. The conversation was closed before its last
    /// answer, so nothing changed. `last_error` is the authority's most
    /// recent `Error` message, where it sent one: what to show a person.
    Abandoned {
        reason: String,
        last_error: Option<String>,
    },
    /// The authority went away, or answered in a way this build cannot read,
    /// after the change was asked for and before it said how it ended. It
    /// may have been made.
    Unknown(String),
    /// The authority refused. `code` is the denial as sent; `denial` is it
    /// where this build knows the code. `reason` is for a person.
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

    /// The current password was wrong (or changed meanwhile).
    pub fn wrong_password(&self) -> bool {
        self.denial() == Some(Denial::AuthenticationFailed)
    }

    /// The key offered, or named for removal, was refused (§2.23): the
    /// reason says why.
    pub fn credential_rejected(&self) -> bool {
        self.denial() == Some(Denial::CredentialRejected)
    }

    /// Whether the change may nonetheless have been made.
    pub fn outcome_unknown(&self) -> bool {
        matches!(self, Refusal::Unknown(_))
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Unreachable(error) => {
                write!(f, "cannot reach the authority at {LOGON_SOCKET_PATH}: {error}")
            }
            Refusal::Unsent(what) | Refusal::Unrenderable(what) => f.write_str(what),
            Refusal::Abandoned {
                last_error: Some(text),
                ..
            } => f.write_str(text),
            Refusal::Abandoned { reason, .. } => f.write_str(reason),
            Refusal::Unknown(what) => write!(f, "{what}; whether the change was made is not known"),
            Refusal::Declined { reason, code, .. } if reason.is_empty() => {
                write!(f, "the authority refused (denial {code})")
            }
            Refusal::Declined { reason, .. } => f.write_str(reason),
        }
    }
}

impl std::error::Error for Refusal {}

/// The logon socket, for changing one's own credentials.
#[derive(Debug, Clone)]
pub struct Credentials {
    path: PathBuf,
}

impl Default for Credentials {
    fn default() -> Credentials {
        Credentials::new()
    }
}

impl Credentials {
    /// The logon socket where it is: [`LOGON_SOCKET_PATH`].
    pub fn new() -> Credentials {
        Credentials::at(LOGON_SOCKET_PATH)
    }

    /// A logon socket at `path`: for tests, and nothing else.
    pub fn at(path: impl AsRef<Path>) -> Credentials {
        Credentials {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Change the caller's own password (`CredentialChangeStart`).
    pub fn change_password(&self, collector: &mut dyn Collector) -> Result<(), Refusal> {
        let start = wire::encode_credential_change_start(&CredentialChangeStart {
            // The only type rendered here.
            supported_credential_types: vec![CredentialType::Password],
        });
        self.converse(start, collector)
    }

    /// Add an SSH public key to the caller's own account
    /// (`CredentialEnrollStart`): one line of an OpenSSH `.pub` file. Its
    /// comment becomes its label. The authority asks for the current password
    /// first. Adding a key does not let it be used to sign in unless the
    /// account's credential policy allows keys.
    pub fn add_key(
        &self,
        public_key_line: &str,
        collector: &mut dyn Collector,
    ) -> Result<(), Refusal> {
        self.enroll(EnrollAction::Add, public_key_line, collector)
    }

    /// Remove one of the caller's own SSH public keys, named by its
    /// fingerprint as `ssh-keygen -l` writes it (`SHA256:…`). The authority
    /// asks for the current password first.
    pub fn remove_key(
        &self,
        fingerprint: &str,
        collector: &mut dyn Collector,
    ) -> Result<(), Refusal> {
        self.enroll(EnrollAction::Remove, fingerprint, collector)
    }

    fn enroll(
        &self,
        action: EnrollAction,
        material: &str,
        collector: &mut dyn Collector,
    ) -> Result<(), Refusal> {
        let start = wire::encode_credential_enroll_start(&CredentialEnrollStart {
            // For the proof: the current password.
            supported_credential_types: vec![CredentialType::Password],
            action,
            credential_type: CredentialType::SshPublicKey,
            material: material.to_string(),
        });
        self.converse(start, collector)
    }

    fn converse(
        &self,
        start: Result<Vec<u8>, libauthd::WireError>,
        collector: &mut dyn Collector,
    ) -> Result<(), Refusal> {
        let start = start
            .map_err(|error| Refusal::Unsent(format!("could not encode the request: {error:?}")))?;
        let stream = UnixStream::connect(&self.path).map_err(Refusal::Unreachable)?;
        stream
            .set_read_timeout(Some(REPLY_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(SEND_TIMEOUT)))
            .map_err(Refusal::Unreachable)?;
        converse(&stream, &start, collector)
    }
}

/// Run one conversation on a connected logon socket, from its opening to its
/// terminal message.
pub fn converse(
    stream: &UnixStream,
    start: &[u8],
    collector: &mut dyn Collector,
) -> Result<(), Refusal> {
    send_message(stream, start)
        .map_err(|error| Refusal::Unsent(format!("could not reach the authority: {error}")))?;

    let mut last_error = None;
    let mut number = 0;
    loop {
        // With a descriptor, in case one arrives: none is expected, and one
        // that does is closed here by being dropped rather than left behind.
        let (message, _descriptor) = recv_message_with_fd(&wire::FRAMING, stream)
            .map_err(|error| Refusal::Unknown(format!("lost the authority: {error}")))?;
        let (message_type, _) = wire::decode_header(message.expose())
            .map_err(|error| Refusal::Unknown(format!("malformed reply: {error:?}")))?;

        match message_type {
            MSG_CREDENTIAL_REQUEST => {
                let request = wire::decode_credential_request(message.expose()).map_err(|error| {
                    Refusal::Unrenderable(format!(
                        "the authority sent a request this cannot render: {error:?}"
                    ))
                })?;
                // Checked before anything is shown or asked: a client that
                // cannot render a prompt fails rather than guessing (§2.8).
                if request
                    .prompts
                    .iter()
                    .any(|prompt| prompt.credential_type != CredentialType::Password)
                {
                    return Err(Refusal::Unrenderable(
                        "the authority requested an unsupported credential".into(),
                    ));
                }
                number += 1;
                let round = Round {
                    number,
                    messages: request
                        .messages
                        .iter()
                        .map(|message| Notice {
                            severity: message.severity,
                            text: message.text.clone(),
                        })
                        .collect(),
                    prompts: request
                        .prompts
                        .iter()
                        .map(|prompt| Ask {
                            credential_ref: prompt.credential_ref,
                            label: prompt.credential_name.clone(),
                            secret: true,
                        })
                        .collect(),
                };
                if let Some(error) = round
                    .messages
                    .iter()
                    .rev()
                    .find(|notice| notice.severity == MessageSeverity::Error)
                {
                    last_error = Some(error.text.clone());
                }

                // Abandoning is closing the connection without answering,
                // which the caller does by dropping it: nothing changes on a
                // conversation that never sent its last answer.
                let secrets = collector.round(&round).map_err(|abandon| Refusal::Abandoned {
                    reason: abandon.reason,
                    last_error: last_error.clone(),
                })?;
                if secrets.len() != round.prompts.len() {
                    return Err(Refusal::Abandoned {
                        reason: format!(
                            "{} answers for {} prompts",
                            secrets.len(),
                            round.prompts.len()
                        ),
                        last_error,
                    });
                }
                let answers = round
                    .prompts
                    .iter()
                    .zip(secrets)
                    .map(|(ask, data)| Answer {
                        credential_ref: ask.credential_ref,
                        data,
                    })
                    .collect();
                let encoded = wire::encode_credential_response(&CredentialResponse { answers })
                    .map_err(|error| {
                        Refusal::Abandoned {
                            reason: format!("could not encode the answers: {error:?}"),
                            last_error: last_error.clone(),
                        }
                    })?;
                send_message(stream, encoded.expose())
                    .map_err(|error| Refusal::Unknown(format!("lost the authority: {error}")))?;
            }

            MSG_CREDENTIAL_CHANGED => {
                wire::decode_credential_changed(message.expose())
                    .map_err(|error| Refusal::Unknown(format!("malformed reply: {error:?}")))?;
                return Ok(());
            }

            MSG_ACCESS_DENIED => {
                // Leniently: a denial newer than this build is still a
                // refusal, with its number (§2.B).
                let (code, reason) = wire::decode_access_denied_code(message.expose())
                    .map_err(|error| Refusal::Unknown(format!("malformed denial: {error:?}")))?;
                return Err(Refusal::Declined {
                    code,
                    denial: Denial::from_u32(code),
                    reason,
                });
            }

            other => {
                return Err(Refusal::Unknown(format!(
                    "unexpected message {other:#06x} from the authority"
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libauthd::transport::recv_message;
    use libauthd::wire::{
        AccessDenied, CredentialChanged, CredentialRequest, MSG_CREDENTIAL_CHANGE_START,
        MSG_CREDENTIAL_ENROLL_START, MSG_CREDENTIAL_RESPONSE, Message, Prompt,
    };
    use std::thread;

    /// Answers from a script, a prompt at a time, and remembers what it was
    /// asked and shown — a terminal's way of collecting.
    struct Scripted {
        answers: Vec<&'static [u8]>,
        asked: Vec<String>,
        shown: Vec<String>,
        rounds: Vec<u32>,
    }

    impl Scripted {
        fn new(answers: Vec<&'static [u8]>) -> Self {
            Self {
                answers,
                asked: Vec::new(),
                shown: Vec::new(),
                rounds: Vec::new(),
            }
        }
    }

    impl Collector for Scripted {
        fn round(&mut self, round: &Round) -> Result<Vec<Secret>, Abandon> {
            self.rounds.push(round.number);
            self.shown
                .extend(round.messages.iter().map(|m| m.text.clone()));
            let mut out = Vec::new();
            for ask in &round.prompts {
                assert!(ask.secret);
                self.asked.push(ask.label.clone());
                if self.answers.is_empty() {
                    return Err(Abandon::new("no more answers"));
                }
                out.push(Secret::from_slice(self.answers.remove(0)));
            }
            Ok(out)
        }
    }

    fn prompt(credential_ref: u32, name: &str) -> Prompt {
        Prompt {
            parameters: Vec::new(),
            credential_ref,
            credential_type: CredentialType::Password,
            credential_name: name.into(),
        }
    }

    type Answered = Vec<Vec<(u32, Vec<u8>)>>;

    /// Play the authority: check the opening is `opening`, then send
    /// `script`, reading a response after each request. Stops early if the
    /// client hangs up. Returns the opening and every round's answers.
    fn authority(
        socket: UnixStream,
        opening: u16,
        script: Vec<Vec<u8>>,
    ) -> thread::JoinHandle<(Vec<u8>, Answered)> {
        thread::spawn(move || {
            let first = recv_message(&wire::FRAMING, &socket).expect("an opening");
            let (message_type, _) = wire::decode_header(first.expose()).expect("a header");
            assert_eq!(message_type, opening);

            let mut answered = Vec::new();
            for message in script {
                let (message_type, _) = wire::decode_header(&message).expect("a header");
                if send_message(&socket, &message).is_err() {
                    break;
                }
                if message_type == MSG_CREDENTIAL_REQUEST {
                    let Ok(reply) = recv_message(&wire::FRAMING, &socket) else {
                        break;
                    };
                    let (message_type, _) = wire::decode_header(reply.expose()).expect("a header");
                    assert_eq!(message_type, MSG_CREDENTIAL_RESPONSE);
                    let response = wire::decode_credential_response(reply.expose()).expect("decodes");
                    answered.push(
                        response
                            .answers
                            .iter()
                            .map(|a| (a.credential_ref, a.data.expose().to_vec()))
                            .collect(),
                    );
                }
            }
            (first.expose().to_vec(), answered)
        })
    }

    fn request(messages: Vec<Message>, prompts: Vec<Prompt>) -> Vec<u8> {
        wire::encode_credential_request(&CredentialRequest { messages, prompts }).expect("encodes")
    }

    fn changed() -> Vec<u8> {
        wire::encode_credential_changed(&CredentialChanged).expect("encodes")
    }

    fn change_start() -> Vec<u8> {
        wire::encode_credential_change_start(&CredentialChangeStart {
            supported_credential_types: vec![CredentialType::Password],
        })
        .unwrap()
    }

    fn password_rounds() -> Vec<Vec<u8>> {
        vec![
            request(
                vec![Message {
                    severity: MessageSeverity::Info,
                    text: "Changing the password for jack".into(),
                }],
                vec![prompt(1, "Current password")],
            ),
            request(
                Vec::new(),
                vec![prompt(2, "New password"), prompt(3, "Retype new password")],
            ),
            changed(),
        ]
    }

    #[test]
    fn a_change_renders_every_round_and_ends_on_changed() {
        let (client, server) = UnixStream::pair().expect("socketpair");
        let authority = authority(server, MSG_CREDENTIAL_CHANGE_START, password_rounds());

        let mut collector = Scripted::new(vec![b"old", b"new", b"new"]);
        converse(&client, &change_start(), &mut collector).expect("changed");

        let (opening, answered) = authority.join().expect("the authority");
        let start = wire::decode_credential_change_start(&opening).expect("decodes");
        assert_eq!(start.supported_credential_types, vec![CredentialType::Password]);
        assert_eq!(answered[0], vec![(1, b"old".to_vec())]);
        assert_eq!(
            answered[1],
            vec![(2, b"new".to_vec()), (3, b"new".to_vec())],
            "answers go back under the refs they were asked with"
        );
        assert_eq!(
            collector.asked,
            ["Current password", "New password", "Retype new password"]
        );
        assert_eq!(collector.shown, ["Changing the password for jack"]);
        assert_eq!(collector.rounds, [1, 2]);
    }

    /// A form filled first answers round by round, in order.
    #[test]
    fn a_prefilled_form_answers_a_change() {
        let (client, server) = UnixStream::pair().expect("socketpair");
        let authority = authority(server, MSG_CREDENTIAL_CHANGE_START, password_rounds());
        let mut form = Prefilled::new([b"old", b"new", b"new"].map(|s| Secret::from_slice(s)));
        converse(&client, &change_start(), &mut form).expect("changed");
        let (_, answered) = authority.join().expect("the authority");
        assert_eq!(answered.len(), 2);
    }

    /// The case a form must handle: the authority says what was wrong and asks
    /// again, the form has nothing more, and the caller is given what the
    /// authority said.
    #[test]
    fn a_form_that_runs_out_abandons_with_the_last_error() {
        let (client, server) = UnixStream::pair().expect("socketpair");
        let mut script = password_rounds();
        script.insert(
            2,
            request(
                vec![Message {
                    severity: MessageSeverity::Error,
                    text: "The passwords do not match.".into(),
                }],
                vec![prompt(2, "New password"), prompt(3, "Retype new password")],
            ),
        );
        let authority = authority(server, MSG_CREDENTIAL_CHANGE_START, script);

        let mut form = Prefilled::new([b"old", b"new", b"nwe"].map(|s| Secret::from_slice(s)));
        let refusal = converse(&client, &change_start(), &mut form).expect_err("abandoned");
        drop(client);
        let (_, answered) = authority.join().expect("the authority");
        assert_eq!(answered.len(), 2, "the third round was never answered");
        match &refusal {
            Refusal::Abandoned { last_error, .. } => {
                assert_eq!(last_error.as_deref(), Some("The passwords do not match."))
            }
            other => panic!("expected an abandon, got {other:?}"),
        }
        assert_eq!(refusal.to_string(), "The passwords do not match.");
        assert!(!refusal.outcome_unknown());
    }

    #[test]
    fn a_denial_is_reported_with_its_reason() {
        let (client, server) = UnixStream::pair().expect("socketpair");
        let script = vec![
            request(Vec::new(), vec![prompt(1, "Current password")]),
            wire::encode_access_denied(&AccessDenied {
                denial: Denial::AuthenticationFailed,
                reason: "Authentication failed.".into(),
            })
            .expect("encodes"),
        ];
        let authority = authority(server, MSG_CREDENTIAL_CHANGE_START, script);
        let refusal = converse(&client, &change_start(), &mut Scripted::new(vec![b"guess"]))
            .expect_err("a denial is a failure");
        authority.join().expect("the authority");
        assert!(refusal.wrong_password());
        assert_eq!(refusal.to_string(), "Authentication failed.");
    }

    /// PGSS client obligation 4: an authority that goes away without a
    /// terminal message has not said how the change ended.
    #[test]
    fn an_authority_that_goes_away_leaves_the_outcome_unknown() {
        let (client, server) = UnixStream::pair().expect("socketpair");
        let authority = authority(
            server,
            MSG_CREDENTIAL_CHANGE_START,
            vec![request(Vec::new(), vec![prompt(1, "Current password")])],
        );
        let refusal = converse(&client, &change_start(), &mut Scripted::new(vec![b"old"]))
            .expect_err("no terminal is not success");
        authority.join().expect("the authority");
        assert!(refusal.outcome_unknown(), "{refusal:?}");
    }

    /// A logon's terminal is not a change's.
    #[test]
    fn a_grant_is_not_a_change() {
        let (client, server) = UnixStream::pair().expect("socketpair");
        let grant = wire::encode_access_granted(&wire::AccessGranted::default()).expect("encodes");
        let authority = authority(server, MSG_CREDENTIAL_CHANGE_START, vec![grant]);
        assert!(converse(&client, &change_start(), &mut Scripted::new(Vec::new())).is_err());
        authority.join().expect("the authority");
    }

    /// A prompt this client cannot render fails the conversation rather than
    /// being guessed at (§2.8).
    #[test]
    fn an_unrenderable_prompt_ends_it() {
        let (client, server) = UnixStream::pair().expect("socketpair");
        let key_prompt = Prompt {
            parameters: libauthd::ssh::disposition(0).unwrap(),
            credential_ref: 1,
            credential_type: CredentialType::SshPublicKey,
            credential_name: "SSH public key".into(),
        };
        let authority = authority(
            server,
            MSG_CREDENTIAL_CHANGE_START,
            vec![request(Vec::new(), vec![key_prompt])],
        );
        let refusal = converse(&client, &change_start(), &mut Scripted::new(vec![b"x"]))
            .expect_err("refused");
        drop(client);
        authority.join().expect("the authority");
        assert!(matches!(refusal, Refusal::Unrenderable(_)), "{refusal:?}");
    }

    /// A stand-in logon socket at a fresh path, for the public methods.
    fn stand_in(
        script: Vec<Vec<u8>>,
    ) -> (Credentials, PathBuf, thread::JoinHandle<(Vec<u8>, Answered)>) {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "libauthd-client-credential-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("logon.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            authority(stream, MSG_CREDENTIAL_ENROLL_START, script)
                .join()
                .unwrap()
        });
        (Credentials::at(&path), dir, handle)
    }

    #[test]
    fn adding_a_key_opens_an_enrolment_and_proves_the_password() {
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample laptop";
        let (credentials, dir, authority) = stand_in(vec![
            request(Vec::new(), vec![prompt(1, "Current password")]),
            changed(),
        ]);
        let mut form = Prefilled::new([Secret::from_slice(b"old")]);
        credentials.add_key(line, &mut form).expect("added");
        let (opening, answered) = authority.join().unwrap();
        let start = wire::decode_credential_enroll_start(&opening).unwrap();
        assert_eq!(start.action, EnrollAction::Add);
        assert_eq!(start.credential_type, CredentialType::SshPublicKey);
        assert_eq!(start.material, line);
        assert_eq!(start.supported_credential_types, vec![CredentialType::Password]);
        assert_eq!(answered, vec![vec![(1, b"old".to_vec())]]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn removing_a_key_names_its_fingerprint_and_a_rejection_says_why() {
        let (credentials, dir, authority) = stand_in(vec![
            wire::encode_access_denied(&AccessDenied {
                denial: Denial::CredentialRejected,
                reason: "This account has no SSH key with the fingerprint SHA256:x.".into(),
            })
            .unwrap(),
        ]);
        let refusal = credentials
            .remove_key("SHA256:x", &mut Prefilled::new([]))
            .expect_err("rejected");
        let (opening, _) = authority.join().unwrap();
        let start = wire::decode_credential_enroll_start(&opening).unwrap();
        assert_eq!(start.action, EnrollAction::Remove);
        assert_eq!(start.material, "SHA256:x");
        assert!(refusal.credential_rejected());
        assert!(refusal.to_string().contains("no SSH key"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_absent_authority_is_unreachable() {
        let refusal = Credentials::at("/nonexistent/logon.sock")
            .change_password(&mut Prefilled::new([]))
            .expect_err("unreachable");
        match refusal {
            Refusal::Unreachable(error) => assert_eq!(error.kind(), io::ErrorKind::NotFound),
            other => panic!("expected unreachable, got {other:?}"),
        }
    }
}
