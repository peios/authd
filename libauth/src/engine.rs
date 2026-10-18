//! One request per connection, with explicit prompt and terminal states.
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::{Duration, Instant};

use auth_core::{Secret, ident, lps, wire};
use auth_core::frame::{Framing, WireError};
use crate::connection::Connection;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Logon,
    Attest,
    Change,
    Lookup,
    Enumerate,
    Account,
    DisplayName,
    Query,
    End,
}

impl Kind {
    fn mutates(self) -> bool {
        !matches!(
            self,
            Self::Lookup | Self::Enumerate | Self::Account | Self::Query
        )
    }
    fn framing(self) -> Framing {
        match self {
            Self::Lookup | Self::Enumerate => wire::FRAMING,
            Self::Account | Self::DisplayName => lps::FRAMING,
            _ => wire::FRAMING,
        }
    }
}

pub(crate) enum Output {
    Grant {
        token: Option<OwnedFd>,
        grant: wire::AccessGranted,
    },
    Changed,
    Lookup(ident::LookupReply),
    Listing(ident::EnumerateReply),
    Account(lps::OwnAccount),
    Allowed,
    Ended(wire::SessionEnded),
}

pub(crate) struct Failure {
    pub category: u32,
    pub code: u32,
    pub message: String,
    pub unknown: bool,
}

pub(crate) enum State {
    Pending,
    Prompt(wire::CredentialRequest),
    Complete(Output),
    Denied(Failure),
    Failed(Failure),
    Cancelled(Failure),
}

pub(crate) struct Operation {
    pub state: State,
    pub round: u64,
    connection: Option<Connection>,
    kind: Kind,
    capabilities: Vec<wire::CredentialType>,
    timeout: Duration,
    deadline: Instant,
}

impl Operation {
    pub fn begin(
        path: &Path,
        timeout: Duration,
        kind: Kind,
        request: Secret,
        capabilities: Vec<wire::CredentialType>,
    ) -> Self {
        let connection = Connection::open(path, kind.framing(), request);
        let (connection, state) = match connection {
            Ok(connection) => (Some(connection), State::Pending),
            Err(error) => (
                None,
                State::Failed(Failure {
                    category: error_category(&error),
                    code: error.raw_os_error().unwrap_or(0) as u32,
                    message: error.to_string(),
                    unknown: false,
                }),
            ),
        };
        Self {
            connection,
            state,
            kind,
            capabilities,
            round: 0,
            timeout,
            deadline: Instant::now() + timeout,
        }
    }

    pub fn poll_info(&self) -> Option<(i32, i16, u64)> {
        if !matches!(self.state, State::Pending) {
            return None;
        }
        let socket = self.connection.as_ref()?;
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        // Round upward: a positive submillisecond interval must not look expired.
        let millis = remaining.as_millis() as u64
            + u64::from(!remaining.subsec_nanos().is_multiple_of(1_000_000));
        Some((socket.fd(), socket.interests(), millis))
    }

    pub fn step(&mut self) {
        if !matches!(self.state, State::Pending) {
            return;
        }
        if Instant::now() >= self.deadline {
            self.fail(io::Error::new(
                io::ErrorKind::TimedOut,
                "authentication reply timed out",
            ));
            return;
        }
        let Some(socket) = self.connection.as_mut() else {
            return;
        };
        match socket.step() {
            Ok(Some((message, token))) => {
                match self.accept(message.expose(), token) {
                    Ok(state) => self.state = state,
                    Err(error) => self.fail(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid authentication reply: {error:?}"),
                    )),
                }
                if !matches!(self.state, State::Pending | State::Prompt(_)) {
                    self.connection = None;
                }
            }
            Ok(None) => {}
            Err(error) => self.fail(error),
        }
    }

    pub fn respond(&mut self, round: u64, answers: Vec<wire::Answer>) -> Result<(), WireError> {
        let State::Prompt(request) = &self.state else {
            return Err(WireError::UnknownValue);
        };
        if round != self.round || answers.len() != request.prompts.len() {
            return Err(WireError::UnknownValue);
        }
        for (prompt, answer) in request.prompts.iter().zip(&answers) {
            if prompt.credential_ref != answer.credential_ref {
                return Err(WireError::UnknownValue);
            }
        }
        let message = wire::encode_credential_response(&wire::CredentialResponse { answers })?;
        let Some(connection) = self.connection.as_mut() else {
            return Err(WireError::UnknownValue);
        };
        connection.send(message);
        self.state = State::Pending;
        self.deadline = Instant::now() + self.timeout;
        Ok(())
    }

    pub fn cancel(&mut self) {
        if !matches!(self.state, State::Pending | State::Prompt(_)) {
            return;
        }
        let unknown = self.outcome_unknown();
        self.state = State::Cancelled(Failure {
            category: 5,
            code: 0,
            message: "operation cancelled".into(),
            unknown,
        });
        self.connection = None;
    }

    fn outcome_unknown(&self) -> bool {
        self.kind.mutates()
            && self
                .connection
                .as_ref()
                .is_some_and(|socket| socket.submitted)
    }

    fn fail(&mut self, error: io::Error) {
        self.state = State::Failed(Failure {
            category: error_category(&error),
            code: error.raw_os_error().unwrap_or(0) as u32,
            message: error.to_string(),
            unknown: self.outcome_unknown(),
        });
        self.connection = None;
    }

    fn accept(&mut self, message: &[u8], token: Option<OwnedFd>) -> Result<State, WireError> {
        let (message_type, _) = auth_core::frame::decode_header(&self.kind.framing(), message)?;
        let granted = matches!(self.kind, Kind::Logon | Kind::Attest)
            && message_type == wire::MSG_ACCESS_GRANTED;
        if token.is_some() != granted {
            return Err(WireError::UnknownValue);
        }
        match self.kind {
            Kind::Lookup => {
                let result = ident::decode_lookup_reply(message)?;
                if result.tag != 1 {
                    return Err(WireError::UnknownValue);
                }
                return Ok(State::Complete(Output::Lookup(result)));
            }
            Kind::Enumerate => {
                let result = ident::decode_enumerate_reply(message)?;
                if result.tag != 1 {
                    return Err(WireError::UnknownValue);
                }
                return Ok(State::Complete(Output::Listing(result)));
            }
            Kind::Account | Kind::DisplayName => return self.accept_self(message, message_type),
            _ => {}
        }
        if message_type == wire::MSG_ACCESS_DENIED {
            let (code, message) = wire::decode_access_denied_code(message)?;
            return Ok(State::Denied(Failure {
                category: 6,
                code,
                message,
                unknown: false,
            }));
        }
        if message_type == wire::MSG_CREDENTIAL_REQUEST
            && matches!(self.kind, Kind::Logon | Kind::Change)
        {
            let request = wire::decode_credential_request(message)?;
            let mut seen = std::collections::HashSet::new();
            for prompt in &request.prompts {
                if !self.capabilities.contains(&prompt.credential_type)
                    || !seen.insert(prompt.credential_ref)
                {
                    return Err(WireError::UnknownValue);
                }
            }
            self.round = self.round.checked_add(1).ok_or(WireError::TooLong)?;
            return Ok(State::Prompt(request));
        }
        let result = match self.kind {
            Kind::Logon | Kind::Attest => Output::Grant {
                token,
                grant: wire::decode_access_granted(message)?,
            },
            Kind::Change => {
                wire::decode_credential_changed(message)?;
                Output::Changed
            }
            Kind::Query => {
                wire::decode_session_end_allowed(message)?;
                Output::Allowed
            }
            Kind::End => Output::Ended(wire::decode_session_ended(message)?),
            _ => return Err(WireError::UnexpectedMessage(message_type)),
        };
        Ok(State::Complete(result))
    }

    fn accept_self(&self, message: &[u8], message_type: u16) -> Result<State, WireError> {
        if message_type == lps::MSG_FAILED {
            let (code, reason) = lps::decode_failed_code(message)?;
            return Ok(State::Denied(Failure {
                category: 7,
                code,
                message: reason,
                unknown: false,
            }));
        }
        if self.kind == Kind::Account {
            Ok(State::Complete(Output::Account(lps::decode_self(message)?)))
        } else {
            lps::decode_done(message)?;
            Ok(State::Complete(Output::Changed))
        }
    }
}

fn error_category(error: &io::Error) -> u32 {
    match error.kind() {
        io::ErrorKind::TimedOut => 2,
        io::ErrorKind::InvalidData => 3,
        io::ErrorKind::NotFound
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::PermissionDenied => 1,
        _ => 4,
    }
}
