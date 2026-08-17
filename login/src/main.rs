//! **login** — Peios' `/bin/login`, a PGSS Logon originator for terminal
//! sessions.
//!
//! Collects an identifier and whatever credentials the authority asks for,
//! installs the token it is given, and execs the user's shell.
//!
//! # It does not know what a password is
//!
//! That is the point of a conversational protocol, and it is worth stating
//! plainly because it constrains every change to this file. `login` renders the
//! prompts the authority sends and returns the answers. It does not decide what
//! to ask for, it does not know which credentials this principal requires, and
//! it has no opinion about multi-factor.
//!
//! So adding TOTP, or expiry-forces-change, or smartcards, changes authd and
//! leaves this program alone. The moment `login` contains a rule about *what*
//! to ask, that property is gone.
//!
//! # It installs the token on itself
//!
//! `login` makes the user's token its own primary token and then execs the
//! shell, rather than forking a child to run as the user. This is what keeps
//! the authority out of process creation: authd never learns about ttys,
//! environments, or session leadership, and stays small enough to audit.
//!
//! `exec` also replaces the address space, so the credential material this
//! process handled does not survive into the user's shell.


use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitCode};

use libauthd::transport::{recv_message_with_fd, send_message};
use libauthd::wire::{
    self, CredentialResponse, CredentialType, IdentifierType, LogonStart, LogonType,
    MSG_ACCESS_DENIED, MSG_ACCESS_GRANTED, MSG_CREDENTIAL_REQUEST, Answer, Profile,
    decode_access_denied, decode_access_granted, decode_credential_request, decode_header,
    encode_credential_response, encode_logon_start,
};
use libauthd::LOGON_SOCKET_PATH;
use libtty as tty;
use peios::token::Token;

/// The shell handed to a successful logon.
const DEFAULT_SHELL: &str = "/bin/sh";

/// Credential types this build can render. An authority must not prompt for
/// anything outside this list, which is what lets new types be added without
/// breaking older clients like this one.
fn supported() -> Vec<CredentialType> {
    vec![CredentialType::Password]
}

struct Options {
    username: Option<String>,
    /// `-p`: keep the inherited environment instead of building a fresh one.
    preserve_environment: bool,
    /// `-h <host>`: the remote peer, for a logon originated on its behalf.
    remote_host: Option<String>,
}

fn main() -> ExitCode {
    let options = match parse_arguments() {
        Ok(options) => options,
        Err(message) => {
            eprintln!("login: {message}");
            return ExitCode::FAILURE;
        }
    };

    match run(options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("login: {message}");
            ExitCode::FAILURE
        }
    }
}

/// The conventional `/bin/login` surface, so an existing `getty` can drive this
/// unchanged.
///
/// `-f` (skip authentication) is deliberately **not** implemented. On Linux it
/// means "trust me, they are already authenticated", gated only by the caller
/// being root. On Peios that decision belongs to the authority, taken from the
/// verified peer — not to a flag this program believes. Implementing it here
/// would put an authentication bypass in an unprivileged process.
fn parse_arguments() -> Result<Options, String> {
    let mut options = Options {
        username: None,
        preserve_environment: false,
        remote_host: None,
    };

    let mut arguments = std::env::args().skip(1);
    let mut positional_only = false;

    while let Some(argument) = arguments.next() {
        if positional_only || !argument.starts_with('-') {
            if options.username.is_some() {
                return Err(format!("unexpected argument: {argument}"));
            }
            options.username = Some(argument);
            continue;
        }

        match argument.as_str() {
            "--" => positional_only = true,
            "-p" => options.preserve_environment = true,
            "-H" => {} // Accepted and ignored: suppresses the hostname banner.
            "-h" => {
                options.remote_host = Some(
                    arguments
                        .next()
                        .ok_or_else(|| "-h requires a hostname".to_string())?,
                );
            }
            "-f" => {
                return Err(
                    "-f is not supported: pre-authenticated logon is the authority's decision"
                        .into(),
                );
            }
            other => return Err(format!("unknown option: {other}")),
        }
    }

    Ok(options)
}

fn run(options: Options) -> Result<(), String> {
    become_session_leader();

    let username = match options.username {
        Some(name) => name,
        None => tty::prompt_line("Username: ").map_err(|e| format!("could not read username: {e}"))?,
    };

    if username.is_empty() {
        return Err("no username given".into());
    }

    let socket = UnixStream::connect(LOGON_SOCKET_PATH)
        .map_err(|e| format!("could not reach the logon authority: {e}"))?;

    let start = LogonStart {
        logon_type: LogonType::Interactive,
        identifier_type: IdentifierType::Username,
        identifier: username.as_bytes().to_vec(),
        tty: current_tty(),
        remote_host: options.remote_host,
        supported_credential_types: supported(),
    };

    send_message(
        &socket,
        &encode_logon_start(&start).map_err(|e| format!("could not encode logon: {e:?}"))?,
    )
    .map_err(|e| format!("could not send logon: {e}"))?;

    let (token, profile) = converse(&socket)?;

    // Become the user, then hand the terminal to their shell. Dropping the
    // socket and the token descriptor first is belt-and-braces — both are
    // O_CLOEXEC — but it keeps the window they exist in as short as the code
    // can express.
    token
        .install()
        .map_err(|e| format!("could not assume the granted identity: {e}"))?;
    drop(token);
    drop(socket);

    exec_shell(&username, &profile, options.preserve_environment)
}

/// Run the conversation to a terminal state, returning the granted token and
/// the profile the authority sent with it.
fn converse(socket: &UnixStream) -> Result<(Token, Profile), String> {
    loop {
        let (message, descriptor) = recv_message_with_fd(&wire::FRAMING, socket)
            .map_err(|e| format!("lost the authority: {e}"))?;

        let (message_type, _) = decode_header(message.expose())
            .map_err(|e| format!("malformed reply from the authority: {e:?}"))?;

        match message_type {
            MSG_CREDENTIAL_REQUEST => {
                let request = decode_credential_request(message.expose())
                    .map_err(|e| format!("malformed credential request: {e:?}"))?;

                for note in &request.messages {
                    tty::show(&note.text).map_err(|e| format!("could not write to terminal: {e}"))?;
                }

                let mut answers = Vec::with_capacity(request.prompts.len());
                for prompt in &request.prompts {
                    // The closed-enum rule: an unrenderable type must fail the
                    // logon rather than be guessed at, because guessing risks
                    // echoing a secret to the screen. Unreachable unless an
                    // authority ignores our advertised capabilities.
                    let data = match prompt.credential_type {
                        CredentialType::Password => {
                            tty::prompt_secret(&format!("{}: ", prompt.credential_name))
                                .map_err(|e| format!("could not read credential: {e}"))?
                        }
                    };
                    answers.push(Answer {
                        credential_ref: prompt.credential_ref,
                        data,
                    });
                }

                let encoded = encode_credential_response(&CredentialResponse { answers })
                    .map_err(|e| format!("could not encode answers: {e:?}"))?;
                send_message(socket, encoded.expose())
                    .map_err(|e| format!("could not send answers: {e}"))?;
            }

            MSG_ACCESS_GRANTED => {
                let granted = decode_access_granted(message.expose())
                    .map_err(|e| format!("malformed grant: {e:?}"))?;
                let descriptor: OwnedFd = descriptor
                    .ok_or("the authority granted access but sent no token")?;
                eprintln!("login: session {} established", granted.session_id);
                return Ok((Token::from(descriptor), granted.profile));
            }

            MSG_ACCESS_DENIED => {
                let denied = decode_access_denied(message.expose())
                    .map_err(|e| format!("malformed denial: {e:?}"))?;
                return Err(if denied.reason.is_empty() {
                    format!("{:?}", denied.denial)
                } else {
                    denied.reason
                });
            }

            other => return Err(format!("unexpected message from the authority: {other:#06x}")),
        }
    }
}

/// Take the terminal as our controlling tty.
///
/// Both calls are allowed to fail: peinit may already have placed us in our own
/// session, in which case `setsid` returns EPERM and there is nothing to fix.
/// A hard failure here would break the common case to satisfy the uncommon one.
fn become_session_leader() {
    unsafe {
        libc::setsid();
        libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY, 0);
    }
}

fn current_tty() -> Option<String> {
    let name = unsafe { libc::ttyname(libc::STDIN_FILENO) };
    if name.is_null() {
        return None;
    }
    unsafe { std::ffi::CStr::from_ptr(name) }
        .to_str()
        .ok()
        .map(str::to_string)
}

/// Replace this process with the user's login shell.
///
/// `argv[0]` carries a leading dash — the convention every shell reads as "this
/// is a login shell, run the profile files". Without it the user gets a shell
/// that has skipped their environment setup, which looks like a broken account
/// rather than a missing dash. The dash goes on the shell's *basename*, since
/// `-/bin/bash` is not what any shell tests for.
///
/// # The profile is used where it is given and defaulted where it is not
///
/// PGSS Logon says every profile field may be empty, and that an authority which
/// knows nothing about home directories is conforming — so each field has a
/// fallback here rather than being required. An authority that says nothing
/// produces exactly the session this did before the profile existed.
///
/// **The home directory is not created, and a missing one is not fatal.** The
/// `chdir` is attempted and its failure reported; the user still gets a shell,
/// in `/`. A login that refused to proceed because a directory was absent would
/// turn a cosmetic problem into being locked out, and creating it here would put
/// directory provisioning inside the one program that must keep working when
/// everything else is broken.
fn exec_shell(
    username: &str,
    profile: &Profile,
    preserve_environment: bool,
) -> Result<(), String> {
    let shell = if profile.shell.is_empty() {
        DEFAULT_SHELL
    } else {
        profile.shell.as_str()
    };
    let home = if profile.home.is_empty() {
        "/"
    } else {
        profile.home.as_str()
    };

    if std::env::set_current_dir(home).is_err() {
        eprintln!("login: {home} is not reachable; starting in /");
        let _ = std::env::set_current_dir("/");
    }

    let mut command = Command::new(shell);
    command.arg0(format!(
        "-{}",
        Path::new(shell)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("sh")
    ));

    if !preserve_environment {
        let term = std::env::var("TERM").unwrap_or_else(|_| "linux".into());
        command
            .env_clear()
            .env("HOME", home)
            .env("SHELL", shell)
            .env("USER", username)
            .env("LOGNAME", username)
            .env("PATH", "/bin")
            .env("TERM", term);
    }

    // Only returns on failure.
    Err(format!("could not start {shell}: {}", command.exec()))
}
