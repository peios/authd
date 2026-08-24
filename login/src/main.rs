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

use libauthd::ident;
use libauthd::transport::{recv_message, recv_message_with_fd, send_message};
use libauthd::wire::{
    self, CredentialResponse, CredentialType, Denial, IdentifierType, LogonStart, LogonType,
    MSG_ACCESS_DENIED, MSG_ACCESS_GRANTED, MSG_CREDENTIAL_REQUEST, Answer, Profile,
    decode_access_denied, decode_access_granted, decode_credential_request, decode_header,
    encode_credential_response, encode_logon_start,
};
use libauthd::LOGON_SOCKET_PATH;

/// How long to wait on an existence lookup before treating it as unanswered.
/// Short: it runs before a prompt, and a login that appears to hang is worse
/// than one that falls through to asking for a name.
const IDENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
use libtty as tty;
use peios::token::Token;

/// The shell handed to a successful logon.
const DEFAULT_SHELL: &str = "/bin/sh";

/// A profile path, or the default when it is absent or not absolute.
///
/// `field` names the value on the terminal when it is rejected, so a principal
/// dropped into `/bin/sh` at `/` can tell why.
fn absolute_or_default<'a>(value: &'a str, default: &'a str, field: &str) -> &'a str {
    if value.is_empty() {
        return default;
    }
    if !value.starts_with('/') {
        eprintln!("login: {field} {value:?} is not an absolute path; using {default}");
        return default;
    }
    value
}

/// Credential types this build can render. An authority must not prompt for
/// anything outside this list, which is what lets new types be added without
/// breaking older clients like this one.
fn supported() -> Vec<CredentialType> {
    vec![CredentialType::Password]
}

/// How the principal is chosen, and what a failure means.
///
/// The three named forms differ *only* in what happens when the attempt does
/// not succeed. None of them tells the authority anything different about who
/// they are — `--try` is a statement about this program's willingness to ask
/// again, not a claim about the principal.
enum Identify {
    /// Nothing given. Ask for a name.
    Prompt,
    /// A bare name. A denial ends the program: an operator who named a
    /// principal wants that principal, and silently offering a different prompt
    /// would hide the failure.
    Named(String),
    /// `--try NAME`. Attempt NAME; on a denial that another principal could
    /// survive, fall back to a full prompt.
    Try(String),
    /// `--try-no-password NAME`. Attempt NAME while advertising that this
    /// client can collect nothing, so only a principal who needs no credential
    /// can succeed (PGSS Logon §4.1). Falls back the same way.
    ///
    /// The distinction from `--try` is what it offers to collect, not what it
    /// claims: the authority still decides, and a client that lies about its
    /// capabilities only denies itself prompts it could have rendered.
    TryNoPassword(String),
}

struct Options {
    identify: Identify,
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
    parse_from(std::env::args().skip(1))
}

fn parse_from<I: Iterator<Item = String>>(arguments: I) -> Result<Options, String> {
    let mut options = Options {
        identify: Identify::Prompt,
        preserve_environment: false,
        remote_host: None,
    };

    let mut arguments = arguments;
    let mut positional_only = false;

    while let Some(argument) = arguments.next() {
        if positional_only || !argument.starts_with('-') {
            if !matches!(options.identify, Identify::Prompt) {
                return Err(format!("unexpected argument: {argument}"));
            }
            options.identify = Identify::Named(argument);
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
            "--try" | "--try-no-password" => {
                if !matches!(options.identify, Identify::Prompt) {
                    return Err(format!("{argument} conflicts with a name already given"));
                }
                let name = arguments
                    .next()
                    .ok_or_else(|| format!("{argument} requires a username"))?;
                options.identify = if argument == "--try" {
                    Identify::Try(name)
                } else {
                    Identify::TryNoPassword(name)
                };
            }
            other => return Err(format!("unknown option: {other}")),
        }
    }

    Ok(options)
}

fn run(options: Options) -> Result<(), String> {
    become_session_leader();

    let remote = options.remote_host.as_deref();
    let (username, token, profile) = match options.identify {
        Identify::Prompt => prompted(remote)?,

        // A named principal that does not exist is said plainly. Existence
        // comes from the *identity* channel, never from a logon denial: PGSS
        // Logon obligation 22 forbids an authority distinguishing an unknown
        // principal from a bad credential, while §6.6 states just as plainly
        // that `NotFound` is an ordinary answer here — "there is no credential,
        // and NotFound is an ordinary answer that this chapter states plainly".
        Identify::Named(name) => {
            if let Existence::No = existence(&name) {
                return Err(format!("user {name} does not exist"));
            }
            let granted = attempt(&name, &supported(), remote).map_err(|r| r.reason)?;
            (name, granted.token, granted.profile)
        }

        Identify::Try(name) => match existence(&name) {
            // Nothing has been rendered yet, so this fallback is invisible —
            // which is the whole point of --try.
            Existence::No => prompted(remote)?,
            // NOT treated as absence. §6.6 calls this the most important rule
            // in the chapter: reporting an unreachable source as "no such user"
            // memoises an outage as a fact. Attempt anyway and let the logon
            // report the outage once, in one place.
            Existence::Yes | Existence::Unknown => {
                fall_back(attempt(&name, &supported(), remote), name, remote)?
            }
        },

        // No lookup. An empty capability list already asks exactly the right
        // question — "can this be completed with no interaction?" — and both
        // "has a password" and "does not exist" answer it the same way, which
        // is what keeps this from being an existence oracle.
        Identify::TryNoPassword(name) => fall_back(attempt(&name, &[], remote), name, remote)?,
    };

    // Become the user, then hand the terminal to their shell. Dropping the
    // token descriptor first is belt-and-braces — it is O_CLOEXEC — but it
    // keeps the window it exists in as short as the code can express.
    token
        .install()
        .map_err(|e| format!("could not assume the granted identity: {e}"))?;
    drop(token);

    exec_shell(&username, &profile, options.preserve_environment)
}

/// Take a rejected attempt to a full prompt, or give up.
///
/// # One rule decides whether the fallback is silent
///
/// **Say why only if the user was shown something.** A `--try` that got as far
/// as a password prompt has interrupted someone, and dropping them to
/// `Username:` with no explanation reads as a broken program — they typed a
/// password and got asked for a name. A `--try-no-password` that was refused
/// before any prompt was rendered has interrupted nobody, and announcing it
/// would put a line on the console of every machine where the principal simply
/// has a password, which is the ordinary case rather than an event.
///
/// So the rule is about what the person in front of the terminal saw, not about
/// which flag was passed — and the two flags get their different behaviour
/// without either of them naming it.
fn fall_back(
    outcome: Result<Granted, Rejected>,
    name: String,
    remote: Option<&str>,
) -> Result<(String, Token, Profile), String> {
    match outcome {
        Ok(granted) => Ok((name, granted.token, granted.profile)),
        // Nothing this program can do differently will help. Asking for another
        // name would offer a prompt that cannot work either.
        Err(rejected) if rejected.fatal => Err(rejected.reason),
        Err(rejected) => {
            if rejected.rendered {
                eprintln!("login: {}", rejected.reason);
            }
            prompted(remote)
        }
    }
}

/// Ask for a name and log in as whoever is given.
fn prompted(remote: Option<&str>) -> Result<(String, Token, Profile), String> {
    let username =
        tty::prompt_line("Username: ").map_err(|e| format!("could not read username: {e}"))?;
    if username.is_empty() {
        return Err("no username given".into());
    }
    let granted = attempt(&username, &supported(), remote).map_err(|r| r.reason)?;
    Ok((username, granted.token, granted.profile))
}

/// A completed logon.
struct Granted {
    token: Token,
    profile: Profile,
}

/// A logon that did not complete.
struct Rejected {
    reason: String,
    /// Whether retrying as a different principal could plausibly work. False
    /// for a transport failure, an unavailable authority, or a peer that may
    /// not originate this logon at all — none of which another name fixes.
    fatal: bool,
    /// Whether anything reached the user's terminal before the denial. Drives
    /// the fallback rule in [`fall_back`].
    rendered: bool,
}

/// Run one logon conversation to a terminal state.
fn attempt(
    username: &str,
    collectable: &[CredentialType],
    remote: Option<&str>,
) -> Result<Granted, Rejected> {
    let socket = UnixStream::connect(LOGON_SOCKET_PATH).map_err(|e| Rejected {
        reason: format!("could not reach the logon authority: {e}"),
        fatal: true,
        rendered: false,
    })?;

    let start = LogonStart {
        logon_type: LogonType::Interactive,
        identifier_type: IdentifierType::Username,
        identifier: username.as_bytes().to_vec(),
        tty: current_tty(),
        remote_host: remote.map(str::to_string),
        supported_credential_types: collectable.to_vec(),
    };

    let encoded = encode_logon_start(&start).map_err(|e| Rejected {
        reason: format!("could not encode logon: {e:?}"),
        fatal: true,
        rendered: false,
    })?;
    send_message(&socket, &encoded).map_err(|e| Rejected {
        reason: format!("could not send logon: {e}"),
        fatal: true,
        rendered: false,
    })?;

    let granted = converse(&socket)?;
    // Dropped before the caller can exec: the socket is the authority's view of
    // this conversation, and it has nothing left to say.
    drop(socket);
    Ok(granted)
}

/// A rejection nothing can be retried against: a transport failure, a malformed
/// message, or an authority that will not speak. Carries `rendered` so the
/// fallback rule still knows whether the user saw anything.
fn fatal(reason: String, rendered: bool) -> Rejected {
    Rejected {
        reason,
        fatal: true,
        rendered,
    }
}

/// Read the conversation to a terminal state.
///
/// Renders whatever the authority asks for and returns the answers. It decides
/// nothing about *what* is asked — see the module docs — so a passwordless
/// logon needs no special case here: the authority simply never sends a
/// credential request, and the first thing to arrive is the grant.
fn converse(socket: &UnixStream) -> Result<Granted, Rejected> {
    // Set the moment anything reaches the terminal, and never cleared.
    let mut rendered = false;

    loop {
        let (message, descriptor) = recv_message_with_fd(&wire::FRAMING, socket)
            .map_err(|e| fatal(format!("lost the authority: {e}"), rendered))?;

        let (message_type, _) = decode_header(message.expose()).map_err(|e| {
            fatal(
                format!("malformed reply from the authority: {e:?}"),
                rendered,
            )
        })?;

        match message_type {
            MSG_CREDENTIAL_REQUEST => {
                let request = decode_credential_request(message.expose())
                    .map_err(|e| fatal(format!("malformed credential request: {e:?}"), rendered))?;

                for note in &request.messages {
                    rendered = true;
                    tty::show(&note.text).map_err(|e| {
                        fatal(format!("could not write to terminal: {e}"), rendered)
                    })?;
                }

                let mut answers = Vec::with_capacity(request.prompts.len());
                for prompt in &request.prompts {
                    // The closed-enum rule: an unrenderable type must fail the
                    // logon rather than be guessed at, because guessing risks
                    // echoing a secret to the screen. Unreachable unless an
                    // authority ignores our advertised capabilities.
                    let data = match prompt.credential_type {
                        CredentialType::Password => {
                            rendered = true;
                            tty::prompt_secret(&format!("{}: ", prompt.credential_name)).map_err(
                                |e| fatal(format!("could not read credential: {e}"), rendered),
                            )?
                        }
                    };
                    answers.push(Answer {
                        credential_ref: prompt.credential_ref,
                        data,
                    });
                }

                let encoded = encode_credential_response(&CredentialResponse { answers })
                    .map_err(|e| fatal(format!("could not encode answers: {e:?}"), rendered))?;
                send_message(socket, encoded.expose())
                    .map_err(|e| fatal(format!("could not send answers: {e}"), rendered))?;
            }

            MSG_ACCESS_GRANTED => {
                let granted = decode_access_granted(message.expose())
                    .map_err(|e| fatal(format!("malformed grant: {e:?}"), rendered))?;
                let descriptor: OwnedFd = descriptor.ok_or_else(|| {
                    fatal(
                        "the authority granted access but sent no token".into(),
                        rendered,
                    )
                })?;
                eprintln!("login: session {} established", granted.session_id);
                return Ok(Granted {
                    token: Token::from(descriptor),
                    profile: granted.profile,
                });
            }

            MSG_ACCESS_DENIED => {
                let denied = decode_access_denied(message.expose())
                    .map_err(|e| fatal(format!("malformed denial: {e:?}"), rendered))?;
                return Err(Rejected {
                    reason: if denied.reason.is_empty() {
                        format!("{:?}", denied.denial)
                    } else {
                        denied.reason
                    },
                    fatal: !retryable(denied.denial),
                    rendered,
                });
            }

            other => {
                return Err(fatal(
                    format!("unexpected message from the authority: {other:#06x}"),
                    rendered,
                ));
            }
        }
    }
}

/// Whether asking again, as someone else, could plausibly succeed.
///
/// The split follows what the denial is *about*. `AuthenticationFailed` and
/// `AccountRestricted` are about the principal, so another principal may fare
/// better. Everything else is about this peer, this connection or this
/// authority — `PermissionDenied` and `LogonTypeNotPermitted` say the caller
/// may not originate this logon at all, and no name changes that — so falling
/// back would only offer a prompt that cannot work either.
fn retryable(denial: Denial) -> bool {
    matches!(
        denial,
        Denial::AuthenticationFailed | Denial::AccountRestricted
    )
}

/// Whether a principal exists, asked on the identity channel.
enum Existence {
    Yes,
    No,
    /// Not answered. **Never read as absence** — see PGSS Logon §6.6: an
    /// unreachable source reported as `NotFound` turns an outage into a fact,
    /// and a caller that acts on it locks someone out for as long as the
    /// answer is believed.
    Unknown,
}

/// Ask `/run/ident.sock` whether a name resolves to a principal.
///
/// This is the *only* place `login` learns whether an account exists, and it is
/// deliberately not the logon socket. Chapter 6 exists to answer this and its
/// socket must grant connect access to every principal that runs ordinary
/// programs, because withholding it "would not protect anything" — the same
/// answer is already available to anything that calls `getpwnam`. Chapter 4
/// must never answer it (obligation 22).
///
/// No fields are requested: existence is the whole question, and asking for a
/// home directory this program will not use would invite the authority to
/// withhold a field and turn a two-state answer into three.
fn existence(name: &str) -> Existence {
    let Ok(socket) = UnixStream::connect(libauthd::IDENT_SOCKET_PATH) else {
        return Existence::Unknown;
    };
    let _ = socket.set_read_timeout(Some(IDENT_TIMEOUT));
    let _ = socket.set_write_timeout(Some(IDENT_TIMEOUT));

    let tag = 1;
    let Ok(request) = ident::encode_lookup(&ident::Lookup {
        tag,
        key: ident::Key::Name(name.to_string()),
        kind: ident::Kind::Principal,
        fields: ident::Fields::empty(),
    }) else {
        return Existence::Unknown;
    };
    if send_message(&socket, &request).is_err() {
        return Existence::Unknown;
    }
    let Ok(received) = recv_message(&wire::FRAMING, &socket) else {
        return Existence::Unknown;
    };
    let Ok(reply) = ident::decode_lookup_reply(received.expose()) else {
        return Existence::Unknown;
    };
    // Only ever one request outstanding, so a mismatched tag means this is not
    // the stream it should be.
    if reply.tag != tag {
        return Existence::Unknown;
    }

    match reply.outcome {
        ident::Outcome::Found => Existence::Yes,
        ident::Outcome::NotFound => Existence::No,
        ident::Outcome::Unavailable | ident::Outcome::Refused | ident::Outcome::Malformed => {
            Existence::Unknown
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
    // Client obligation 16: a relative `shell` is never executed and a relative
    // `home` is never resolved against login's own working directory. A `shell`
    // containing no separator is relative too, and must not be resolved against
    // a search path.
    //
    // Without this, `Command::new("sh")` reaches `execvp` and gets a PATH
    // search — performed by a process that has just installed the principal's
    // token. §2.9's reasoning that a wrong `profile` "would produce an
    // inconvenient session rather than an unsafe one" holds only because the
    // client refuses a relative path; it was not refusing.
    //
    // A rejected value falls back exactly as an empty one does, and says so,
    // matching how an unreachable home is already reported.
    let shell = absolute_or_default(&profile.shell, DEFAULT_SHELL, "shell");
    let home = absolute_or_default(&profile.home, "/", "home directory");

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

#[cfg(test)]
mod tests {

    /// Client obligation 16: a relative `shell` is never executed and a
    /// relative `home` is never resolved against login's own cwd. A `shell`
    /// containing no separator is relative too — `Command::new("sh")` reaches
    /// `execvp` and gets a PATH search, performed by a process that has just
    /// installed the principal's token.
    #[test]
    fn a_relative_shell_or_home_falls_back_to_the_default() {
        for relative in ["sh", "bin/sh", "./sh", "../bin/sh", "~/bin/sh"] {
            assert_eq!(
                absolute_or_default(relative, "/bin/sh", "shell"),
                "/bin/sh",
                "{relative} is relative and must not be executed"
            );
        }
        assert_eq!(absolute_or_default("home/jack", "/", "home directory"), "/");
    }

    /// An empty field already fell back; that must not change.
    #[test]
    fn an_empty_field_still_falls_back() {
        assert_eq!(absolute_or_default("", "/bin/sh", "shell"), "/bin/sh");
        assert_eq!(absolute_or_default("", "/", "home directory"), "/");
    }

    /// And an absolute one is used as given, or the check would be a rewrite.
    #[test]
    fn an_absolute_path_is_used_unchanged() {
        assert_eq!(absolute_or_default("/bin/bash", "/bin/sh", "shell"), "/bin/bash");
        assert_eq!(absolute_or_default("/home/jack", "/", "home directory"), "/home/jack");
        // A path with a space or an odd name is still absolute.
        assert_eq!(absolute_or_default("/opt/my shell", "/bin/sh", "shell"), "/opt/my shell");
    }
    use super::*;

    fn parse(arguments: &[&str]) -> Result<Options, String> {
        parse_from(arguments.iter().map(|a| (*a).to_string()))
    }

    #[test]
    fn a_bare_name_is_a_named_logon() {
        let options = parse(&["jack"]).expect("must parse");
        assert!(matches!(options.identify, Identify::Named(name) if name == "jack"));
    }

    #[test]
    fn no_arguments_prompts() {
        assert!(matches!(
            parse(&[]).expect("must parse").identify,
            Identify::Prompt
        ));
    }

    #[test]
    fn try_and_try_no_password_take_a_name() {
        assert!(matches!(
            parse(&["--try", "jack"]).expect("must parse").identify,
            Identify::Try(name) if name == "jack"
        ));
        let options = parse(&["--try-no-password", "peios"]).expect("must parse");
        assert!(matches!(
            options.identify,
            Identify::TryNoPassword(name) if name == "peios"
        ));
    }

    #[test]
    fn try_without_a_name_is_an_error() {
        assert!(parse(&["--try"]).is_err());
        assert!(parse(&["--try-no-password"]).is_err());
    }

    /// Two names is a mistake worth naming, whichever way round they are given.
    /// Silently preferring one would make `login --try a b` do something the
    /// operator did not ask for.
    #[test]
    fn a_name_cannot_be_given_twice() {
        assert!(parse(&["--try", "jack", "root"]).is_err());
        assert!(parse(&["root", "--try", "jack"]).is_err());
        assert!(parse(&["jack", "root"]).is_err());
    }

    /// `--try` must not swallow a following option as its name. It does take
    /// the next word whatever it is, so this pins the behaviour rather than
    /// asserting a rejection: `--try -p` logs in as a principal called `-p`,
    /// which fails at the authority rather than silently enabling `-p`.
    #[test]
    fn try_takes_the_next_word_as_its_name() {
        let options = parse(&["--try", "-p"]).expect("must parse");
        assert!(matches!(options.identify, Identify::Try(name) if name == "-p"));
        assert!(!options.preserve_environment);
    }

    #[test]
    fn pre_authenticated_logon_is_still_refused() {
        assert!(parse(&["-f", "jack"]).is_err());
    }

    /// The fallback rule's other half. A denial about the *principal* can be
    /// retried as someone else; one about this peer or this authority cannot,
    /// and offering a prompt that also cannot work would loop a console.
    #[test]
    fn only_principal_denials_are_retryable() {
        for denial in [Denial::AuthenticationFailed, Denial::AccountRestricted] {
            assert!(retryable(denial), "{denial:?} should fall back");
        }
        for denial in [
            Denial::PermissionDenied,
            Denial::LogonTypeNotPermitted,
            Denial::AuthorityUnavailable,
            Denial::ConversationLimit,
            Denial::Internal,
            Denial::MalformedRequest,
            Denial::UnsupportedVersion,
        ] {
            assert!(!retryable(denial), "{denial:?} must not fall back");
        }
    }
}
