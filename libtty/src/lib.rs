//! Terminal input, including reading a secret without echoing it.
//!
//! Small and hand-rolled rather than pulled from a crate: this is a handful of
//! `termios` calls, and the tools that use it handle credentials, so their
//! dependency lists are worth keeping legible.
//!
//! Shared by `login` and `lps` — both have to take a password from a terminal
//! and neither should own a second copy of the guard that restores echo
//! afterwards.

use std::io::{self, BufRead, Read, Write};

use libauthd::Secret;

/// The longest single answer accepted from a terminal.
///
/// The protocol's own ceiling, so a passphrase this collector accepts is one
/// the wire accepts. It used to be 1024, which silently truncated anything
/// longer and sent the prefix: the logon then failed with
/// `AuthenticationFailed`, indistinguishable from a wrong password, so a
/// principal with a long passphrase simply could not sign in with nothing
/// anywhere saying why — and the remainder stayed in the terminal's input
/// queue to be read by whatever ran next, which after a failed logon is
/// usually a shell.
const MAX_ANSWER_BYTES: usize = libauthd::wire::MAX_CREDENTIAL_BYTES;

/// Restores the terminal's echo setting when dropped.
///
/// A guard rather than a matched pair of calls because the read between them
/// can fail or the process can be interrupted, and a terminal left with echo
/// disabled is a broken terminal — the next person to type sees nothing.
struct EchoGuard {
    fd: libc::c_int,
    original: libc::termios,
    restore: bool,
}

impl EchoGuard {
    /// Disable echo on `fd`, returning a guard that restores it.
    fn suppress(fd: libc::c_int) -> io::Result<Self> {
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            // Not a terminal (a pipe under test, say). Nothing to suppress, and
            // nothing to restore — but say so rather than pretending.
            return Err(io::Error::last_os_error());
        }

        let mut quiet = original;
        quiet.c_lflag &= !libc::ECHO;
        // Keep ECHONL so the newline the user types still moves the cursor,
        // otherwise the prompt and whatever follows it run together.
        quiet.c_lflag |= libc::ECHONL;

        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &quiet) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            fd,
            original,
            restore: true,
        })
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        if self.restore {
            unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original) };
        }
    }
}

/// Read one line, echoing it. For non-secret input such as a username.
pub fn prompt_line(prompt: &str) -> io::Result<String> {
    write_prompt(prompt)?;
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer)?;
    Ok(buffer.trim_end_matches(['\r', '\n']).to_string())
}

/// Read one line without echoing it, into a buffer that wipes itself.
///
/// The intermediate read buffer is a [`Secret`] too, not an ordinary array —
/// otherwise the credential would sit in a stack buffer nobody erases, and the
/// self-wiping return value would be theatre.
pub fn prompt_secret(prompt: &str) -> io::Result<Secret> {
    write_prompt(prompt)?;

    // A `Password` is defined by its collection method — "a line of text, not
    // echoed" — and that is the whole content of the credential type. So a
    // terminal whose echo cannot be suppressed cannot render the prompt, and
    // §2.8's rule for a prompt a client cannot render applies: fail rather than
    // guess, precisely because guessing may echo a secret to the screen.
    //
    // The old code swallowed the failure with `.ok()`, reasoning that a
    // non-terminal input has no echo to suppress. That is true for a pipe and
    // false for a terminal whose `tcsetattr` failed, and an `Err` alone cannot
    // tell them apart. `isatty` can.
    let _guard = match EchoGuard::suppress(libc::STDIN_FILENO) {
        Ok(guard) => Some(guard),
        Err(error) => {
            if unsafe { libc::isatty(libc::STDIN_FILENO) } == 1 {
                return Err(io::Error::other(format!(
                    "refusing to read a secret from a terminal whose echo could not be \
                     suppressed: {error}"
                )));
            }
            // Not a terminal — a pipe under test, say. There is no echo to
            // suppress and nothing to restore.
            None
        }
    };

    let mut buffer = Secret::zeroed(MAX_ANSWER_BYTES + 1);
    let read = io::stdin().read(buffer.expose_mut())?;

    let line = &buffer.expose()[..read];
    let trimmed = line
        .iter()
        .position(|byte| *byte == b'\n' || *byte == b'\r')
        .unwrap_or(line.len());

    // One byte of headroom is read beyond the ceiling purely so this can tell
    // "exactly at the limit" from "over it". A client MUST NOT silently
    // truncate an answer; one whose collection method admits fewer bytes fails
    // the conversation instead.
    if trimmed > MAX_ANSWER_BYTES {
        return Err(io::Error::other(format!(
            "the answer is longer than the {MAX_ANSWER_BYTES}-byte maximum"
        )));
    }

    Ok(Secret::from_slice(&line[..trimmed]))
}

/// Show a message from the authority.
pub fn show(text: &str) -> io::Result<()> {
    let mut out = io::stdout();
    writeln!(out, "{text}")?;
    out.flush()
}

fn write_prompt(prompt: &str) -> io::Result<()> {
    let mut out = io::stdout();
    write!(out, "{prompt}")?;
    out.flush()
}

/// Read one line of secret material from standard input, without prompting and
/// without assuming a terminal.
///
/// For callers driven by a script or a pipe. It reads exactly one line — where
/// [`prompt_secret`] takes a fixed-size read and trims — because a pipe may
/// hold several lines and consuming more than one would swallow input intended
/// for whatever asks next.
///
/// The intermediate buffer is wiped before it is dropped, for the same reason
/// [`prompt_secret`] reads into a [`Secret`]: a credential left in freed memory
/// is a credential leaked, whichever buffer it was in.
pub fn read_line_secret() -> io::Result<Secret> {
    let mut buffer = Vec::new();
    io::stdin().lock().read_until(b'\n', &mut buffer)?;

    let end = buffer
        .iter()
        .position(|byte| *byte == b'\n' || *byte == b'\r')
        .unwrap_or(buffer.len());
    let secret = Secret::from_slice(&buffer[..end]);

    for byte in buffer.iter_mut() {
        // SAFETY: `buffer` is live and exclusively borrowed. Volatile so the
        // store is not elided as dead.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

    Ok(secret)
}

/// Whether standard input is a terminal.
///
/// Decides whether a password can be confirmed by asking twice. Down a pipe
/// there is nobody to ask, and prompting again would silently consume the next
/// line of whatever is driving the tool.
pub fn stdin_is_a_terminal() -> bool {
    io::IsTerminal::is_terminal(&io::stdin())
}
