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

use auth_core::Secret;

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
const MAX_ANSWER_BYTES: usize = auth_core::wire::MAX_CREDENTIAL_BYTES;

/// Restores the terminal's echo setting when dropped.
///
/// A guard rather than a matched pair of calls because the read between them
/// can fail or unwind, and a terminal left with echo
/// disabled is a broken terminal — the next person to type sees nothing.
struct EchoGuard {
    fd: libc::c_int,
    original: libc::termios,
}

impl EchoGuard {
    /// Disable echo on `fd`, returning a guard that restores it.
    fn suppress(fd: libc::c_int) -> io::Result<Self> {
        // SAFETY: termios contains scalar fields; tcgetattr initializes the live output.
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: original is writable and lives through the syscall.
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

        // SAFETY: quiet is a complete termios copied from tcgetattr.
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &quiet) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd, original })
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        // Drop cannot report a restoration failure. Make a best-effort attempt
        // even when the read failed; the caller still receives its original error.
        // SAFETY: original came from tcgetattr and remains valid through this call.
        let _ = unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original) };
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
            // SAFETY: isatty accepts any descriptor and reports invalid ones as errors.
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
/// Intermediate chunks are self-wiping [`Secret`] buffers, including when a
/// partial read fails. No growing plaintext allocation can leave an unwiped
/// previous allocation behind when the input line grows.
pub fn read_line_secret() -> io::Result<Secret> {
    read_secret_line(&mut io::stdin().lock())
}

fn read_secret_line(reader: &mut impl BufRead) -> io::Result<Secret> {
    let mut chunks = Vec::new();
    loop {
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if available.is_empty() {
            break;
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |index| index + 1);
        chunks.push(Secret::from_slice(&available[..consumed]));
        reader.consume(consumed);
        if newline.is_some() {
            break;
        }
    }

    // Consume through LF even if CR trimmed the answer earlier, matching the
    // one-line input contract. Only Secret handles move when chunks grows.
    let length = chunks
        .iter()
        .flat_map(|chunk| chunk.expose())
        .take_while(|byte| **byte != b'\r' && **byte != b'\n')
        .count();
    let mut secret = Secret::zeroed(length);
    let mut offset = 0;
    for chunk in chunks {
        let copied = chunk.len().min(length - offset);
        secret.expose_mut()[offset..offset + copied].copy_from_slice(&chunk.expose()[..copied]);
        offset += copied;
    }
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

#[cfg(test)]
mod tests {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    use std::io::{self, BufRead, BufReader, Cursor, Read};

    use super::{MAX_ANSWER_BYTES, read_secret_line};

    // Only the requesting test thread tracks a single exact-sized allocation.
    // Observe bytes while the allocation is still valid, immediately before
    // returning it to System. This tests wiping without reading freed memory.
    thread_local! {
        static TRACK_BYTES: Cell<usize> = const { Cell::new(0) };
        static TRACK_POINTER: Cell<*mut u8> = const { Cell::new(std::ptr::null_mut()) };
        static OBSERVED_WIPE: Cell<Option<bool>> = const { Cell::new(None) };
    }

    struct ObservingAllocator;

    // SAFETY: all allocation operations delegate to System with unchanged
    // layouts. Observation reads only the live allocation passed to dealloc.
    unsafe impl GlobalAlloc for ObservingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: GlobalAlloc supplies a valid layout, forwarded unchanged.
            let pointer = unsafe { System.alloc(layout) };
            let _ = TRACK_BYTES.try_with(|size| {
                if size.get() == layout.size() && !pointer.is_null() {
                    let _ = TRACK_POINTER.try_with(|tracked| {
                        if tracked.get().is_null() {
                            tracked.set(pointer);
                        }
                    });
                }
            });
            pointer
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            let _ = TRACK_POINTER.try_with(|tracked| {
                if tracked.get() == pointer {
                    // SAFETY: this allocation remains live until System.dealloc;
                    // the tracked credential buffer initialized all its bytes.
                    let bytes = unsafe { std::slice::from_raw_parts(pointer, layout.size()) };
                    let _ = OBSERVED_WIPE.try_with(|result| {
                        result.set(Some(bytes.iter().all(|byte| *byte == 0)));
                    });
                    tracked.set(std::ptr::null_mut());
                }
            });
            // SAFETY: pointer and layout come unchanged from the allocator contract.
            unsafe { System.dealloc(pointer, layout) };
        }
    }

    #[global_allocator]
    static ALLOCATOR: ObservingAllocator = ObservingAllocator;

    struct PartialFailure {
        remaining: &'static [u8],
        interrupted: bool,
    }

    impl Read for PartialFailure {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let available = self.fill_buf()?;
            let count = available.len().min(output.len());
            output[..count].copy_from_slice(&available[..count]);
            self.consume(count);
            Ok(count)
        }
    }

    impl BufRead for PartialFailure {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            if self.interrupted {
                self.interrupted = false;
                return Err(io::ErrorKind::Interrupted.into());
            }
            if self.remaining.is_empty() {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            Ok(self.remaining)
        }

        fn consume(&mut self, count: usize) {
            self.remaining = &self.remaining[count..];
        }
    }

    struct WipeObservation;

    impl WipeObservation {
        fn start(bytes: usize) -> Self {
            OBSERVED_WIPE.set(None);
            TRACK_POINTER.set(std::ptr::null_mut());
            TRACK_BYTES.set(bytes);
            Self
        }
    }

    impl Drop for WipeObservation {
        fn drop(&mut self) {
            TRACK_BYTES.set(0);
            TRACK_POINTER.set(std::ptr::null_mut());
        }
    }

    #[test]
    fn partial_read_error_wipes_the_owned_credential_buffer() {
        const CREDENTIAL: &[u8] = b"partial-credential-data!";
        let mut reader = PartialFailure {
            remaining: CREDENTIAL,
            interrupted: false,
        };
        let observation = WipeObservation::start(CREDENTIAL.len());
        let result = read_secret_line(&mut reader);
        let wiped = OBSERVED_WIPE.get();
        drop(observation);
        assert_eq!(
            result.expect_err("injected read failure").kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            wiped,
            Some(true),
            "credential allocation must be wiped before release"
        );
        assert!(
            reader.remaining.is_empty(),
            "the failure follows partial input"
        );
    }

    #[test]
    fn fragmented_input_leaves_the_next_line_unread() {
        let mut reader = BufReader::with_capacity(3, Cursor::new(b"password\rignored\nsecond\n"));
        assert_eq!(read_secret_line(&mut reader).unwrap().expose(), b"password");
        assert_eq!(read_secret_line(&mut reader).unwrap().expose(), b"second");
        assert!(read_secret_line(&mut reader).unwrap().is_empty());
    }

    #[test]
    fn interrupted_input_retries_without_losing_the_line() {
        let mut reader = PartialFailure {
            remaining: b"secret\n",
            interrupted: true,
        };
        assert_eq!(read_secret_line(&mut reader).unwrap().expose(), b"secret");
    }

    #[test]
    fn eof_preserves_an_unterminated_line_without_a_new_size_limit() {
        let bytes = vec![b'x'; MAX_ANSWER_BYTES + 1];
        let mut reader = BufReader::with_capacity(31, Cursor::new(&bytes));
        assert_eq!(read_secret_line(&mut reader).unwrap().expose(), bytes);
    }
}
