//! Randomness, from the kernel, for the two things lpsd must never make
//! guessable: a machine's domain SID and a verifier's salt.
//!
//! `getrandom(2)` rather than `/dev/urandom`, and the difference matters here
//! more than almost anywhere. `/dev/urandom` never blocks — including before the
//! kernel's CRNG has been seeded — and the moment lpsd is most likely to be
//! generating a domain SID and its first salts is *first boot on a fresh
//! machine*, which is exactly when that pool is least likely to be ready. With
//! flags of zero, `getrandom` blocks until the CRNG is initialised and never
//! returns unseeded output.
//!
//! A domain SID that could collide with another machine's is not a theoretical
//! problem: it is two machines whose principals have the same SIDs, which
//! means the security descriptors written by one grant access to the other's
//! users.

use std::io;

/// Fill `buf` with randomness the kernel vouches for.
///
/// `getrandom` may return short for large requests (the kernel caps a single
/// call at 256 bytes when it must block), so this loops rather than assuming
/// one call suffices — and retries on `EINTR`, which is a signal arriving, not
/// a failure.
pub fn fill(buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        // SAFETY: writing at most `len` bytes into a live, exclusively borrowed
        // slice starting at `filled`.
        let taken = unsafe {
            libc::getrandom(
                buf[filled..].as_mut_ptr().cast(),
                buf.len() - filled,
                0, // block until seeded; never return unseeded bytes
            )
        };
        if taken < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        filled += taken as usize;
    }
    Ok(())
}

/// A fixed-size array of randomness.
pub fn array<const N: usize>() -> io::Result<[u8; N]> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_fills_the_whole_buffer() {
        // Larger than getrandom's 256-byte single-call cap, so this exercises
        // the loop rather than just the happy path.
        let mut buf = [0u8; 1024];
        fill(&mut buf).expect("the kernel must provide randomness");
        assert!(
            buf.iter().any(|&b| b != 0),
            "1024 zero bytes means the buffer was never filled"
        );
        assert!(
            buf[512..].iter().any(|&b| b != 0),
            "the tail past the first call must be filled too"
        );
    }

    #[test]
    fn an_empty_request_succeeds() {
        fill(&mut []).expect("asking for nothing must not fail");
    }

    #[test]
    fn two_draws_differ() {
        let a = array::<32>().expect("randomness");
        let b = array::<32>().expect("randomness");
        assert_ne!(a, b, "two 32-byte draws must not be equal");
    }
}
