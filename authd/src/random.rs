//! Randomness, from the kernel, for the one value authd itself must make
//! unguessable: an NTLMv2 server challenge (PGSS §2.11).
//!
//! `getrandom(2)` with flags of zero blocks until the kernel's CRNG is seeded
//! and never returns unseeded output, which `/dev/urandom` does not promise.
//! A predictable challenge would let a captured response be replayed.

use std::io;

/// A fixed-size array of randomness the kernel vouches for.
///
/// `getrandom` can return fewer bytes than requested, so this loops until the
/// array is full and retries an interrupted call (`EINTR`).
pub fn array<const N: usize>() -> io::Result<[u8; N]> {
    let mut out = [0u8; N];
    let mut filled = 0;
    while filled < N {
        // SAFETY: writing at most `N - filled` bytes into a live, exclusively
        // borrowed array starting at `filled`.
        let taken = unsafe { libc::getrandom(out[filled..].as_mut_ptr().cast(), N - filled, 0) };
        if taken < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        filled += taken as usize;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_challenges_differ() {
        // 64 bits colliding twice in a row is not a flake worth allowing for.
        let first = array::<8>().unwrap();
        let second = array::<8>().unwrap();
        assert_ne!(first, second);
    }
}
