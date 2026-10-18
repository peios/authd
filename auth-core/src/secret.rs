//! A byte buffer that is wiped when dropped.
//!
//! Credential material crosses `logon.sock` in the clear (see the crate docs for
//! why that is the right call), which makes it this crate's job to bound how
//! long it survives in memory. [`Secret`] is the type every credential travels
//! in: it allocates exactly, never grows, and zeroes itself on drop.
//!
//! ## What this does and does not guarantee
//!
//! It guarantees that *this* buffer is zeroed before its allocation returns to
//! the allocator. It cannot guarantee anything about copies made elsewhere — a
//! `String` the caller parsed the credential out of, a read buffer it was
//! decoded from, a register or stack slot the optimiser chose. Callers own
//! those. In particular, whoever decodes a message is responsible for wiping
//! the buffer it decoded *from*; [`Secret`] only covers what it holds.
//!
//! It also cannot defend against a hostile kernel, a core dump, or swap. Those
//! are addressed elsewhere (process integrity protection, disabling core dumps
//! for the daemon) and are out of scope here.

use core::fmt;
use core::sync::atomic::{Ordering, compiler_fence};

/// A byte buffer whose contents are zeroed on drop.
///
/// Deliberately not [`Clone`]: every copy is another buffer to wipe, so copying
/// is something a caller should have to write out explicitly.
pub struct Secret {
    buf: Box<[u8]>,
}

impl Secret {
    /// An empty secret. Used for credential kinds that carry no material, such
    /// as a pre-authenticated logon or a well-known service principal.
    pub fn empty() -> Self {
        Self {
            buf: Box::from([].as_slice()),
        }
    }

    /// Copy `src` into an exactly-sized allocation.
    ///
    /// The allocation is sized to `src.len()` up front and never grown, so the
    /// buffer this wipes on drop is the only one this type ever owned — there
    /// is no reallocation leaving a stale copy behind.
    ///
    /// The caller still owns `src`, and must wipe it if it holds credential
    /// material.
    pub fn from_slice(src: &[u8]) -> Self {
        let mut owned = Vec::with_capacity(src.len());
        owned.extend_from_slice(src);
        debug_assert_eq!(owned.len(), owned.capacity());
        Self {
            buf: owned.into_boxed_slice(),
        }
    }

    /// A zeroed buffer of exactly `len` bytes, to be filled in place.
    ///
    /// This is how a reader takes bytes off a socket without staging them in an
    /// ordinary buffer first: there is no intermediate copy to forget to wipe,
    /// because the destination is already self-wiping.
    pub fn zeroed(len: usize) -> Self {
        Self {
            buf: vec![0u8; len].into_boxed_slice(),
        }
    }

    /// The material, for the one component entitled to interpret it.
    pub fn expose(&self) -> &[u8] {
        &self.buf
    }

    /// Mutable access, for filling a [`Secret::zeroed`] buffer in place.
    pub fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Volatile writes so the compiler cannot elide stores to memory it can
        // prove is never read again, plus a fence to stop them being sunk past
        // the deallocation that follows.
        for byte in self.buf.iter_mut() {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// Redacted, so a stray `{:?}` on a request cannot put a password in a log.
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({} bytes, redacted)", self.buf.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_slice_copies_exactly() {
        let s = Secret::from_slice(b"hunter2");
        assert_eq!(s.expose(), b"hunter2");
        assert_eq!(s.len(), 7);
    }

    #[test]
    fn empty_is_empty() {
        let s = Secret::empty();
        assert!(s.is_empty());
        assert_eq!(s.expose(), b"");
    }

    #[test]
    fn debug_does_not_leak() {
        let rendered = format!("{:?}", Secret::from_slice(b"hunter2"));
        assert!(!rendered.contains("hunter2"), "{rendered}");
    }
}
