//! Packing an answer into the caller's buffer.
//!
//! Every NSS entry point is handed a `char *buf` and a length, and the
//! `struct passwd` it fills points *into* that buffer. Nothing here allocates:
//! the contract is that the caller owns the memory and the module writes into
//! it, which is what lets `getpwnam_r` be re-entrant at all.
//!
//! Running out of room is not an error in the ordinary sense. It is
//! `NSS_STATUS_TRYAGAIN` with `ERANGE`, and glibc's answer is to call again with
//! a larger buffer — so a packer that overflowed silently would corrupt the
//! caller's stack rather than trigger the retry that exists for it.

use core::ffi::c_char;

/// A bump allocator over a caller-owned buffer.
pub struct Packer {
    base: *mut c_char,
    len: usize,
    used: usize,
}

impl Packer {
    /// # Safety
    ///
    /// `base` must point to at least `len` writable bytes, and must outlive
    /// every pointer this hands out.
    pub unsafe fn new(base: *mut c_char, len: usize) -> Self {
        Self {
            base,
            len,
            used: 0,
        }
    }

    /// Copy a string in, NUL-terminated, and return a pointer to it.
    ///
    /// `None` means the buffer is full, which the caller turns into `ERANGE`.
    pub fn str(&mut self, value: &str) -> Option<*mut c_char> {
        // An interior NUL would truncate the string a C caller reads, so it is a
        // refusal rather than something to sanitise. Nothing that reaches here
        // should contain one — names are printable ASCII by policy — and a
        // silent truncation is exactly how a name comes to mean a different
        // principal.
        if value.as_bytes().contains(&0) {
            return None;
        }
        let need = value.len() + 1;
        let at = self.reserve(need, 1)?;
        // SAFETY: `reserve` returned an offset with `need` bytes available.
        unsafe {
            let dst = self.base.add(at) as *mut u8;
            core::ptr::copy_nonoverlapping(value.as_ptr(), dst, value.len());
            dst.add(value.len()).write(0);
            Some(dst as *mut c_char)
        }
    }

    /// Reserve room for `count` pointers, aligned, and return the array.
    ///
    /// Used for `gr_mem`, which is a NUL-terminated array of `char *`. The
    /// alignment matters: an unaligned pointer array is undefined behaviour on
    /// every architecture that cares, and the buffer glibc hands over carries no
    /// alignment guarantee past one byte.
    pub fn pointers(&mut self, count: usize) -> Option<*mut *mut c_char> {
        let size = size_of::<*mut c_char>();
        let need = size.checked_mul(count)?;
        let at = self.reserve(need, align_of::<*mut c_char>())?;
        // SAFETY: `reserve` aligned the offset and left `need` bytes.
        Some(unsafe { self.base.add(at) as *mut *mut c_char })
    }

    fn reserve(&mut self, need: usize, align: usize) -> Option<usize> {
        // SAFETY: `base` is valid for `len` bytes; the cast is only used to find
        // the alignment of the offset, never dereferenced.
        let addr = self.base as usize;
        let at = self.used;
        let padding = (align - (addr.wrapping_add(at) % align)) % align;
        let start = at.checked_add(padding)?;
        let end = start.checked_add(need)?;
        if end > self.len {
            return None;
        }
        self.used = end;
        Some(start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(pointer: *mut c_char) -> String {
        // SAFETY: the packer wrote a NUL-terminated string here.
        unsafe {
            let mut out = Vec::new();
            let mut at = pointer as *const u8;
            while *at != 0 {
                out.push(*at);
                at = at.add(1);
            }
            String::from_utf8(out).expect("what went in was UTF-8")
        }
    }

    #[test]
    fn strings_are_packed_nul_terminated_and_read_back() {
        let mut buf = [0i8; 64];
        let mut packer = unsafe { Packer::new(buf.as_mut_ptr(), buf.len()) };
        let first = packer.str("jack").expect("must fit");
        let second = packer.str("/home/jack").expect("must fit");
        assert_eq!(read(first), "jack");
        assert_eq!(read(second), "/home/jack");
    }

    /// The signal that makes glibc retry with a bigger buffer. Overflowing
    /// instead would write past the caller's stack.
    #[test]
    fn a_full_buffer_refuses_rather_than_overflowing() {
        let mut buf = [0i8; 8];
        let mut packer = unsafe { Packer::new(buf.as_mut_ptr(), buf.len()) };
        assert!(packer.str("1234567").is_some(), "seven bytes and a NUL fit");
        assert!(packer.str("x").is_none(), "and nothing more does");
    }

    #[test]
    fn an_interior_nul_is_refused() {
        let mut buf = [0i8; 64];
        let mut packer = unsafe { Packer::new(buf.as_mut_ptr(), buf.len()) };
        assert!(packer.str("ja\0ck").is_none());
    }

    /// A misaligned pointer array is undefined behaviour, and the buffer glibc
    /// hands over guarantees nothing past one byte.
    #[test]
    fn a_pointer_array_is_aligned_however_the_buffer_started() {
        let mut buf = [0i8; 128];
        let mut packer = unsafe { Packer::new(buf.as_mut_ptr(), buf.len()) };
        // One byte of string first, so the next offset is odd.
        packer.str("").expect("must fit");
        let array = packer.pointers(4).expect("must fit");
        assert_eq!(
            array as usize % align_of::<*mut c_char>(),
            0,
            "the array must be aligned even after an odd-length string"
        );
    }

    #[test]
    fn a_pointer_array_that_does_not_fit_refuses() {
        let mut buf = [0i8; 8];
        let mut packer = unsafe { Packer::new(buf.as_mut_ptr(), buf.len()) };
        assert!(packer.pointers(64).is_none());
    }

    #[test]
    fn packing_continues_after_a_pointer_array() {
        let mut buf = [0i8; 128];
        let mut packer = unsafe { Packer::new(buf.as_mut_ptr(), buf.len()) };
        let array = packer.pointers(2).expect("must fit");
        let name = packer.str("ada").expect("must fit");
        // SAFETY: the array has room for two pointers.
        unsafe {
            array.write(name);
            array.add(1).write(core::ptr::null_mut());
            assert_eq!(read(*array), "ada");
            assert!((*array.add(1)).is_null());
        }
    }
}
