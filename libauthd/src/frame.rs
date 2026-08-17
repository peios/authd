//! The framing and encoding primitives shared by PGSS Logon and PSI.
//!
//! Two protocols live in this crate, and they are deliberately close relatives:
//! PSI is a superset of PGSS Logon (see [`crate::psi`]). Rather than
//! reimplement the codec twice — and drift — the reader, the writer, the error
//! type and the header layout live here once, parameterised by a [`Framing`].
//!
//! # The shared header
//!
//! Every message in both protocols opens with the same twelve bytes:
//!
//! ```text
//! +-----------------------------------+
//! | magic (4 literal bytes)           |
//! +-----------------+-----------------+
//! | version u16     | msg_type u16    |
//! +-----------------+-----------------+
//! | total_len u32 (header + body)     |
//! +-----------------------------------+
//! ```
//!
//! A protocol may *append* to that — PSI adds a conversation id — but the first
//! twelve bytes are fixed, which is what lets the transport frame a message off
//! a stream without knowing which protocol it is carrying.
//!
//! Multi-byte integers are little-endian, matching the KACS wire formats.
//!
//! # The magic is a safety device, not decoration
//!
//! Because the two protocols share message bodies, a socket plugged into the
//! wrong daemon could otherwise *partially* work — which is far worse than
//! failing outright. Distinct magics make that a hard error on the first four
//! bytes rather than a subtle misbehaviour several fields in.
//!
//! # Extensibility
//!
//! **Every struct is length-framed**, and so is every array element. A decoder
//! reads the fields it knows and then skips to the struct's declared end, so a
//! field appended by a newer peer is stepped over rather than mistaken for the
//! next field. This is what makes the format extensible *inside* arrays, where
//! ignoring trailing bytes at the message level would not help.
//!
//! The rules that keeps working under:
//!
//! - Fields are **appended only** — never reordered, never removed, never
//!   changed in meaning.
//! - A new field must be **optional with a safe default**, because older peers
//!   will not send it and will not read it.
//! - Adding an **enum value is a breaking change**, because every peer is
//!   required to understand every value it is sent. That needs a version bump.

/// Where the `total_len` field sits in every header of both protocols.
const TOTAL_LEN_AT: usize = 8;

/// The fixed part of a header, common to every protocol here.
pub const COMMON_HEADER_BYTES: usize = 12;

/// The largest a SID can be: the eight-byte prelude plus fifteen
/// sub-authorities, which is the most the encoding's one-byte count admits.
///
/// A fact about SIDs rather than about any one protocol, which is why it lives
/// here and every protocol that carries one refers to it. Three copies of the
/// same number, kept in step by hand, is how a field ends up bounded
/// differently on the two sides of a wire.
pub const MAX_SID_BYTES: usize = 68;

/// What distinguishes one protocol's framing from another's.
///
/// Held as a `&'static` constant per protocol, so the transport can frame
/// messages for either without knowing which it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Framing {
    /// Four literal bytes opening every message.
    pub magic: [u8; 4],
    /// The only version this build speaks.
    pub version: u16,
    /// Total header length, `>= COMMON_HEADER_BYTES`.
    pub header_bytes: usize,
    /// Ceiling on a whole message, header included.
    pub max_message_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// Fewer bytes than the field being read requires.
    Truncated,
    /// The leading four bytes were not this protocol's magic.
    BadMagic,
    /// A version this build does not speak.
    UnsupportedVersion(u16),
    /// Not the message type expected in this position.
    UnexpectedMessage(u16),
    /// A length or count exceeded its bound.
    TooLong,
    /// A field required to be UTF-8 was not.
    NotUtf8,
    /// An enum value this build does not recognise. Per the closed-enum rule,
    /// this fails the exchange rather than being skipped.
    UnknownValue,
}

/// Read a message header, returning `(msg_type, total_len)`.
///
/// A reader uses `total_len` to know how many bytes to accumulate before
/// handing the whole message to the matching body decoder.
pub fn decode_header(framing: &Framing, buf: &[u8]) -> Result<(u16, usize), WireError> {
    let mut r = Reader::new(buf);
    if r.take(4)? != framing.magic {
        return Err(WireError::BadMagic);
    }
    let version = r.u16()?;
    if version != framing.version {
        return Err(WireError::UnsupportedVersion(version));
    }
    let msg_type = r.u16()?;
    let total_len = r.u32()? as usize;
    if total_len < framing.header_bytes || total_len > framing.max_message_bytes {
        return Err(WireError::TooLong);
    }
    Ok((msg_type, total_len))
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(WireError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    /// Whether this struct's body is exhausted.
    ///
    /// The test for an optional trailing field: a peer older than the field
    /// simply did not write it, so the reader runs out where the field would
    /// have been and the decoder substitutes a default rather than failing.
    pub(crate) fn at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub(crate) fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, WireError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, WireError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub(crate) fn bytes(&mut self, max: usize) -> Result<&'a [u8], WireError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(WireError::TooLong);
        }
        self.take(len)
    }

    pub(crate) fn string(&mut self, max: usize) -> Result<&'a str, WireError> {
        core::str::from_utf8(self.bytes(max)?).map_err(|_| WireError::NotUtf8)
    }

    /// Enter a length-framed struct, returning a reader bounded to its body and
    /// leaving `self` positioned after it.
    ///
    /// This is what makes appending a field safe: the caller reads the fields
    /// it knows from the sub-reader and simply drops it, and any trailing bytes
    /// a newer peer wrote are stepped over here rather than misread as the next
    /// field.
    pub(crate) fn open(&mut self) -> Result<Reader<'a>, WireError> {
        let len = self.u32()? as usize;
        Ok(Reader::new(self.take(len)?))
    }

    /// Read a `count`-prefixed array of length-framed structs.
    pub(crate) fn array<T>(
        &mut self,
        max: usize,
        mut each: impl FnMut(&mut Reader<'a>) -> Result<T, WireError>,
    ) -> Result<Vec<T>, WireError> {
        let count = self.u32()? as usize;
        if count > max {
            return Err(WireError::TooLong);
        }
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let mut element = self.open()?;
            out.push(each(&mut element)?);
        }
        Ok(out)
    }
}

/// Position a reader on a message's body, checking it is the expected type.
///
/// Skips the whole header, protocol extension included, so a caller that needs
/// a field from that extension (PSI's conversation id) must read it separately
/// — see [`crate::psi::decode_envelope`].
pub(crate) fn open_body<'a>(
    framing: &Framing,
    buf: &'a [u8],
    expected: u16,
) -> Result<Reader<'a>, WireError> {
    let (msg_type, total_len) = decode_header(framing, buf)?;
    if msg_type != expected {
        return Err(WireError::UnexpectedMessage(msg_type));
    }
    if buf.len() < total_len {
        return Err(WireError::Truncated);
    }
    let mut r = Reader::new(&buf[..total_len]);
    r.take(framing.header_bytes)?;
    r.open()
}

pub(crate) fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() { None } else { Some(s.to_owned()) }
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

pub(crate) struct Writer {
    buf: Vec<u8>,
    max_message_bytes: usize,
}

impl Writer {
    /// Begin a message, writing the fixed twelve-byte header.
    ///
    /// A protocol whose header extends past that appends its own fields
    /// immediately after this call and before opening the body.
    pub(crate) fn new(framing: &Framing, msg_type: u16) -> Self {
        let mut buf = Vec::new();
        buf.extend_from_slice(&framing.magic);
        buf.extend_from_slice(&framing.version.to_le_bytes());
        buf.extend_from_slice(&msg_type.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // total_len, patched by finish
        Self {
            buf,
            max_message_bytes: framing.max_message_bytes,
        }
    }

    pub(crate) fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub(crate) fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn bytes(&mut self, data: &[u8], max: usize) -> Result<(), WireError> {
        if data.len() > max {
            return Err(WireError::TooLong);
        }
        self.u32(data.len() as u32);
        self.buf.extend_from_slice(data);
        Ok(())
    }

    pub(crate) fn string(&mut self, s: &str, max: usize) -> Result<(), WireError> {
        self.bytes(s.as_bytes(), max)
    }

    /// Reserve a struct's length prefix; pair with [`Self::close`].
    pub(crate) fn open(&mut self) -> usize {
        let at = self.buf.len();
        self.u32(0);
        at
    }

    pub(crate) fn close(&mut self, at: usize) {
        let len = (self.buf.len() - at - 4) as u32;
        self.buf[at..at + 4].copy_from_slice(&len.to_le_bytes());
    }

    pub(crate) fn count(&mut self, n: usize, max: usize) -> Result<(), WireError> {
        if n > max {
            return Err(WireError::TooLong);
        }
        self.u32(n as u32);
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<Vec<u8>, WireError> {
        if self.buf.len() > self.max_message_bytes {
            return Err(WireError::TooLong);
        }
        let total = self.buf.len() as u32;
        self.buf[TOTAL_LEN_AT..TOTAL_LEN_AT + 4].copy_from_slice(&total.to_le_bytes());
        Ok(self.buf)
    }
}

/// Zero a buffer about to be dropped.
///
/// Used on intermediate encode buffers that briefly hold the same plaintext a
/// returned [`crate::secret::Secret`] does.
pub(crate) fn wipe(mut buf: Vec<u8>) {
    for byte in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
