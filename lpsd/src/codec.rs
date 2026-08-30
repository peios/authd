//! The store file's byte format: a versioned header, a CRC32C over the body,
//! and length-framed primitives to build the body out of.
//!
//! # Why a checksum, when the write is atomic
//!
//! [`crate::fs::replace`] means a reader sees either the whole previous file or
//! the whole next one — never a half-written one. So the checksum is not there
//! to catch a torn write.
//!
//! It is there because of what the alternative failure looks like. This file
//! holds every local credential verifier and every local principal's SID. A
//! store that silently decoded *short* — because a byte flipped in a length
//! field, because a filesystem returned a stale block, because something
//! truncated it — would present as an account quietly no longer existing, or as
//! a verifier that no password matches. Both look like an administrator's
//! mistake rather than corruption, and the natural response to either ("recreate
//! the account") destroys evidence.
//!
//! So the whole body is checksummed and the checksum is verified *before any of
//! it is interpreted*. Corruption becomes a refusal to load, which is the one
//! outcome an operator cannot misread. [`crate::store`] turns that refusal into
//! a refusal to start, deliberately: see its module docs for why a corrupt store
//! must never be treated the same as an absent one.
//!
//! # Shape borrowed, code not
//!
//! The layout — magic, version, length, CRC32C, verify-before-parse — follows
//! `udd`'s `store::persist::codec`, which had already worked out what a small
//! durable format wants. The implementation is separate on purpose: these two
//! files never read each other, so there is no correctness requirement that the
//! two agree, and a shared crate would couple lpsd's release to a project under
//! heavy development for no benefit it can name. Recorded in PEI-166.

/// `PEIOSLPS` — Peios Local Principal Store.
pub const MAGIC: [u8; 8] = *b"PEIOSLPS";

/// Bumped when the body's meaning changes in a way an older reader would get
/// wrong. An older reader refuses a newer file rather than guessing.
///
/// **2** added Unix IDs, group objects, the profile fields and claims.
/// **3** made a Unix ID default to the RID and dropped the separate counter —
/// see [`crate::store`].
///
/// Older versions remain *readable*: [`open`] hands the version back so the
/// store can be upgraded in place rather than refused, which on a machine whose
/// only administrator lives in that file is the difference between an upgrade
/// and a brick.
pub const VERSION: u16 = 4;

/// The oldest body layout this lpsd can still read.
pub const OLDEST_READABLE_VERSION: u16 = 1;

/// `magic[8] | version u16 | body_len u32 | body_crc u32`
pub const HEADER_BYTES: usize = 18;

#[derive(Debug, PartialEq, Eq)]
pub enum CodecError {
    /// Shorter than the header, or the body is shorter than the header claims.
    Truncated,
    /// Not a store file at all.
    BadMagic,
    /// A store file from a future version of lpsd.
    UnsupportedVersion(u16),
    /// The body did not survive the trip.
    BadChecksum,
    /// Longer than the header claims. As suspicious as short: something
    /// appended to a file only this daemon should write.
    TrailingBytes,
    /// A length field ran past the end of the body.
    Malformed,
    /// A string field was not UTF-8.
    NotUtf8,
}

impl core::fmt::Display for CodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => write!(f, "the store is truncated"),
            Self::BadMagic => write!(f, "not a principal store"),
            Self::UnsupportedVersion(v) => {
                write!(f, "store format version {v} is newer than this lpsd understands")
            }
            Self::BadChecksum => write!(f, "the store failed its checksum"),
            Self::TrailingBytes => write!(f, "the store has trailing bytes"),
            Self::Malformed => write!(f, "the store is malformed"),
            Self::NotUtf8 => write!(f, "the store contains a non-UTF-8 string"),
        }
    }
}

// ---------------------------------------------------------------------------
// CRC32C
// ---------------------------------------------------------------------------

/// Castagnoli, reflected: the polynomial SCTP, iSCSI, ext4 and every modern
/// x86 use, chosen over CRC-32 (zlib's) for its better error detection on short
/// runs and because it is the one a reader is most likely to already have.
const POLYNOMIAL: u32 = 0x82F6_3B78;

const fn build_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut byte = 0usize;
    while byte < 256 {
        let mut crc = byte as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLYNOMIAL
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[byte] = crc;
        byte += 1;
    }
    table
}

static TABLE: [u32; 256] = build_table();

/// CRC32C of `data`.
///
/// Table-driven rather than using the SSE4.2 instruction: this runs once per
/// store read and once per store write, on a file measured in kilobytes, so the
/// only thing worth optimising for is being obviously correct on every machine.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc = (crc >> 8) ^ TABLE[((crc ^ byte as u32) & 0xFF) as usize];
    }
    !crc
}

// ---------------------------------------------------------------------------
// The file envelope
// ---------------------------------------------------------------------------

/// Wrap a body in a header, ready to be written.
pub fn seal(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_BYTES + body.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&crc32c(body).to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// Validate a file and return its version and body.
///
/// Every check that can be made without interpreting the body is made here, in
/// the order that produces the most specific diagnosis: a file from the wrong
/// program reports as such rather than as a checksum failure, and a truncated
/// one reports as truncated rather than as corrupt. Only once this returns does
/// anything look at what the body *means*, which is what keeps the parser from
/// ever running on bytes that failed their checksum.
///
/// The version is *returned* rather than merely checked, because old and new
/// are not symmetric. A **newer** file is refused outright — its body means
/// something this code does not know, and guessing is how a downgrade silently
/// discards accounts. An **older** one is handed to the caller to upgrade, since
/// every field this version added has a defensible default and refusing would
/// strand a machine whose only administrator lives in the file.
pub fn open(file: &[u8]) -> Result<(u16, &[u8]), CodecError> {
    if file.len() < HEADER_BYTES {
        return Err(CodecError::Truncated);
    }
    if file[..8] != MAGIC {
        return Err(CodecError::BadMagic);
    }
    let version = u16::from_le_bytes([file[8], file[9]]);
    if version > VERSION || version < OLDEST_READABLE_VERSION {
        return Err(CodecError::UnsupportedVersion(version));
    }
    let body_len = u32::from_le_bytes([file[10], file[11], file[12], file[13]]) as usize;
    let expected_crc = u32::from_le_bytes([file[14], file[15], file[16], file[17]]);

    let available = file.len() - HEADER_BYTES;
    if available < body_len {
        return Err(CodecError::Truncated);
    }
    if available > body_len {
        return Err(CodecError::TrailingBytes);
    }

    let body = &file[HEADER_BYTES..];
    if crc32c(body) != expected_crc {
        return Err(CodecError::BadChecksum);
    }
    Ok((version, body))
}

// ---------------------------------------------------------------------------
// Body primitives
// ---------------------------------------------------------------------------

/// Builds a body. Infallible: a store that cannot be encoded is a bug here, not
/// a runtime condition, and every length involved is bounded by what
/// [`crate::store`] already accepted.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    pub fn u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    pub fn u64(&mut self, value: u64) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Length-framed bytes, so an unknown field can be skipped whole.
    pub fn bytes(&mut self, value: &[u8]) {
        self.u32(value.len() as u32);
        self.buf.extend_from_slice(value);
    }

    pub fn str(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Reads a body that has already passed its checksum.
///
/// Bounds are still checked on every read. The checksum proves the bytes are
/// the ones that were written; it proves nothing about whether *this* version
/// of the parser agrees with them, and a length field written by a future
/// version could still run off the end.
pub struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }

    pub fn at_end(&self) -> bool {
        self.at >= self.buf.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let end = self.at.checked_add(n).ok_or(CodecError::Malformed)?;
        let slice = self.buf.get(self.at..end).ok_or(CodecError::Malformed)?;
        self.at = end;
        Ok(slice)
    }

    pub fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32, CodecError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn u64(&mut self) -> Result<u64, CodecError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn bytes(&mut self) -> Result<&'a [u8], CodecError> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    pub fn str(&mut self) -> Result<&'a str, CodecError> {
        core::str::from_utf8(self.bytes()?).map_err(|_| CodecError::NotUtf8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_matches_the_standard_check_value() {
        // The check value every CRC-32C implementation is expected to produce.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn crc32c_of_nothing_is_zero() {
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn a_sealed_body_opens_back_to_itself() {
        let file = seal(b"hello");
        assert_eq!(open(&file).expect("must open"), (VERSION, &b"hello"[..]));
    }

    #[test]
    fn an_empty_body_round_trips() {
        let file = seal(b"");
        assert_eq!(open(&file).expect("must open"), (VERSION, &b""[..]));
    }

    #[test]
    fn a_flipped_body_byte_is_caught() {
        let mut file = seal(b"hello");
        file[HEADER_BYTES] ^= 0x01;
        assert_eq!(open(&file), Err(CodecError::BadChecksum));
    }

    #[test]
    fn a_truncated_file_is_caught_as_truncated() {
        let file = seal(b"hello");
        for len in 0..file.len() {
            assert_eq!(
                open(&file[..len]),
                Err(CodecError::Truncated),
                "a {len}-byte file must report as truncated, not as corrupt"
            );
        }
    }

    #[test]
    fn appended_bytes_are_caught() {
        let mut file = seal(b"hello");
        file.push(0);
        assert_eq!(open(&file), Err(CodecError::TrailingBytes));
    }

    #[test]
    fn another_programs_file_is_not_a_checksum_failure() {
        let file = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(open(file), Err(CodecError::BadMagic));
    }

    #[test]
    fn a_newer_version_is_refused_by_version() {
        let mut file = seal(b"hello");
        file[8..10].copy_from_slice(&(VERSION + 1).to_le_bytes());
        // Refused on the version, before the checksum it would also fail — the
        // operator needs to be told "newer lpsd wrote this", not "corrupt".
        assert_eq!(open(&file), Err(CodecError::UnsupportedVersion(VERSION + 1)));
    }

    /// The asymmetry that lets a store be upgraded rather than refused: an
    /// older version opens, and says which one it is so the body can be read
    /// with the layout that wrote it.
    #[test]
    fn an_older_version_opens_and_reports_itself() {
        let mut file = seal(b"hello");
        file[8..10].copy_from_slice(&OLDEST_READABLE_VERSION.to_le_bytes());
        assert_eq!(
            open(&file).expect("an older store must still open"),
            (OLDEST_READABLE_VERSION, &b"hello"[..])
        );
    }

    #[test]
    fn a_version_below_the_oldest_readable_is_refused() {
        let mut file = seal(b"hello");
        file[8..10].copy_from_slice(&(OLDEST_READABLE_VERSION - 1).to_le_bytes());
        assert_eq!(
            open(&file),
            Err(CodecError::UnsupportedVersion(OLDEST_READABLE_VERSION - 1))
        );
    }

    #[test]
    fn primitives_round_trip() {
        let mut w = Writer::new();
        w.u8(7);
        w.u32(0xDEAD_BEEF);
        w.str("jack");
        w.bytes(&[1, 2, 3]);
        let body = w.finish();

        let mut r = Reader::new(&body);
        assert_eq!(r.u8().unwrap(), 7);
        assert_eq!(r.u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.str().unwrap(), "jack");
        assert_eq!(r.bytes().unwrap(), &[1, 2, 3]);
        assert!(r.at_end());
    }

    #[test]
    fn a_length_running_past_the_end_is_malformed_not_a_panic() {
        let mut w = Writer::new();
        w.u32(64); // claims 64 bytes follow
        let body = w.finish();
        assert_eq!(Reader::new(&body).bytes(), Err(CodecError::Malformed));
    }

    #[test]
    fn a_non_utf8_string_is_rejected() {
        let mut w = Writer::new();
        w.bytes(&[0xff, 0xfe]);
        let body = w.finish();
        assert_eq!(Reader::new(&body).str(), Err(CodecError::NotUtf8));
    }

    #[test]
    fn reading_past_the_end_fails_rather_than_wrapping() {
        let mut r = Reader::new(&[]);
        assert_eq!(r.u32(), Err(CodecError::Malformed));
    }
}
