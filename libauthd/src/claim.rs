//! **Claims** — the named, typed attributes a principal carries into
//! conditional ACE evaluation.
//!
//! A claim is directory data. Active Directory sources them from attributes on
//! the user and computer objects and the DC issues them in the Kerberos PAC;
//! Peios sources them from whichever principal source holds the principal. That
//! is why they travel on PSI's assertion rather than being derived by authd:
//! unlike a privilege or an integrity level, a claim is a *fact about someone*
//! that only their directory knows.
//!
//! # This type is shared, its encodings are not
//!
//! One `Claim` crosses PSI, is stored by lpsd, and is displayed by `lps`. The
//! byte layouts differ — lpsd's store has its own codec — but the *shape* does
//! not, which is what stops a claim meaning one thing on disk and another on the
//! wire.
//!
//! It stops short of the kernel. Turning a `Claim` into
//! `peios::token::ClaimValues` happens once, in authd, at the boundary where the
//! security library enters: libauthd is deliberately inert and has no dependency
//! on it, which is why SIDs here are opaque bytes.
//!
//! # Bounds
//!
//! The type codes and flag bits are PSD-004 §3.9's, used verbatim rather than
//! translated, so a claim that survives this module is one KACS can parse. The
//! *counts* are ours and are tighter than the specification permits — see
//! [`MAX_VALUES`]. They bound the work done decoding a message from a source
//! before any of it is believed.

use crate::frame::{Reader, Writer, WireError};

/// How many claims one principal may carry.
///
/// A store and transport bound rather than a KACS one. A principal with more
/// than a handful of claims is describing something the directory should
/// probably model as a group.
pub const MAX_CLAIMS: usize = 64;

/// The longest claim name, in UTF-8 bytes.
///
/// KACS bounds the name at 256 UTF-16LE code units *including* the terminator,
/// i.e. 255 characters. A string's UTF-16 length never exceeds its UTF-8 byte
/// length — one to four bytes collapse to one code unit each, and only the
/// four-byte forms produce two — so bounding the bytes at 255 guarantees the
/// code units fit, conservatively and without transcoding to find out.
pub const MAX_NAME_BYTES: usize = 255;

/// How many values one claim may carry.
///
/// KACS permits 1024 (§3.9). This is deliberately far tighter: it is a bound on
/// work done for a message that has not yet been believed, and nothing in Peios
/// has a use for a 1024-valued local claim. A source needing more is describing
/// something else.
pub const MAX_VALUES: usize = 64;

pub const MAX_STRING_BYTES: usize = 1024;
pub const MAX_OCTET_BYTES: usize = 1024;

/// A SID's maximum size, from [`crate::frame`].
pub const MAX_SID_BYTES: usize = crate::frame::MAX_SID_BYTES;

// PSD-004 §3.9 value types. `FQBN` (0x0004) is reserved and unsupported, which
// is why the numbering has a hole in it.
pub const TYPE_INT64: u32 = 0x0001;
pub const TYPE_UINT64: u32 = 0x0002;
pub const TYPE_STRING: u32 = 0x0003;
pub const TYPE_SID: u32 = 0x0005;
pub const TYPE_BOOLEAN: u32 = 0x0006;
pub const TYPE_OCTET: u32 = 0x0010;

// PSD-004 §3.9 claim flags.
pub const FLAG_NON_INHERITABLE: u32 = 0x0001;
pub const FLAG_CASE_SENSITIVE: u32 = 0x0002;
pub const FLAG_USE_FOR_DENY_ONLY: u32 = 0x0004;
pub const FLAG_DISABLED: u32 = 0x0010;
pub const FLAG_MANDATORY: u32 = 0x0020;

/// Every flag this version understands. Unknown bits are *preserved* by KACS
/// but have no defined meaning, so a claim carrying one is refused here rather
/// than passed to the kernel on the assumption it will be ignored.
pub const KNOWN_FLAGS: u32 = FLAG_NON_INHERITABLE
    | FLAG_CASE_SENSITIVE
    | FLAG_USE_FOR_DENY_ONLY
    | FLAG_DISABLED
    | FLAG_MANDATORY;

/// A claim's values, which are homogeneous and may be empty.
///
/// `ValueCount = 0` is valid per §3.9 and normalises to *absent* at resolution
/// time. It is kept representable rather than collapsed to "no claim", because
/// the two differ to an administrator: an empty claim is one somebody set and
/// then emptied, and losing that distinction on a round trip would silently
/// rewrite what they wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Values {
    Int64(Vec<i64>),
    Uint64(Vec<u64>),
    Boolean(Vec<bool>),
    /// UTF-8 here; transcoded to UTF-16LE when it reaches the kernel.
    String(Vec<String>),
    /// Binary SIDs. Structurally unvalidated — libauthd has no security
    /// library — so the recipient must check before believing one.
    Sid(Vec<Vec<u8>>),
    Octet(Vec<Vec<u8>>),
}

impl Values {
    pub fn type_code(&self) -> u32 {
        match self {
            Self::Int64(_) => TYPE_INT64,
            Self::Uint64(_) => TYPE_UINT64,
            Self::Boolean(_) => TYPE_BOOLEAN,
            Self::String(_) => TYPE_STRING,
            Self::Sid(_) => TYPE_SID,
            Self::Octet(_) => TYPE_OCTET,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Int64(v) => v.len(),
            Self::Uint64(v) => v.len(),
            Self::Boolean(v) => v.len(),
            Self::String(v) => v.len(),
            Self::Sid(v) => v.len(),
            Self::Octet(v) => v.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// An empty value list of the type `code` names.
    pub fn empty_of(code: u32) -> Option<Self> {
        Some(match code {
            TYPE_INT64 => Self::Int64(Vec::new()),
            TYPE_UINT64 => Self::Uint64(Vec::new()),
            TYPE_BOOLEAN => Self::Boolean(Vec::new()),
            TYPE_STRING => Self::String(Vec::new()),
            TYPE_SID => Self::Sid(Vec::new()),
            TYPE_OCTET => Self::Octet(Vec::new()),
            _ => return None,
        })
    }

    /// The name PSD-004 §3.9 gives this type, for diagnostics and `lps`.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Int64(_) => "int64",
            Self::Uint64(_) => "uint64",
            Self::Boolean(_) => "boolean",
            Self::String(_) => "string",
            Self::Sid(_) => "sid",
            Self::Octet(_) => "octet",
        }
    }

    /// Parse a type name as `lps` spells it.
    pub fn type_from_name(name: &str) -> Option<u32> {
        Some(match name {
            "int64" => TYPE_INT64,
            "uint64" => TYPE_UINT64,
            "boolean" => TYPE_BOOLEAN,
            "string" => TYPE_STRING,
            "sid" => TYPE_SID,
            "octet" => TYPE_OCTET,
            _ => return None,
        })
    }
}

/// One named, typed, multi-valued security attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub name: String,
    pub flags: u32,
    pub values: Values,
}

/// Why a claim is not usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimError {
    /// Empty, overlong, or containing an interior NUL.
    Name,
    /// More values than [`MAX_VALUES`].
    TooManyValues,
    /// A string or octet value past its ceiling, or a SID past [`MAX_SID_BYTES`].
    ValueTooLong,
    /// A flag bit outside [`KNOWN_FLAGS`].
    UnknownFlags,
}

impl core::fmt::Display for ClaimError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Name => write!(
                f,
                "a claim name must be 1 to {MAX_NAME_BYTES} bytes and contain no NUL"
            ),
            Self::TooManyValues => write!(f, "a claim may carry at most {MAX_VALUES} values"),
            Self::ValueTooLong => write!(f, "a claim value is longer than permitted"),
            Self::UnknownFlags => write!(f, "a claim carries a flag bit with no defined meaning"),
        }
    }
}

impl Claim {
    /// Check a claim is one this system can carry all the way to a token.
    ///
    /// Called by whoever *accepts* a claim — lpsd when it is set, authd when one
    /// is asserted — rather than by the decoder, so that "structurally decodable"
    /// and "semantically usable" stay separable. A claim rejected here is a
    /// refusal with a reason; one rejected by the decoder is a malformed peer.
    ///
    /// The interior-NUL check is not cosmetic: the name crosses a C ABI as a
    /// `CString`, so a NUL would truncate it and the token would silently carry
    /// a *different, shorter* claim name than the one an administrator set.
    pub fn validate(&self) -> Result<(), ClaimError> {
        if self.name.is_empty()
            || self.name.len() > MAX_NAME_BYTES
            || self.name.as_bytes().contains(&0)
        {
            return Err(ClaimError::Name);
        }
        if self.flags & !KNOWN_FLAGS != 0 {
            return Err(ClaimError::UnknownFlags);
        }
        if self.values.len() > MAX_VALUES {
            return Err(ClaimError::TooManyValues);
        }
        let fits = match &self.values {
            Values::String(v) => v.iter().all(|s| s.len() <= MAX_STRING_BYTES),
            Values::Octet(v) => v.iter().all(|b| b.len() <= MAX_OCTET_BYTES),
            Values::Sid(v) => v.iter().all(|s| s.len() <= MAX_SID_BYTES),
            _ => true,
        };
        if !fits {
            return Err(ClaimError::ValueTooLong);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Wire encoding
// ---------------------------------------------------------------------------

/// Write one claim's body. The caller supplies the enclosing frame.
///
/// Every value gets its own length frame, matching [`Reader::array`]'s shape.
/// For an eight-byte scalar that is four bytes of overhead, paid deliberately:
/// it is the only layout in which a value can grow a field later, and a
/// per-type layout is how a decoder ends up disagreeing with an encoder about
/// where the next value starts.
pub(crate) fn write_claim(w: &mut Writer, claim: &Claim) -> Result<(), WireError> {
    w.string(&claim.name, MAX_NAME_BYTES)?;
    w.u32(claim.flags);
    w.u32(claim.values.type_code());
    w.count(claim.values.len(), MAX_VALUES)?;

    macro_rules! each {
        ($values:expr, $write:expr) => {
            for value in $values {
                let at = w.open();
                #[allow(clippy::redundant_closure_call)]
                ($write)(w, value)?;
                w.close(at);
            }
        };
    }

    match &claim.values {
        Values::Int64(v) => each!(v, |w: &mut Writer, value: &i64| {
            w.u64(*value as u64);
            Ok::<(), WireError>(())
        }),
        Values::Uint64(v) => each!(v, |w: &mut Writer, value: &u64| {
            w.u64(*value);
            Ok::<(), WireError>(())
        }),
        Values::Boolean(v) => each!(v, |w: &mut Writer, value: &bool| {
            // KACS stores a boolean as a u64 and normalises any non-zero to
            // true. Writing exactly 1 rather than any truthy value keeps the
            // encoding canonical, so two equal claims encode identically.
            w.u64(u64::from(*value));
            Ok::<(), WireError>(())
        }),
        Values::String(v) => each!(v, |w: &mut Writer, value: &String| w
            .string(value, MAX_STRING_BYTES)),
        Values::Sid(v) => each!(v, |w: &mut Writer, value: &Vec<u8>| w
            .bytes(value, MAX_SID_BYTES)),
        Values::Octet(v) => each!(v, |w: &mut Writer, value: &Vec<u8>| w
            .bytes(value, MAX_OCTET_BYTES)),
    }
    Ok(())
}

/// Read one claim from a reader positioned on its body.
pub(crate) fn read_claim(r: &mut Reader<'_>) -> Result<Claim, WireError> {
    let name = r.string(MAX_NAME_BYTES)?.to_owned();
    let flags = r.u32()?;
    let type_code = r.u32()?;

    // An unknown type is refused rather than skipped. §3.9 is explicit that an
    // unsupported type invalidates the containing entry, and a claim silently
    // dropped in transit is worse than a refused message: a conditional ACE
    // that should have matched simply would not, with nothing to point at.
    let values = match type_code {
        TYPE_INT64 => Values::Int64(r.array(MAX_VALUES, |v| Ok(v.u64()? as i64))?),
        TYPE_UINT64 => Values::Uint64(r.array(MAX_VALUES, |v| v.u64())?),
        TYPE_BOOLEAN => Values::Boolean(r.array(MAX_VALUES, |v| Ok(v.u64()? != 0))?),
        TYPE_STRING => Values::String(r.array(MAX_VALUES, |v| {
            Ok(v.string(MAX_STRING_BYTES)?.to_owned())
        })?),
        TYPE_SID => Values::Sid(r.array(MAX_VALUES, |v| Ok(v.bytes(MAX_SID_BYTES)?.to_vec()))?),
        TYPE_OCTET => {
            Values::Octet(r.array(MAX_VALUES, |v| Ok(v.bytes(MAX_OCTET_BYTES)?.to_vec()))?)
        }
        _ => return Err(WireError::UnknownValue),
    };

    Ok(Claim {
        name,
        flags,
        values,
    })
}

/// Write a count-prefixed array of claims, each in its own frame.
pub(crate) fn write_claims(w: &mut Writer, claims: &[Claim]) -> Result<(), WireError> {
    w.count(claims.len(), MAX_CLAIMS)?;
    for claim in claims {
        let at = w.open();
        write_claim(w, claim)?;
        w.close(at);
    }
    Ok(())
}

/// Read a count-prefixed array of claims.
pub(crate) fn read_claims(r: &mut Reader<'_>) -> Result<Vec<Claim>, WireError> {
    r.array(MAX_CLAIMS, read_claim)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PSI-framed message whose body is whatever `build` writes.
    ///
    /// PSI's header is the common twelve bytes *plus* a conversation id, so the
    /// id has to be written before the body opens — exactly as `psi::begin`
    /// does. Omitting it leaves `open_body` skipping eight bytes of body.
    fn message(build: impl FnOnce(&mut Writer) -> Result<(), WireError>) -> Vec<u8> {
        let mut w = Writer::new(&crate::psi::FRAMING, 1);
        w.u64(0);
        let body = w.open();
        build(&mut w).expect("must encode");
        w.close(body);
        w.finish().expect("must finish")
    }

    fn body(bytes: &[u8]) -> Result<Reader<'_>, WireError> {
        crate::frame::open_body(&crate::psi::FRAMING, bytes, 1)
    }

    fn round_trip(values: Values) -> Values {
        let claim = Claim {
            name: "Department".into(),
            flags: FLAG_MANDATORY,
            values,
        };
        let bytes = message(|w| write_claims(w, core::slice::from_ref(&claim)));

        let mut r = body(&bytes).unwrap();
        let mut decoded = read_claims(&mut r).unwrap();
        assert_eq!(decoded.len(), 1);
        let decoded = decoded.remove(0);
        assert_eq!(decoded.name, "Department");
        assert_eq!(decoded.flags, FLAG_MANDATORY);
        decoded.values
    }

    #[test]
    fn every_value_type_round_trips() {
        assert_eq!(
            round_trip(Values::Int64(vec![-1, 0, i64::MIN, i64::MAX])),
            Values::Int64(vec![-1, 0, i64::MIN, i64::MAX])
        );
        assert_eq!(
            round_trip(Values::Uint64(vec![0, u64::MAX])),
            Values::Uint64(vec![0, u64::MAX])
        );
        assert_eq!(
            round_trip(Values::Boolean(vec![true, false])),
            Values::Boolean(vec![true, false])
        );
        assert_eq!(
            round_trip(Values::String(vec!["Engineering".into(), "".into()])),
            Values::String(vec!["Engineering".into(), "".into()])
        );
        assert_eq!(
            round_trip(Values::Sid(vec![vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]])),
            Values::Sid(vec![vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]])
        );
        assert_eq!(
            round_trip(Values::Octet(vec![vec![0xde, 0xad], Vec::new()])),
            Values::Octet(vec![vec![0xde, 0xad], Vec::new()])
        );
    }

    /// A claim with no values is not the same as no claim, and §3.9 says so.
    #[test]
    fn an_empty_claim_survives_a_round_trip_with_its_type() {
        assert_eq!(round_trip(Values::String(Vec::new())), Values::String(Vec::new()));
        assert_eq!(round_trip(Values::Int64(Vec::new())), Values::Int64(Vec::new()));
    }

    /// KACS normalises any non-zero to true. A decoder that compared against 1
    /// would read a claim written by a conforming producer as false.
    #[test]
    fn any_non_zero_boolean_decodes_as_true() {
        let bytes = message(|w| {
            w.count(1, MAX_CLAIMS)?;
            let claim = w.open();
            w.string("Contractor", MAX_NAME_BYTES)?;
            w.u32(0);
            w.u32(TYPE_BOOLEAN);
            w.count(1, MAX_VALUES)?;
            let value = w.open();
            w.u64(0xffff_ffff_ffff_ffff);
            w.close(value);
            w.close(claim);
            Ok(())
        });

        let mut r = body(&bytes).unwrap();
        assert_eq!(
            read_claims(&mut r).unwrap()[0].values,
            Values::Boolean(vec![true])
        );
    }

    #[test]
    fn an_unsupported_type_is_refused_rather_than_skipped() {
        let bytes = message(|w| {
            w.count(1, MAX_CLAIMS)?;
            let claim = w.open();
            w.string("Whatever", MAX_NAME_BYTES)?;
            w.u32(0);
            w.u32(0x0004); // FQBN, reserved and unsupported.
            w.count(0, MAX_VALUES)?;
            w.close(claim);
            Ok(())
        });

        let mut r = body(&bytes).unwrap();
        assert_eq!(read_claims(&mut r).unwrap_err(), WireError::UnknownValue);
    }

    #[test]
    fn validation_rejects_what_cannot_reach_a_token() {
        let good = Claim {
            name: "Department".into(),
            flags: FLAG_MANDATORY,
            values: Values::String(vec!["Engineering".into()]),
        };
        assert_eq!(good.validate(), Ok(()));

        let named = |name: &str| Claim {
            name: name.into(),
            ..good.clone()
        };
        assert_eq!(named("").validate(), Err(ClaimError::Name));
        assert_eq!(
            named(&"n".repeat(MAX_NAME_BYTES + 1)).validate(),
            Err(ClaimError::Name)
        );
        // The one that would otherwise pass and then silently truncate at the
        // C ABI, leaving a token carrying a shorter name than was set.
        assert_eq!(named("Dep\0artment").validate(), Err(ClaimError::Name));

        assert_eq!(
            Claim {
                flags: 0x8000_0000,
                ..good.clone()
            }
            .validate(),
            Err(ClaimError::UnknownFlags)
        );
        assert_eq!(
            Claim {
                values: Values::Int64(vec![0; MAX_VALUES + 1]),
                ..good.clone()
            }
            .validate(),
            Err(ClaimError::TooManyValues)
        );
        assert_eq!(
            Claim {
                values: Values::String(vec!["v".repeat(MAX_STRING_BYTES + 1)]),
                ..good.clone()
            }
            .validate(),
            Err(ClaimError::ValueTooLong)
        );
        assert_eq!(
            Claim {
                values: Values::Sid(vec![vec![0; MAX_SID_BYTES + 1]]),
                ..good
            }
            .validate(),
            Err(ClaimError::ValueTooLong)
        );
    }

    #[test]
    fn too_many_claims_is_rejected_by_the_encoder() {
        let claim = Claim {
            name: "Department".into(),
            flags: 0,
            values: Values::Int64(Vec::new()),
        };
        let mut w = Writer::new(&crate::psi::FRAMING, 1);
        assert_eq!(
            write_claims(&mut w, &vec![claim; MAX_CLAIMS + 1]).unwrap_err(),
            WireError::TooLong
        );
    }

    #[test]
    fn type_names_round_trip() {
        for values in [
            Values::Int64(Vec::new()),
            Values::Uint64(Vec::new()),
            Values::Boolean(Vec::new()),
            Values::String(Vec::new()),
            Values::Sid(Vec::new()),
            Values::Octet(Vec::new()),
        ] {
            let code = Values::type_from_name(values.type_name()).expect("must parse");
            assert_eq!(code, values.type_code());
            assert_eq!(Values::empty_of(code), Some(values));
        }
        assert_eq!(Values::type_from_name("fqbn"), None);
        assert_eq!(Values::empty_of(0x0004), None);
    }

    #[test]
    fn every_truncation_errors_rather_than_panics() {
        let claims = vec![
            Claim {
                name: "Department".into(),
                flags: FLAG_MANDATORY,
                values: Values::String(vec!["Engineering".into()]),
            },
            Claim {
                name: "Level".into(),
                flags: 0,
                values: Values::Int64(vec![7]),
            },
        ];
        let bytes = message(|w| write_claims(w, &claims));

        for cut in 0..bytes.len() {
            if let Ok(mut r) = body(&bytes[..cut]) {
                let _ = read_claims(&mut r);
            }
        }
    }
}
