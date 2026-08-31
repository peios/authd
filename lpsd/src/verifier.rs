//! Password verifiers: what lpsd stores instead of a password.
//!
//! # Why a memory-hard KDF, and why nothing reversible
//!
//! The project's standing decision is plaintext over the local socket and an
//! argon2id-class verifier at rest. The two halves are one argument: a
//! challenge-response scheme would require storing something a response can be
//! recomputed from, which is password-equivalent material — the pass-the-hash
//! failure mode, where stealing the store is as good as knowing the passwords.
//! Storing only a verifier means compromising lpsd yields the thing an *offline
//! attack* is run against, not the ability to authenticate.
//!
//! Memory-hardness is what makes that offline attack expensive. A fast hash
//! (even a salted one) is a GPU problem; argon2id's memory cost is the
//! parameter that does not fall to more parallel silicon.
//!
//! # Parameters live in the record, not in this file
//!
//! Every verifier carries the algorithm and cost parameters it was created
//! with. That is what makes them upgradeable: raising the cost applies to
//! verifiers created afterwards, and older records stay verifiable until their
//! passwords are next set. A constant here, read at verification time, would
//! instead break every existing account the moment it changed.

use crate::codec::{CodecError, Reader, Writer};
use crate::random;

/// Which KDF produced a verifier.
///
/// One variant today. It exists so that changing KDF is a new variant and a
/// match arm rather than a store-format break — the same reason the parameters
/// are stored rather than assumed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Algorithm {
    Argon2id,
}

impl Algorithm {
    const ARGON2ID: u8 = 1;

    fn to_byte(self) -> u8 {
        match self {
            Self::Argon2id => Self::ARGON2ID,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            Self::ARGON2ID => Some(Self::Argon2id),
            _ => None,
        }
    }
}

/// Memory cost, in KiB. 19 MiB — the low-memory configuration OWASP recommends
/// for argon2id (19456 KiB, t=2, p=1). Chosen over the higher-memory variants
/// because lpsd runs on everything Peios runs on, including machines where
/// reserving 64 MiB per concurrent logon would be the more dangerous choice.
const MEMORY_KIB: u32 = 19_456;
/// Time cost (passes).
const PASSES: u32 = 2;
/// Parallelism. One lane: lpsd verifies one password at a time and threads
/// here would buy latency at the cost of making the memory figure per-lane.
const LANES: u32 = 1;
/// Salt length. 16 bytes is the argon2 recommendation and comfortably beyond
/// any birthday concern for a store with hundreds of records.
const SALT_BYTES: usize = 16;
/// Output length.
const HASH_BYTES: usize = 32;

#[derive(Debug)]
pub enum VerifierError {
    /// The KDF refused the parameters or the input.
    Kdf,
    /// Randomness was unavailable, so no salt could be drawn.
    NoRandomness(std::io::Error),
}

impl core::fmt::Display for VerifierError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Kdf => write!(f, "the key-derivation function failed"),
            Self::NoRandomness(e) => write!(f, "no randomness available: {e}"),
        }
    }
}

/// What is stored in place of a password.
#[derive(Clone, PartialEq, Eq)]
pub struct Verifier {
    algorithm: Algorithm,
    memory_kib: u32,
    passes: u32,
    lanes: u32,
    salt: Vec<u8>,
    hash: Vec<u8>,
}

/// Redacted. A verifier is not password-equivalent, but it is the input to an
/// offline attack, and a stray `{:?}` in a log is how it would escape.
impl core::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Verifier({:?}, redacted)", self.algorithm)
    }
}

impl Verifier {
    /// Derive a verifier for `password`, with a fresh salt and the current
    /// parameters.
    pub fn create(password: &[u8]) -> Result<Self, VerifierError> {
        let salt = random::array::<SALT_BYTES>().map_err(VerifierError::NoRandomness)?;
        Self::derive(password, &salt, MEMORY_KIB, PASSES, LANES)
    }

    /// A verifier for a password nobody knows.
    ///
    /// Used to make an unknown principal cost the same as a known one — see
    /// [`crate::store::Store::authenticate`]. Deriving it from randomness
    /// rather than from a fixed string means it is not merely unguessable but
    /// not even *constant*, so it cannot be recognised in a memory dump as "the
    /// decoy".
    pub fn decoy() -> Result<Self, VerifierError> {
        let password = random::array::<32>().map_err(VerifierError::NoRandomness)?;
        Self::create(&password)
    }

    fn derive(
        password: &[u8],
        salt: &[u8],
        memory_kib: u32,
        passes: u32,
        lanes: u32,
    ) -> Result<Self, VerifierError> {
        let hash = run_argon2id(password, salt, memory_kib, passes, lanes)?;
        Ok(Self {
            algorithm: Algorithm::Argon2id,
            memory_kib,
            passes,
            lanes,
            salt: salt.to_vec(),
            hash,
        })
    }

    /// Whether `password` is the one this verifier was made from.
    ///
    /// Recomputes with *this record's* parameters, not the current defaults, so
    /// an account created before a cost increase still verifies.
    pub fn verify(&self, password: &[u8]) -> bool {
        let Algorithm::Argon2id = self.algorithm;
        let Ok(candidate) = run_argon2id(
            password,
            &self.salt,
            self.memory_kib,
            self.passes,
            self.lanes,
        ) else {
            // A KDF failure is not a wrong password, but there is nothing
            // useful to say to a caller that must not learn the difference.
            return false;
        };
        constant_time_eq(&candidate, &self.hash)
    }

    pub fn encode(&self, w: &mut Writer) {
        w.u8(self.algorithm.to_byte());
        w.u32(self.memory_kib);
        w.u32(self.passes);
        w.u32(self.lanes);
        w.bytes(&self.salt);
        w.bytes(&self.hash);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let algorithm = Algorithm::from_byte(r.u8()?).ok_or(CodecError::Malformed)?;
        let memory_kib = r.u32()?;
        let passes = r.u32()?;
        let lanes = r.u32()?;
        let salt = r.bytes()?.to_vec();
        let hash = r.bytes()?.to_vec();

        // Parameters a future lpsd might write but this one cannot run. Caught
        // here rather than at verification time, where the failure would be
        // indistinguishable from a wrong password and would lock the account
        // out silently.
        if salt.is_empty() || hash.is_empty() || memory_kib == 0 || passes == 0 || lanes == 0 {
            return Err(CodecError::Malformed);
        }

        Ok(Self {
            algorithm,
            memory_kib,
            passes,
            lanes,
            salt,
            hash,
        })
    }
}

fn run_argon2id(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    passes: u32,
    lanes: u32,
) -> Result<Vec<u8>, VerifierError> {
    use argon2::{Algorithm as A, Argon2, Params, Version};

    let params =
        Params::new(memory_kib, passes, lanes, Some(HASH_BYTES)).map_err(|_| VerifierError::Kdf)?;
    let argon2 = Argon2::new(A::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; HASH_BYTES];
    argon2
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| VerifierError::Kdf)?;
    Ok(out)
}

/// Compare without branching on contents.
///
/// The comparison is between two derived hashes rather than between secrets, so
/// the exposure is smaller than it looks — but a verifier comparison is the
/// textbook place for this and writing it any other way invites the reader to
/// assume it was considered and rejected.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0u8;
    for (x, y) in a.iter().zip(b) {
        difference |= x ^ y;
    }
    core::hint::black_box(difference) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // Argon2id at 19 MiB is deliberately slow, so these use the cheapest
    // parameters the algorithm permits wherever the cost is not the point.
    fn cheap(password: &[u8], salt: &[u8]) -> Verifier {
        Verifier::derive(password, salt, 8, 1, 1).expect("must derive")
    }

    #[test]
    fn the_right_password_verifies() {
        let v = cheap(b"password", b"0123456789abcdef");
        assert!(v.verify(b"password"));
    }

    #[test]
    fn the_wrong_password_does_not() {
        let v = cheap(b"password", b"0123456789abcdef");
        assert!(!v.verify(b"Password"));
        assert!(!v.verify(b"passwor"));
        assert!(!v.verify(b"password "));
        assert!(!v.verify(b""));
    }

    #[test]
    fn the_password_is_not_recoverable_from_the_record() {
        let v = cheap(b"hunter2", b"0123456789abcdef");
        let mut w = Writer::new();
        v.encode(&mut w);
        let encoded = w.finish();
        assert!(
            !encoded.windows(7).any(|window| window == b"hunter2"),
            "the stored record must not contain the password"
        );
    }

    #[test]
    fn a_fresh_verifier_uses_a_fresh_salt() {
        let a = Verifier::create(b"same").expect("must create");
        let b = Verifier::create(b"same").expect("must create");
        assert_ne!(
            a.salt, b.salt,
            "two accounts with the same password must not share a salt"
        );
        assert_ne!(
            a.hash, b.hash,
            "identical passwords must not produce identical records"
        );
        assert!(a.verify(b"same") && b.verify(b"same"));
    }

    #[test]
    fn a_verifier_round_trips() {
        let v = cheap(b"password", b"0123456789abcdef");
        let mut w = Writer::new();
        v.encode(&mut w);
        let encoded = w.finish();

        let decoded = Verifier::decode(&mut Reader::new(&encoded)).expect("must decode");
        assert_eq!(decoded, v);
        assert!(decoded.verify(b"password"));
    }

    #[test]
    fn old_parameters_still_verify_after_the_defaults_move() {
        // The record carries m=8,t=1,p=1 while the defaults are far higher.
        // Verification must use the record's, or every existing account breaks
        // the day the cost is raised.
        let v = cheap(b"password", b"0123456789abcdef");
        assert_ne!(
            v.memory_kib, MEMORY_KIB,
            "the fixture must differ from the defaults for this to prove anything"
        );
        assert!(v.verify(b"password"));
    }

    #[test]
    fn a_fresh_verifier_uses_the_current_parameters() {
        let v = Verifier::create(b"password").expect("must create");
        assert_eq!(
            (v.memory_kib, v.passes, v.lanes),
            (MEMORY_KIB, PASSES, LANES)
        );
    }

    #[test]
    fn an_unknown_algorithm_is_refused() {
        let mut w = Writer::new();
        w.u8(0xFF);
        w.u32(8);
        w.u32(1);
        w.u32(1);
        w.bytes(b"0123456789abcdef");
        w.bytes(&[0u8; 32]);
        let encoded = w.finish();
        assert_eq!(
            Verifier::decode(&mut Reader::new(&encoded)),
            Err(CodecError::Malformed)
        );
    }

    #[test]
    fn degenerate_parameters_are_refused_at_decode() {
        for (memory, passes, lanes) in [(0, 1, 1), (8, 0, 1), (8, 1, 0)] {
            let mut w = Writer::new();
            w.u8(1);
            w.u32(memory);
            w.u32(passes);
            w.u32(lanes);
            w.bytes(b"0123456789abcdef");
            w.bytes(&[0u8; 32]);
            let encoded = w.finish();
            assert_eq!(
                Verifier::decode(&mut Reader::new(&encoded)),
                Err(CodecError::Malformed),
                "({memory}, {passes}, {lanes}) must be refused at decode, not at verify"
            );
        }
    }

    #[test]
    fn an_empty_salt_or_hash_is_refused() {
        for (salt, hash) in [
            (&b""[..], &[0u8; 32][..]),
            (&b"0123456789abcdef"[..], &[][..]),
        ] {
            let mut w = Writer::new();
            w.u8(1);
            w.u32(8);
            w.u32(1);
            w.u32(1);
            w.bytes(salt);
            w.bytes(hash);
            let encoded = w.finish();
            assert_eq!(
                Verifier::decode(&mut Reader::new(&encoded)),
                Err(CodecError::Malformed)
            );
        }
    }

    #[test]
    fn a_decoy_verifies_nothing_plausible() {
        let decoy = Verifier::decoy().expect("must create");
        assert!(!decoy.verify(b""));
        assert!(!decoy.verify(b"password"));
    }

    #[test]
    fn two_decoys_differ() {
        let a = Verifier::decoy().expect("must create");
        let b = Verifier::decoy().expect("must create");
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn debug_does_not_leak_the_record() {
        let v = cheap(b"password", b"0123456789abcdef");
        let rendered = format!("{v:?}");
        assert!(rendered.contains("Argon2id"));
        assert!(!rendered.contains("0123456789abcdef"), "{rendered}");
    }

    #[test]
    fn constant_time_eq_agrees_with_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }
}
