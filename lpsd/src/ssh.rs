//! SSH key parsing and proof verification in the credential owner.
use libauthd::ssh::{Binding, MAX_KEY, Offer};
use signature::Verifier;
use ssh_key::{Algorithm, HashAlg, PublicKey, Signature};

pub fn parse(blob: &[u8]) -> Option<PublicKey> {
    if blob.len() > MAX_KEY {
        return None;
    }
    let key = PublicKey::from_bytes(blob).ok()?;
    if key.to_bytes().ok()?.as_slice() != blob {
        return None;
    }
    match key.algorithm() {
        Algorithm::Ed25519 => {}
        Algorithm::Rsa { .. } => {
            let rsa = key.key_data().rsa()?;
            let n = rsa.n.as_positive_bytes()?;
            let bits = n
                .len()
                .checked_mul(8)?
                .checked_sub(n.first()?.leading_zeros() as usize)?;
            if !(3072..=8192).contains(&bits) {
                return None;
            }
            rsa_key(rsa)?;
        }
        _ => return None,
    }
    Some(key)
}

// ssh-key's conversion uses rsa's default 4096-bit ceiling. Our credential
// contract explicitly permits up to 8192 bits, with the same mathematical
// validation and a bounded public exponent.
fn rsa_key(key: &ssh_key::public::RsaPublicKey) -> Option<rsa::RsaPublicKey> {
    rsa::RsaPublicKey::new_with_max_size(
        rsa::BigUint::from_bytes_be(key.n.as_positive_bytes()?),
        rsa::BigUint::from_bytes_be(key.e.as_positive_bytes()?),
        8192,
    )
    .ok()
}

pub fn import(line: &str) -> Option<(Vec<u8>, String)> {
    if line.len() > 16384 || line.trim().contains(['\n', '\r']) {
        return None;
    }
    let key = PublicKey::from_openssh(line.trim()).ok()?;
    let bytes = key.to_bytes().ok()?;
    parse(&bytes)?;
    Some((bytes, key.comment().to_owned()))
}

pub fn eligible(blob: &[u8], algorithm: &str) -> bool {
    let Some(key) = parse(blob) else {
        return false;
    };
    match key.algorithm() {
        Algorithm::Ed25519 => algorithm == "ssh-ed25519",
        Algorithm::Rsa { .. } => matches!(algorithm, "rsa-sha2-256" | "rsa-sha2-512"),
        _ => false,
    }
}

pub fn verify(binding: &Binding, offer: &Offer) -> bool {
    if !eligible(&offer.key, &offer.algorithm) {
        return false;
    }
    let Some(key) = parse(&offer.key) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(offer.signature.as_slice()) else {
        return false;
    };
    if signature.algorithm().as_str() != offer.algorithm {
        return false;
    }
    let Ok(data) = binding.signed_data(offer) else {
        return false;
    };
    if let Some(public) = key.key_data().rsa() {
        let Some(public) = rsa_key(public) else {
            return false;
        };
        let Ok(proof) = rsa::pkcs1v15::Signature::try_from(signature.as_bytes()) else {
            return false;
        };
        match offer.algorithm.as_str() {
            "rsa-sha2-256" => rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(public)
                .verify(&data, &proof)
                .is_ok(),
            "rsa-sha2-512" => rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(public)
                .verify(&data, &proof)
                .is_ok(),
            _ => false,
        }
    } else {
        key.key_data().verify(&data, &signature).is_ok()
    }
}

pub fn fingerprint(blob: &[u8]) -> Option<String> {
    Some(parse(blob)?.fingerprint(HashAlg::Sha256).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use signature::Signer;
    use ssh_key::private::{Ed25519Keypair, Ed25519PrivateKey};

    #[test]
    fn rsa_upper_bound_proofs_and_invalid_exponent() {
        // Public-only vectors signed independently by OpenSSL. No private key
        // is needed or retained by the source or this test suite.
        let blob = include_bytes!("../tests/fixtures/rsa8192.pubblob");
        let binding = Binding {
            connection: [1; 16],
            session: vec![2; 32],
            username: "alice".into(),
        };
        for (algorithm, signature) in [
            (
                "rsa-sha2-256",
                include_bytes!("../tests/fixtures/rsa-sha2-256.proof").as_slice(),
            ),
            (
                "rsa-sha2-512",
                include_bytes!("../tests/fixtures/rsa-sha2-512.proof").as_slice(),
            ),
        ] {
            let mut offer = Offer {
                algorithm: algorithm.into(),
                key: blob.to_vec(),
                signature: signature.to_vec(),
            };
            assert!(verify(&binding, &offer));
            *offer.signature.last_mut().unwrap() ^= 1;
            assert!(!verify(&binding, &offer));
        }
        let key = parse(blob).unwrap();
        let mut rsa = key.key_data().rsa().unwrap().clone();
        rsa.e = ssh_key::Mpint::from_positive_bytes(&[1]).unwrap();
        assert!(parse(&PublicKey::new(rsa.into(), "invalid").to_bytes().unwrap()).is_none());
    }

    #[test]
    fn verifies_only_the_bound_identity_and_transport() {
        let pair = Ed25519Keypair::from(Ed25519PrivateKey::from_bytes(&[42; 32]));
        let key = PublicKey::new(pair.public.into(), "test");
        let binding = Binding {
            connection: [1; 16],
            session: vec![2; 32],
            username: "alice".into(),
        };
        let mut offer = Offer {
            algorithm: "ssh-ed25519".into(),
            key: key.to_bytes().unwrap(),
            signature: vec![],
        };
        let sig: Signature = pair
            .try_sign(&binding.signed_data(&offer).unwrap())
            .unwrap();
        offer.signature = Vec::try_from(sig).unwrap();
        assert!(verify(&binding, &offer));
        let mut other = binding.clone();
        other.username = "bob".into();
        assert!(!verify(&other, &offer));
        other = binding;
        other.session[0] ^= 1;
        assert!(!verify(&other, &offer));
        offer.algorithm = "ssh-rsa".into();
        assert!(!verify(&other, &offer));
    }
}
