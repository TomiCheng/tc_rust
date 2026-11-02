use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_dh_key::{DhKeyGenerationParams, DhKeyPairGenerator};

use crate::generate::{KeyGenParams, KeyPair, KeyPairGeneratorEntry};
use crate::params::{AnyPrivateKey, AnyPublicKey};
use crate::{AlgoError, ErrorKind};

// The group alone: a size does not name one, so Bouncy Castle refuses it too
fn check_params(params: &KeyGenParams) -> Result<(), AlgoError> {
    match params {
        KeyGenParams::Dh(_) => Ok(()),
        _ => Err(AlgoError::new(ErrorKind::InvalidKeyGenParams)),
    }
}

fn generate(params: &KeyGenParams, rng: &mut dyn CryptoRng) -> Result<KeyPair, AlgoError> {
    let KeyGenParams::Dh(group) = params else {
        return Err(AlgoError::new(ErrorKind::InvalidKeyGenParams));
    };
    // tc_dh_key checks the group here, so its errors are about the params
    let invalid = |error| AlgoError::with_source(ErrorKind::InvalidKeyGenParams, error);
    let mut generator = DhKeyPairGenerator::new();
    generator
        .init(DhKeyGenerationParams::new(group.clone(), rng))
        .map_err(invalid)?;
    let (public, private) = generator.generate_key_pair().map_err(invalid)?;
    Ok(KeyPair {
        public: AnyPublicKey::Dh(public),
        private: AnyPrivateKey::Dh(private),
    })
}

// Bouncy Castle's DHKeyPairGenerator, with its alias and, as there, no OID. It has no default
// group, so init is required
pub(super) const DH: KeyPairGeneratorEntry =
    KeyPairGeneratorEntry::new(&["DH", "DIFFIEHELLMAN"], &[], None, check_params, generate);
