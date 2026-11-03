use rand_core::CryptoRng;
use tc_asn1::NamedOid;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_cfrg_curves::{KeyGenerationParams, X448KeyPairGenerator};

use crate::generate::KeyGenParams;
use crate::generate::key_pair::{KeyPair, KeyPairGeneratorEntry};
use crate::params::{AnyPrivateKey, AnyPublicKey};
use crate::{AlgoError, ErrorKind};

// The strength of Bouncy Castle's X448KeyGenerationParameters. X448 has one size, so this is
// the default and the only size init takes
const BITS: usize = 448;

fn check_params(params: &KeyGenParams) -> Result<(), AlgoError> {
    match params {
        KeyGenParams::Strength { bits: BITS } => Ok(()),
        _ => Err(AlgoError::new(ErrorKind::InvalidKeyGenParams)),
    }
}

fn generate(_: &KeyGenParams, rng: &mut dyn CryptoRng) -> Result<KeyPair, AlgoError> {
    let invalid = |error| AlgoError::with_source(ErrorKind::InvalidKeyGenParams, error);
    let mut generator = X448KeyPairGenerator::new();
    generator
        .init(KeyGenerationParams::new(rng))
        .map_err(invalid)?;
    let (public, private) = generator.generate_key_pair().map_err(invalid)?;
    Ok(KeyPair {
        public: AnyPublicKey::X448(public),
        private: AnyPrivateKey::X448(private),
    })
}

// Bouncy Castle's X448KeyPairGenerator, with id-X448 of RFC 8410 as its OID
pub(super) const X448: KeyPairGeneratorEntry = KeyPairGeneratorEntry::new(
    &["X448"],
    &[NamedOid::new(&[0x2b, 0x65, 0x6f], "1.3.101.111", "id-X448")],
    Some(KeyGenParams::Strength { bits: BITS }),
    check_params,
    generate,
);
