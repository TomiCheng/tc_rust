use rand_core::CryptoRng;
use tc_asn1::NamedOid;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_cfrg_curves::{KeyGenerationParams, X25519KeyPairGenerator};

use crate::generate::KeyGenParams;
use crate::generate::key_pair::{KeyPair, KeyPairGeneratorEntry};
use crate::params::{AnyPrivateKey, AnyPublicKey};
use crate::{AlgoError, ErrorKind};

// The strength of Bouncy Castle's X25519KeyGenerationParameters. X25519 has one size, so this is
// the default and the only size init takes
const BITS: usize = 255;

fn check_params(params: &KeyGenParams) -> Result<(), AlgoError> {
    match params {
        KeyGenParams::Strength { bits: BITS } => Ok(()),
        _ => Err(AlgoError::new(ErrorKind::InvalidKeyGenParams)),
    }
}

fn generate(_: &KeyGenParams, rng: &mut dyn CryptoRng) -> Result<KeyPair, AlgoError> {
    let invalid = |error| AlgoError::with_source(ErrorKind::InvalidKeyGenParams, error);
    let mut generator = X25519KeyPairGenerator::new();
    generator
        .init(KeyGenerationParams::new(rng))
        .map_err(invalid)?;
    let (public, private) = generator.generate_key_pair().map_err(invalid)?;
    Ok(KeyPair {
        public: AnyPublicKey::X25519(public),
        private: AnyPrivateKey::X25519(private),
    })
}

// Bouncy Castle's X25519KeyPairGenerator, with id-X25519 of RFC 8410 as its OID
pub(super) const X25519: KeyPairGeneratorEntry = KeyPairGeneratorEntry::new(
    &["X25519"],
    &[NamedOid::new(&[0x2b, 0x65, 0x6e], "1.3.101.110", "id-X25519")],
    Some(KeyGenParams::Strength { bits: BITS }),
    check_params,
    generate,
);
