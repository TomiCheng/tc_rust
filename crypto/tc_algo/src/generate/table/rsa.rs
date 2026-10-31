use rand_core::CryptoRng;
use tc_asn1::NamedOid;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_rsa::{RsaKeyGenerationParamsRef, RsaKeyGenerator};

use crate::generate::{KeyGenParams, KeyPair, KeyPairGeneratorEntry};
use crate::params::{AnyPrivateKey, AnyPublicKey};
use crate::{AlgoError, ErrorKind};

// The size alone keeps the default exponent and certainty, as Bouncy Castle's
// KeyGenerationParameters do for RSA
fn check_params(params: &KeyGenParams) -> Result<(), AlgoError> {
    match params {
        KeyGenParams::Strength { .. } | KeyGenParams::Rsa(_) => Ok(()),
        #[allow(unreachable_patterns, reason = "every other variant may be off")]
        _ => Err(AlgoError::new(ErrorKind::InvalidKeyGenParams)),
    }
}

fn generate(params: &KeyGenParams, rng: &mut dyn CryptoRng) -> Result<KeyPair, AlgoError> {
    let rsa = match params {
        KeyGenParams::Rsa(rsa) => rsa.clone(),
        KeyGenParams::Strength { bits } => KeyGenParams::rsa().with_bits(*bits),
        #[allow(unreachable_patterns, reason = "every other variant may be off")]
        _ => return Err(AlgoError::new(ErrorKind::InvalidKeyGenParams)),
    };
    let bits =
        u32::try_from(rsa.bits).map_err(|_| AlgoError::new(ErrorKind::InvalidKeyGenParams))?;
    let rsa_params = RsaKeyGenerationParamsRef::new(rng)
        .with_public_exponent(rsa.public_exponent)
        .with_strength(bits)
        .with_certainty(rsa.certainty);
    // tc_rsa checks the values here, so its errors are about the params
    let invalid = |error| AlgoError::with_source(ErrorKind::InvalidKeyGenParams, error);
    let mut generator = RsaKeyGenerator::new();
    generator.init(rsa_params).map_err(invalid)?;
    let (public, private) = generator.generate_key_pair().map_err(invalid)?;
    Ok(KeyPair {
        public: AnyPublicKey::Rsa(public),
        private: AnyPrivateKey::Rsa(private),
    })
}

pub(super) const RSA: KeyPairGeneratorEntry = KeyPairGeneratorEntry::new(
    &["RSA"],
    &[NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
        "1.2.840.113549.1.1.1",
        "rsaEncryption",
    )],
    Some(KeyGenParams::Rsa(KeyGenParams::rsa())),
    check_params,
    generate,
);
