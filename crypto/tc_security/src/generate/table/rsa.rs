use rand::CryptoRng;
use tc_asn1::NamedOid;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_rsa::{RsaKeyGenerationParamsRef, RsaKeyGenerator};

use super::no_key;
use crate::generate::{GeneratorEntry, KeyGenParams};
use crate::params::AnyParams;
use crate::{AnyError, SecurityError};

const PUBLIC_EXPONENT: u32 = 65537;
const STRENGTH: usize = 2048;
const CERTAINTY: u32 = 100;

fn check_params(params: &KeyGenParams) -> Result<(), SecurityError> {
    if matches!(
        params,
        KeyGenParams::Basic { .. } | KeyGenParams::Rsa { .. }
    ) {
        Ok(())
    } else {
        Err(SecurityError::InvalidKeyGenParams)
    }
}

fn generate_key_pair(
    params: &KeyGenParams,
    rng: &mut dyn CryptoRng,
) -> Result<(AnyParams, AnyParams), AnyError> {
    let (public_exponent, certainty) = match *params {
        KeyGenParams::Rsa {
            public_exponent,
            certainty,
            ..
        } => (public_exponent, certainty),
        _ => (PUBLIC_EXPONENT, CERTAINTY),
    };
    let strength = u32::try_from(params.strength())
        .map_err(|_| AnyError::new(SecurityError::InvalidKeyGenParams))?;
    let rsa_params = RsaKeyGenerationParamsRef::new(rng)
        .with_public_exponent(public_exponent)
        .with_strength(strength)
        .with_certainty(certainty);
    let mut generator = RsaKeyGenerator::new();
    generator.init(rsa_params).map_err(AnyError::new)?;
    let (public, private) = generator.generate_key_pair().map_err(AnyError::new)?;
    Ok((AnyParams::rsa(public), AnyParams::rsa(private)))
}

pub(super) const RSA: GeneratorEntry = GeneratorEntry::new(
    &["RSA"],
    &[NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
        "1.2.840.113549.1.1.1",
        "rsaEncryption",
    )],
    KeyGenParams::Rsa {
        public_exponent: PUBLIC_EXPONENT,
        strength: STRENGTH,
        certainty: CERTAINTY,
    },
    check_params,
    no_key,
    generate_key_pair,
);
