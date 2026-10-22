use rand::CryptoRng;
use tc_asn1::NamedOid;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_cfrg_curves::{CfrgError, KeyGenerationParams};

use super::no_key;
use crate::generate::{GeneratorEntry, KeyGenParams};
use crate::params::AnyParams;
use crate::{AnyError, SecurityError};

// 金鑰大小由曲線決定；同 BC，只用 rng，strength 不看
fn check_params(params: &KeyGenParams) -> Result<(), SecurityError> {
    if matches!(params, KeyGenParams::Basic { .. }) {
        Ok(())
    } else {
        Err(SecurityError::InvalidKeyGenParams)
    }
}

fn key_pair<'a, G>(
    mut generator: G,
    rng: &'a mut dyn CryptoRng,
    public: fn(G::PublicKey) -> AnyParams,
    private: fn(G::PrivateKey) -> AnyParams,
) -> Result<(AnyParams, AnyParams), AnyError>
where
    G: KeyPairGenerator<Error = CfrgError>
        + KeyPairGeneratorInit<KeyGenerationParams<'a>, Error = CfrgError>,
{
    generator
        .init(KeyGenerationParams::new(rng))
        .map_err(AnyError::new)?;
    let (public_key, private_key) = generator.generate_key_pair().map_err(AnyError::new)?;
    Ok((public(public_key), private(private_key)))
}

#[cfg(feature = "x25519")]
fn x25519(_: &KeyGenParams, rng: &mut dyn CryptoRng) -> Result<(AnyParams, AnyParams), AnyError> {
    key_pair(
        tc_cfrg_curves::X25519KeyPairGenerator::new(),
        rng,
        |key| AnyParams::X25519Public { key },
        |key| AnyParams::X25519Private { key },
    )
}

#[cfg(feature = "x448")]
fn x448(_: &KeyGenParams, rng: &mut dyn CryptoRng) -> Result<(AnyParams, AnyParams), AnyError> {
    key_pair(
        tc_cfrg_curves::X448KeyPairGenerator::new(),
        rng,
        |key| AnyParams::X448Public { key },
        |key| AnyParams::X448Private { key },
    )
}

#[cfg(feature = "ed25519")]
fn ed25519(_: &KeyGenParams, rng: &mut dyn CryptoRng) -> Result<(AnyParams, AnyParams), AnyError> {
    key_pair(
        tc_cfrg_curves::Ed25519KeyPairGenerator::new(),
        rng,
        |key| AnyParams::Ed25519Public { key },
        |key| AnyParams::Ed25519Private { key },
    )
}

#[cfg(feature = "ed448")]
fn ed448(_: &KeyGenParams, rng: &mut dyn CryptoRng) -> Result<(AnyParams, AnyParams), AnyError> {
    key_pair(
        tc_cfrg_curves::Ed448KeyPairGenerator::new(),
        rng,
        |key| AnyParams::Ed448Public { key },
        |key| AnyParams::Ed448Private { key },
    )
}

#[cfg(feature = "x25519")]
pub(super) const X25519: GeneratorEntry = GeneratorEntry::new(
    &["X25519"],
    &[NamedOid::new(
        &[0x2b, 0x65, 0x6e],
        "1.3.101.110",
        "id-X25519",
    )],
    KeyGenParams::Basic { strength: 256 },
    check_params,
    no_key,
    x25519,
);

#[cfg(feature = "x448")]
pub(super) const X448: GeneratorEntry = GeneratorEntry::new(
    &["X448"],
    &[NamedOid::new(&[0x2b, 0x65, 0x6f], "1.3.101.111", "id-X448")],
    KeyGenParams::Basic { strength: 448 },
    check_params,
    no_key,
    x448,
);

// ctx 與 ph 用同一種金鑰，同 BC 是別名
#[cfg(feature = "ed25519")]
pub(super) const ED25519: GeneratorEntry = GeneratorEntry::new(
    &["Ed25519", "Ed25519ctx", "Ed25519ph"],
    &[NamedOid::new(
        &[0x2b, 0x65, 0x70],
        "1.3.101.112",
        "id-Ed25519",
    )],
    KeyGenParams::Basic { strength: 256 },
    check_params,
    no_key,
    ed25519,
);

#[cfg(feature = "ed448")]
pub(super) const ED448: GeneratorEntry = GeneratorEntry::new(
    &["Ed448", "Ed448ph"],
    &[NamedOid::new(
        &[0x2b, 0x65, 0x71],
        "1.3.101.113",
        "id-Ed448",
    )],
    KeyGenParams::Basic { strength: 448 },
    check_params,
    no_key,
    ed448,
);
