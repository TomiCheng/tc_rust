//! 每個產生器一列；各自的 feature 關掉時，這個演算法就不會出現。

#[cfg(feature = "aes")]
mod aes;
#[cfg(feature = "chacha")]
mod chacha;
#[cfg(feature = "rc2")]
mod rc2;
#[cfg(feature = "rc5")]
mod rc5;
#[cfg(feature = "rsa")]
mod rsa;

use super::GeneratorEntry;

#[cfg(any(feature = "aes", feature = "chacha", feature = "rc2", feature = "rc5"))]
fn random_key(strength: usize, rng: &mut dyn rand::CryptoRng) -> Vec<u8> {
    let mut key = vec![0; strength.div_ceil(8)];
    rng.fill_bytes(&mut key);
    key
}

#[cfg(any(feature = "aes", feature = "chacha"))]
fn plain_key(
    params: &super::KeyGenParams,
    rng: &mut dyn rand::CryptoRng,
) -> Result<crate::params::AnyParams, crate::SecurityError> {
    Ok(crate::params::AnyParams::new(random_key(
        params.strength(),
        rng,
    )))
}

#[cfg(feature = "rsa")]
fn no_key(
    _: &super::KeyGenParams,
    _: &mut dyn rand::CryptoRng,
) -> Result<crate::params::AnyParams, crate::SecurityError> {
    Err(crate::SecurityError::WrongGenerator)
}

#[cfg(any(feature = "aes", feature = "chacha", feature = "rc2", feature = "rc5"))]
fn no_key_pair(
    _: &super::KeyGenParams,
    _: &mut dyn rand::CryptoRng,
) -> Result<(crate::params::AnyParams, crate::params::AnyParams), crate::AnyError> {
    Err(crate::AnyError::new(crate::SecurityError::WrongGenerator))
}

pub(super) const GENERATORS: &[GeneratorEntry] = &[
    #[cfg(feature = "aes")]
    aes::AES,
    #[cfg(feature = "aes")]
    aes::AES128,
    #[cfg(feature = "aes")]
    aes::AES192,
    #[cfg(feature = "aes")]
    aes::AES256,
    #[cfg(feature = "chacha")]
    chacha::CHACHA,
    #[cfg(feature = "chacha")]
    chacha::CHACHA7539,
    #[cfg(feature = "chacha")]
    chacha::XCHACHA20,
    #[cfg(feature = "rc2")]
    rc2::RC2,
    #[cfg(feature = "rc5")]
    rc5::RC5,
    #[cfg(feature = "rc5")]
    rc5::RC5_64,
    #[cfg(feature = "rsa")]
    rsa::RSA,
];
