//! 每個產生器一列；各自的 feature 關掉時，這個演算法就不會出現。

#[cfg(feature = "aes")]
mod aes;
#[cfg(feature = "aria")]
mod aria;
#[cfg(feature = "ascon")]
mod ascon;
#[cfg(feature = "camellia")]
mod camellia;
#[cfg(any(
    feature = "x25519",
    feature = "x448",
    feature = "ed25519",
    feature = "ed448"
))]
mod cfrg;
#[cfg(feature = "chacha")]
mod chacha;
#[cfg(any(feature = "des", feature = "desede"))]
mod des;
#[cfg(feature = "ec")]
mod ec;
#[cfg(feature = "rc2")]
mod rc2;
#[cfg(feature = "rc5")]
mod rc5;
#[cfg(feature = "rsa")]
mod rsa;
#[cfg(any(feature = "salsa20", feature = "rc4", feature = "vmpc", feature = "hc"))]
mod stream;

use super::GeneratorEntry;

#[cfg(any(
    feature = "aes",
    feature = "aria",
    feature = "ascon",
    feature = "camellia",
    feature = "chacha",
    feature = "rc2",
    feature = "rc5",
    feature = "salsa20",
    feature = "rc4",
    feature = "vmpc",
    feature = "hc"
))]
fn random_key(strength: usize, rng: &mut dyn rand::CryptoRng) -> Vec<u8> {
    let mut key = vec![0; strength.div_ceil(8)];
    rng.fill_bytes(&mut key);
    key
}

#[cfg(any(
    feature = "aes",
    feature = "aria",
    feature = "ascon",
    feature = "camellia",
    feature = "chacha",
    feature = "salsa20",
    feature = "rc4",
    feature = "vmpc",
    feature = "hc"
))]
fn plain_key(
    params: &super::KeyGenParams,
    rng: &mut dyn rand::CryptoRng,
) -> Result<crate::params::AnyParams, crate::SecurityError> {
    Ok(crate::params::AnyParams::new(random_key(
        params.strength(),
        rng,
    )))
}

#[cfg(any(
    feature = "rsa",
    feature = "x25519",
    feature = "x448",
    feature = "ed25519",
    feature = "ed448",
    feature = "ec"
))]
fn no_key(
    _: &super::KeyGenParams,
    _: &mut dyn rand::CryptoRng,
) -> Result<crate::params::AnyParams, crate::SecurityError> {
    Err(crate::SecurityError::WrongGenerator)
}

#[cfg(any(
    feature = "aes",
    feature = "aria",
    feature = "ascon",
    feature = "camellia",
    feature = "chacha",
    feature = "des",
    feature = "desede",
    feature = "rc2",
    feature = "rc5",
    feature = "salsa20",
    feature = "rc4",
    feature = "vmpc",
    feature = "hc"
))]
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
    #[cfg(feature = "aria")]
    aria::ARIA,
    #[cfg(feature = "aria")]
    aria::ARIA128,
    #[cfg(feature = "aria")]
    aria::ARIA192,
    #[cfg(feature = "aria")]
    aria::ARIA256,
    #[cfg(feature = "ascon")]
    ascon::ASCON_AEAD128,
    #[cfg(feature = "ascon")]
    ascon::ASCON128,
    #[cfg(feature = "ascon")]
    ascon::ASCON128A,
    #[cfg(feature = "ascon")]
    ascon::ASCON80PQ,
    #[cfg(feature = "camellia")]
    camellia::CAMELLIA,
    #[cfg(feature = "camellia")]
    camellia::CAMELLIA128,
    #[cfg(feature = "camellia")]
    camellia::CAMELLIA192,
    #[cfg(feature = "camellia")]
    camellia::CAMELLIA256,
    #[cfg(feature = "chacha")]
    chacha::CHACHA,
    #[cfg(feature = "chacha")]
    chacha::CHACHA7539,
    #[cfg(feature = "chacha")]
    chacha::XCHACHA20,
    #[cfg(feature = "salsa20")]
    stream::SALSA20,
    #[cfg(feature = "rc4")]
    stream::RC4,
    #[cfg(feature = "vmpc")]
    stream::VMPC,
    #[cfg(feature = "vmpc")]
    stream::VMPC_KSA3,
    #[cfg(feature = "hc")]
    stream::HC128,
    #[cfg(feature = "hc")]
    stream::HC256,
    #[cfg(feature = "des")]
    des::DES,
    #[cfg(feature = "desede")]
    des::DESEDE,
    #[cfg(feature = "desede")]
    des::DESEDE3,
    #[cfg(feature = "rc2")]
    rc2::RC2,
    #[cfg(feature = "rc5")]
    rc5::RC5,
    #[cfg(feature = "rc5")]
    rc5::RC5_64,
    #[cfg(feature = "rsa")]
    rsa::RSA,
    #[cfg(feature = "x25519")]
    cfrg::X25519,
    #[cfg(feature = "x448")]
    cfrg::X448,
    #[cfg(feature = "ed25519")]
    cfrg::ED25519,
    #[cfg(feature = "ed448")]
    cfrg::ED448,
    #[cfg(feature = "ec")]
    ec::EC,
];
