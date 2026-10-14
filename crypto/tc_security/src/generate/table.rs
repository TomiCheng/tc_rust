//! 每個產生器一列；各自的 feature 關掉時，這個演算法就不會出現。

#[cfg(feature = "aes")]
mod aes;
#[cfg(feature = "rc2")]
mod rc2;
#[cfg(feature = "rc5")]
mod rc5;
#[cfg(feature = "rsa")]
mod rsa;

use super::GeneratorEntry;

#[cfg(any(feature = "aes", feature = "rc2", feature = "rc5"))]
fn random_key(strength: usize, rng: &mut dyn rand::CryptoRng) -> Vec<u8> {
    let mut key = vec![0; strength.div_ceil(8)];
    rng.fill_bytes(&mut key);
    key
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
    #[cfg(feature = "rc2")]
    rc2::RC2,
    #[cfg(feature = "rc5")]
    rc5::RC5,
    #[cfg(feature = "rc5")]
    rc5::RC5_64,
    #[cfg(feature = "rsa")]
    rsa::RSA,
];
