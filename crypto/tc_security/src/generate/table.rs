//! 每個產生器一列；各自的 feature 關掉時，這個演算法就不會出現。

#[cfg(feature = "aes")]
mod aes;
#[cfg(feature = "rsa")]
mod rsa;

use super::GeneratorEntry;

pub(super) const GENERATORS: &[GeneratorEntry] = &[
    #[cfg(feature = "aes")]
    aes::AES,
    #[cfg(feature = "aes")]
    aes::AES128,
    #[cfg(feature = "aes")]
    aes::AES192,
    #[cfg(feature = "aes")]
    aes::AES256,
    #[cfg(feature = "rsa")]
    rsa::RSA,
];
