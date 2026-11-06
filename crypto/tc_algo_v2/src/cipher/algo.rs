#[cfg(feature = "aes")]
mod aes;
#[cfg(feature = "chacha")]
mod chacha;
#[cfg(feature = "rsa")]
mod rsa;

use super::CipherEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the ciphers whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "aes")]
    aes::aes,
    #[cfg(feature = "chacha")]
    chacha::chacha,
    #[cfg(feature = "rsa")]
    rsa::rsa,
];
