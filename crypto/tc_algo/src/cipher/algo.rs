#[cfg(feature = "aes")]
mod aes;
#[cfg(any(feature = "aes", feature = "des", feature = "desede"))]
mod block;
#[cfg(any(feature = "aes", feature = "des", feature = "desede"))]
mod buffered;
#[cfg(feature = "chacha")]
mod chacha;
#[cfg(any(feature = "des", feature = "desede"))]
mod des;
#[cfg(feature = "ies")]
mod ies;
#[cfg(feature = "rsa")]
mod rsa;

use super::CipherEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the ciphers whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "aes")]
    aes::aes,
    #[cfg(feature = "des")]
    des::des,
    #[cfg(feature = "desede")]
    des::desede,
    #[cfg(feature = "chacha")]
    chacha::chacha,
    #[cfg(feature = "rsa")]
    rsa::rsa,
    #[cfg(feature = "ies")]
    ies::ies,
];
