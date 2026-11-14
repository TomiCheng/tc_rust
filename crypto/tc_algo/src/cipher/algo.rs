#[cfg(feature = "aes")]
mod aes;
#[cfg(feature = "aria")]
mod aria;
#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "desede",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
))]
mod block;
#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "desede",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
))]
mod buffered;
#[cfg(feature = "camellia")]
mod camellia;
#[cfg(feature = "chacha")]
mod chacha;
#[cfg(any(feature = "des", feature = "desede"))]
mod des;
#[cfg(feature = "ies")]
mod ies;
#[cfg(feature = "rsa")]
mod rsa;
#[cfg(feature = "seed")]
mod seed;
#[cfg(feature = "sm4")]
mod sm4;

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
    #[cfg(feature = "camellia")]
    camellia::camellia,
    #[cfg(feature = "aria")]
    aria::aria,
    #[cfg(feature = "sm4")]
    sm4::sm4,
    #[cfg(feature = "seed")]
    seed::seed,
    #[cfg(feature = "chacha")]
    chacha::chacha,
    #[cfg(feature = "rsa")]
    rsa::rsa,
    #[cfg(feature = "ies")]
    ies::ies,
];
