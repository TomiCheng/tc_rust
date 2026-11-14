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
    feature = "blowfish",
    feature = "twofish",
    feature = "serpent",
    feature = "tnepres",
    feature = "cast5",
    feature = "cast6",
))]
mod block;
#[cfg(feature = "blowfish")]
mod blowfish;
#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "desede",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
    feature = "blowfish",
    feature = "twofish",
    feature = "serpent",
    feature = "tnepres",
    feature = "cast5",
    feature = "cast6",
))]
mod buffered;
#[cfg(feature = "camellia")]
mod camellia;
#[cfg(feature = "cast5")]
mod cast5;
#[cfg(feature = "cast6")]
mod cast6;
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
#[cfg(feature = "serpent")]
mod serpent;
#[cfg(feature = "sm4")]
mod sm4;
#[cfg(feature = "tnepres")]
mod tnepres;
#[cfg(feature = "twofish")]
mod twofish;

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
    #[cfg(feature = "blowfish")]
    blowfish::blowfish,
    #[cfg(feature = "twofish")]
    twofish::twofish,
    #[cfg(feature = "serpent")]
    serpent::serpent,
    #[cfg(feature = "tnepres")]
    tnepres::tnepres,
    #[cfg(feature = "cast5")]
    cast5::cast5,
    #[cfg(feature = "cast6")]
    cast6::cast6,
    #[cfg(feature = "chacha")]
    chacha::chacha,
    #[cfg(feature = "rsa")]
    rsa::rsa,
    #[cfg(feature = "ies")]
    ies::ies,
];
