#[cfg(feature = "aes")]
mod aes;
#[cfg(feature = "dh")]
mod dh;
#[cfg(any(feature = "aes", feature = "chacha", feature = "hmac-sha256"))]
mod key;
#[cfg(feature = "ml-kem")]
mod ml_kem;
#[cfg(feature = "rsa")]
mod rsa;

use super::{CreateKeyGeneratorRows, CreateKeyPairGeneratorRows};

// What DefaultAlgoBuilder starts with: the rows of the key generators whose features are on
pub(crate) const BUILT_IN_KEY_GENERATORS: &[CreateKeyGeneratorRows] = &[
    #[cfg(feature = "aes")]
    aes::aes,
    #[cfg(any(feature = "aes", feature = "chacha", feature = "hmac-sha256"))]
    key::key,
];

// The same for the key pair generators
pub(crate) const BUILT_IN_KEY_PAIR_GENERATORS: &[CreateKeyPairGeneratorRows] = &[
    #[cfg(feature = "rsa")]
    rsa::rsa,
    #[cfg(feature = "dh")]
    dh::dh,
    #[cfg(feature = "ml-kem")]
    ml_kem::ml_kem,
];
