#[cfg(feature = "aes")]
mod aes;
#[cfg(any(feature = "aes", feature = "chacha", feature = "hmac-sha256"))]
mod key;
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
];
