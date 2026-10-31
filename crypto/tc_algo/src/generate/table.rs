// One row per generator; an algorithm whose feature is off does not appear

#[cfg(feature = "rsa")]
mod rsa;

use super::KeyPairGeneratorEntry;

pub(super) const KEY_PAIR_GENERATORS: &[KeyPairGeneratorEntry] = &[
    #[cfg(feature = "rsa")]
    rsa::RSA,
];
