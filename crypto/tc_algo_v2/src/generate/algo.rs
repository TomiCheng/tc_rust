#[cfg(feature = "aes")]
mod aes;

use super::CreateKeyGeneratorRows;

// What DefaultAlgoBuilder starts with: the rows of the key generators whose features are on
pub(crate) const BUILT_IN_KEY_GENERATORS: &[CreateKeyGeneratorRows] = &[
    #[cfg(feature = "aes")]
    aes::aes,
];
