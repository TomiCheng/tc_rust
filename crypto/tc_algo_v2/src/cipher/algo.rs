#[cfg(feature = "aes")]
mod aes;

use super::CipherEntry;

// What DefaultAlgoBuilder starts with: the rows of the ciphers whose features are on
pub(crate) const BUILT_IN: &[fn() -> Box<dyn CipherEntry>] = &[
    #[cfg(feature = "aes")]
    aes::aes_ecb_no_padding,
];
