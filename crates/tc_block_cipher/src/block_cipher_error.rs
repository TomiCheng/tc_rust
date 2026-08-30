//! Shared error taxonomy for software block-cipher engines.

use core::fmt;

/// Common failures produced while configuring or processing a block cipher.
///
/// Concrete engines may use this type directly when these variants cover their
/// complete failure surface. [`BlockCipher`](tc_cipher_core::BlockCipher) keeps
/// its error as an associated type, so engines with different failure modes can
/// still expose a more specific error type. More common variants may be added as
/// additional engines are implemented; downstream matches must include a
/// wildcard arm.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockCipherError {
    /// The supplied key length was invalid for the algorithm, in bytes.
    InvalidKeyLength(usize),
    /// The configured block size was invalid for the algorithm, in bits.
    InvalidBlockSize(usize),
    /// The key and block sizes are individually valid but not in combination.
    UnsupportedKeyForBlock {
        /// Configured block length in bits.
        block_bits: usize,
        /// Supplied key length in bits.
        key_bits: usize,
    },
    /// A custom S-box had an invalid length, in bytes.
    InvalidSBoxLength(usize),
    /// A custom S-box entry was outside the algorithm's allowed value range.
    InvalidSBoxValue {
        /// Index of the invalid entry.
        index: usize,
        /// Invalid entry value.
        value: u8,
    },
    /// A custom S-box row was not a valid permutation.
    InvalidSBoxRow(usize),
    /// The requested effective key size was invalid, in bits.
    InvalidEffectiveKeyBits(usize),
    /// The requested round count was invalid.
    InvalidRounds(usize),
    /// The supplied tweak length was invalid, in bytes.
    InvalidTweakLength(usize),
    /// Block processing was requested before successful initialization.
    NotInitialised,
    /// The input or output buffer could not hold one complete block.
    BufferTooShort,
}

impl fmt::Display for BlockCipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(bytes) => {
                write!(f, "invalid block-cipher key length: {bytes} bytes")
            }
            Self::InvalidBlockSize(bits) => {
                write!(f, "invalid block-cipher block size: {bits} bits")
            }
            Self::UnsupportedKeyForBlock {
                block_bits,
                key_bits,
            } => write!(
                f,
                "a {key_bits}-bit key is unsupported for a {block_bits}-bit block"
            ),
            Self::InvalidSBoxLength(bytes) => {
                write!(f, "invalid block-cipher S-box length: {bytes} bytes")
            }
            Self::InvalidSBoxValue { index, value } => {
                write!(
                    f,
                    "invalid block-cipher S-box value {value} at index {index}"
                )
            }
            Self::InvalidSBoxRow(row) => {
                write!(f, "invalid block-cipher S-box row: {row}")
            }
            Self::InvalidEffectiveKeyBits(bits) => {
                write!(f, "invalid effective block-cipher key size: {bits} bits")
            }
            Self::InvalidRounds(rounds) => {
                write!(f, "invalid block-cipher round count: {rounds}")
            }
            Self::InvalidTweakLength(bytes) => {
                write!(f, "invalid block-cipher tweak length: {bytes} bytes")
            }
            Self::NotInitialised => write!(f, "block cipher not initialised"),
            Self::BufferTooShort => {
                write!(f, "input or output buffer too short for one block")
            }
        }
    }
}

impl core::error::Error for BlockCipherError {}

#[cfg(test)]
mod tests {
    use super::*;
    use tc_cipher_core::BlockCipher;

    #[test]
    fn configuration_and_buffer_failures_remain_distinct() {
        assert_ne!(
            BlockCipherError::InvalidBlockSize(96),
            BlockCipherError::BufferTooShort
        );
        assert_eq!(
            BlockCipherError::InvalidBlockSize(96).to_string(),
            "invalid block-cipher block size: 96 bits"
        );
        assert_eq!(
            BlockCipherError::BufferTooShort.to_string(),
            "input or output buffer too short for one block"
        );
    }

    #[test]
    fn structured_variants_retain_validation_context() {
        let error = BlockCipherError::UnsupportedKeyForBlock {
            block_bits: 128,
            key_bits: 512,
        };
        assert_eq!(
            error.to_string(),
            "a 512-bit key is unsupported for a 128-bit block"
        );

        let error = BlockCipherError::InvalidSBoxValue {
            index: 7,
            value: 16,
        };
        assert_eq!(
            error.to_string(),
            "invalid block-cipher S-box value 16 at index 7"
        );
    }

    fn assert_shared_error<C: BlockCipher<Error = BlockCipherError>>() {}

    #[test]
    fn every_public_block_cipher_uses_the_shared_error() {
        assert_shared_error::<crate::AesEngine>();
        assert_shared_error::<crate::AesLightEngine>();
        assert_shared_error::<crate::AriaEngine>();
        assert_shared_error::<crate::BlowfishEngine>();
        assert_shared_error::<crate::CamelliaEngine>();
        assert_shared_error::<crate::CamelliaLightEngine>();
        assert_shared_error::<crate::Cast5Engine>();
        assert_shared_error::<crate::Cast6Engine>();
        assert_shared_error::<crate::DesEngine>();
        assert_shared_error::<crate::DesEdeEngine>();
        assert_shared_error::<crate::Dstu7624Engine<4, 4>>();
        assert_shared_error::<crate::Gost28147Engine>();
        assert_shared_error::<crate::IdeaEngine>();
        assert_shared_error::<crate::NoekeonEngine>();
        assert_shared_error::<crate::Rc2Engine>();
        #[cfg(feature = "alloc")]
        assert_shared_error::<crate::Rc532Engine>();
        #[cfg(feature = "alloc")]
        assert_shared_error::<crate::Rc564Engine>();
        assert_shared_error::<crate::Rc6Engine>();
        assert_shared_error::<crate::RijndaelEngine<4, 4>>();
        assert_shared_error::<crate::SeedEngine>();
        assert_shared_error::<crate::SerpentEngine>();
        assert_shared_error::<crate::TnepresEngine>();
        assert_shared_error::<crate::SkipjackEngine>();
        assert_shared_error::<crate::Sm4Engine>();
        assert_shared_error::<crate::TeaEngine>();
        assert_shared_error::<crate::Threefish256Engine>();
        assert_shared_error::<crate::Threefish512Engine>();
        assert_shared_error::<crate::Threefish1024Engine>();
        assert_shared_error::<crate::TwofishEngine>();
        assert_shared_error::<crate::XteaEngine>();
    }
}
