//! The Threefish engine.
//!
//! The word count is a const generic so each variant stores and processes only
//! its own key and block width. Per-variant round functions live in
//! [`super::cipher`].

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

use super::cipher::{self, C_240};
use super::{BlockCipherError, ThreefishParams, valid_word_count};

/// Threefish with a compile-time block/key width.
///
/// `WORDS` must be 4, 8, or 16, selecting Threefish-256, Threefish-512, or
/// Threefish-1024. Prefer the named aliases exported by the crate.
pub struct ThreefishEngine<const WORDS: usize> {
    /// Key words excluding the separately stored parity word.
    key_words: [u64; WORDS],
    /// `C_240 ^ key_words[0] ^ ...`, the final extended-key word.
    parity: u64,
    /// Tweak schedule: `t0`, `t1`, `t0 ^ t1`.
    tweak: [u64; 3],
    initialised: bool,
    for_encryption: bool,
}

impl<const WORDS: usize> ThreefishEngine<WORDS> {
    const VALID_WORD_COUNT: () = assert!(
        valid_word_count(WORDS),
        "Threefish WORDS must be 4, 8, or 16"
    );

    /// Creates an uninitialised engine for the selected Threefish variant.
    pub fn new() -> Self {
        let () = Self::VALID_WORD_COUNT;
        Self {
            key_words: [0; WORDS],
            parity: 0,
            tweak: [0; 3],
            initialised: false,
            for_encryption: false,
        }
    }
}

impl<const WORDS: usize> Default for ThreefishEngine<WORDS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const WORDS: usize> BlockCipher for ThreefishEngine<WORDS> {
    type Error = BlockCipherError;

    fn algorithm_name(&self) -> &str {
        match WORDS {
            4 => "Threefish-256",
            8 => "Threefish-512",
            16 => "Threefish-1024",
            _ => unreachable!("ThreefishEngine validates WORDS"),
        }
    }

    fn block_size(&self) -> usize {
        WORDS * 8
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockCipherError::NotInitialised);
        }
        let bytes = self.block_size();
        if input.len() < bytes || output.len() < bytes {
            return Err(BlockCipherError::BufferTooShort);
        }

        let mut input_words = [0_u64; WORDS];
        for (word, bytes) in input_words.iter_mut().zip(input[..bytes].chunks_exact(8)) {
            *word = u64::from_le_bytes(bytes.try_into().unwrap());
        }

        let mut output_words = [0_u64; WORDS];
        let variant = cipher::variant(WORDS);
        if self.for_encryption {
            cipher::encrypt(
                &variant,
                &self.key_words,
                self.parity,
                &self.tweak,
                &input_words,
                &mut output_words,
            );
        } else {
            cipher::decrypt(
                &variant,
                &self.key_words,
                self.parity,
                &self.tweak,
                &input_words,
                &mut output_words,
            );
        }

        for (word, bytes) in output_words.iter().zip(output[..bytes].chunks_exact_mut(8)) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        Ok(bytes)
    }
}

impl<const WORDS: usize> BlockCipherInit for ThreefishEngine<WORDS> {
    type Params<'a> = ThreefishParams<WORDS>;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.key_words.copy_from_slice(params.key_words());
        self.parity = self
            .key_words
            .iter()
            .fold(C_240, |parity, word| parity ^ word);

        let [t0, t1] = *params.tweak_words();
        self.tweak = [t0, t1, t0 ^ t1];
        self.initialised = true;
        self.for_encryption = direction == CipherDirection::Encrypt;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_accessors_are_known_before_init() {
        let engine = ThreefishEngine::<4>::new();
        assert_eq!(engine.block_size(), 32);
        assert_eq!(engine.algorithm_name(), "Threefish-256");

        let engine = ThreefishEngine::<8>::new();
        assert_eq!(engine.block_size(), 64);
        assert_eq!(engine.algorithm_name(), "Threefish-512");

        let engine = ThreefishEngine::<16>::new();
        assert_eq!(engine.block_size(), 128);
        assert_eq!(engine.algorithm_name(), "Threefish-1024");
    }

    #[test]
    fn process_block_before_init_errors() {
        let mut engine = ThreefishEngine::<4>::new();
        assert_eq!(
            engine.process_block(&[0_u8; 32], &mut [0_u8; 32]),
            Err(BlockCipherError::NotInitialised)
        );
    }

    #[test]
    fn storage_increases_only_by_the_selected_key_width() {
        let size_256 = core::mem::size_of::<ThreefishEngine<4>>();
        let size_512 = core::mem::size_of::<ThreefishEngine<8>>();
        let size_1024 = core::mem::size_of::<ThreefishEngine<16>>();

        assert_eq!(size_512 - size_256, 4 * 8);
        assert_eq!(size_1024 - size_512, 8 * 8);
    }
}
