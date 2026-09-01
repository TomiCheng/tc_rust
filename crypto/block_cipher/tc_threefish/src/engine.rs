//! Threefish block-cipher engine.

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyWithTweakParams;

use crate::cipher::{self, C_240};
use crate::{TWEAK_BYTES, valid_word_count};

/// Threefish with a compile-time block and key width.
///
/// `WORDS` must be 4, 8, or 16, selecting Threefish-256, Threefish-512, or
/// Threefish-1024. The named aliases are usually more convenient.
pub struct ThreefishEngine<const WORDS: usize> {
    key: [u64; WORDS],
    parity: u64,
    tweak: [u64; 3],
    for_encryption: bool,
    initialised: bool,
}

impl<const WORDS: usize> ThreefishEngine<WORDS> {
    const VALID_WORD_COUNT: () = assert!(
        valid_word_count(WORDS),
        "Threefish WORDS must be 4, 8, or 16"
    );

    /// Creates an uninitialised engine for the selected Threefish variant.
    pub const fn new() -> Self {
        let () = Self::VALID_WORD_COUNT;
        Self {
            key: [0; WORDS],
            parity: 0,
            tweak: [0; 3],
            for_encryption: false,
            initialised: false,
        }
    }
}

impl<const WORDS: usize> Default for ThreefishEngine<WORDS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const WORDS: usize> AlgorithmName for ThreefishEngine<WORDS> {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        match WORDS {
            4 => output.write_str("Threefish-256"),
            8 => output.write_str("Threefish-512"),
            16 => output.write_str("Threefish-1024"),
            _ => unreachable!("ThreefishEngine validates WORDS"),
        }
    }
}

impl<const WORDS: usize> BlockCipher for ThreefishEngine<WORDS> {
    fn block_size(&self) -> usize {
        WORDS * 8
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        if !self.initialised {
            return Err(BlockError::NotInitialised);
        }

        let block_bytes = self.block_size();
        if input.len() < block_bytes || output.len() < block_bytes {
            return Err(BlockError::BufferTooShort);
        }

        let mut input_words = [0u64; WORDS];
        for (word, bytes) in input_words
            .iter_mut()
            .zip(input[..block_bytes].chunks_exact(8))
        {
            *word = u64::from_le_bytes(bytes.try_into().unwrap());
        }

        let mut output_words = [0u64; WORDS];
        let variant = cipher::variant(WORDS);
        if self.for_encryption {
            cipher::encrypt(
                &variant,
                &self.key,
                self.parity,
                &self.tweak,
                &input_words,
                &mut output_words,
            );
        } else {
            cipher::decrypt(
                &variant,
                &self.key,
                self.parity,
                &self.tweak,
                &input_words,
                &mut output_words,
            );
        }

        for (word, bytes) in output_words
            .iter()
            .zip(output[..block_bytes].chunks_exact_mut(8))
        {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        Ok(block_bytes)
    }
}

impl<const WORDS: usize> BlockCipherInit for ThreefishEngine<WORDS> {
    type Params<'a> = dyn KeyWithTweakParams + 'a;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), InitError> {
        let key = params.key();
        let key_bytes = WORDS * 8;
        if key.len() != key_bytes {
            return Err(InitError::InvalidKeyLength(key.len()));
        }

        let tweak = params.tweak();
        if let Some(tweak) = tweak
            && tweak.len() != TWEAK_BYTES
        {
            return Err(InitError::InvalidTweakLength(tweak.len()));
        }

        for (word, bytes) in self.key.iter_mut().zip(key.chunks_exact(8)) {
            *word = u64::from_le_bytes(bytes.try_into().unwrap());
        }
        self.parity = self.key.iter().fold(C_240, |parity, word| parity ^ word);

        let mut tweak_words = [0u64; 2];
        if let Some(tweak) = tweak {
            for (word, bytes) in tweak_words.iter_mut().zip(tweak.chunks_exact(8)) {
                *word = u64::from_le_bytes(bytes.try_into().unwrap());
            }
        }
        self.tweak = [
            tweak_words[0],
            tweak_words[1],
            tweak_words[0] ^ tweak_words[1],
        ];

        self.for_encryption = direction == CipherDirection::Encrypt;
        self.initialised = true;
        Ok(())
    }
}
