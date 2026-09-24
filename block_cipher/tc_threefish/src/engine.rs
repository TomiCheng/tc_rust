//! Threefish block-cipher engine.

use core::fmt;

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_zeroize::Zeroize;

use crate::cipher::{self, C_240};
use crate::{
    THREEFISH_256_ALGO_NAME, THREEFISH_512_ALGO_NAME, THREEFISH_1024_ALGO_NAME, TWEAK_BYTES,
    TweakParams,
};

/// Threefish with a compile-time block and key width.
///
/// `WORDS` must be 4, 8, or 16, selecting Threefish-256, Threefish-512, or
/// Threefish-1024. The named aliases are usually more convenient.
///
/// Constant time with respect to key, tweak and block contents: additions,
/// XORs, rotations and schedule indices follow public round parameters.
///
/// Stored keys, parity and tweaks are wiped on replacement and drop. This
/// does not wipe caller buffers or guarantee erasure of every register or stack copy.
///
/// # Example
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_threefish_v2::{Params, Threefish256Engine};
///
/// let key = [0x42; 32];
/// let tweak = [0x11; 16];
/// let plaintext = [0x22; 32];
/// let params = Params::with_tweak(&key, &tweak);
/// let mut engine = Threefish256Engine::new();
/// engine.init(CipherDirection::Encrypt, &params)?;
/// let mut encrypted = [0; 32];
/// engine.process_block(&plaintext, &mut encrypted)?;
/// engine.init(CipherDirection::Decrypt, &params)?;
/// let mut recovered = [0; 32];
/// engine.process_block(&encrypted, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
///
/// Unsupported block widths are rejected at compile time:
///
/// ```compile_fail
/// const INVALID: tc_threefish_v2::ThreefishEngine<3> = tc_threefish_v2::ThreefishEngine::new();
/// ```
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

    /// Creates an uninitialised engine for the selected Threefish variant. Constant time.
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
    /// Creates an uninitialised engine. Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl<const WORDS: usize> fmt::Display for ThreefishEngine<WORDS> {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match WORDS {
            4 => output.write_str(THREEFISH_256_ALGO_NAME),
            8 => output.write_str(THREEFISH_512_ALGO_NAME),
            16 => output.write_str(THREEFISH_1024_ALGO_NAME),
            _ => unreachable!("ThreefishEngine validates WORDS"),
        }
    }
}

impl<const WORDS: usize> BlockCipher for ThreefishEngine<WORDS> {
    type Error = BlockError;

    /// Returns the selected block length in bytes. Constant time.
    fn block_size(&self) -> usize {
        WORDS * 8
    }

    /// Processes one block and returns its length, preserving any output tail.
    ///
    /// Returns `NotInitialised` or `BufferTooShort` without touching output.
    /// Constant time with respect to key, tweak and block contents.
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

impl<P: KeyParams + TweakParams + ?Sized, const WORDS: usize> BlockCipherInit<P>
    for ThreefishEngine<WORDS>
{
    type Error = InitError;

    /// Installs a block-sized key and an optional 16-byte tweak for the selected direction.
    ///
    /// An absent tweak means zero. Invalid key or tweak lengths preserve all prior state.
    /// Constant time with respect to key and tweak contents; lengths are public.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        let key_bytes = WORDS * 8;
        if key.len() != key_bytes {
            return Err(InitError::InvalidKeyLength(key.len()));
        }

        let tweak = params.tweak();
        if let Some(tweak) = tweak {
            if tweak.len() != TWEAK_BYTES {
                return Err(InitError::InvalidTweakLength(tweak.len()));
            }
        }

        self.key.zeroize();
        self.parity.zeroize();
        self.tweak.zeroize();
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

        tweak_words.zeroize();
        self.for_encryption = direction == CipherDirection::Encrypt;
        self.initialised = true;
        Ok(())
    }
}

impl<const WORDS: usize> Drop for ThreefishEngine<WORDS> {
    fn drop(&mut self) {
        self.key.zeroize();
        self.parity.zeroize();
        self.tweak.zeroize();
    }
}

/// Checks a public block-width parameter. Constant time with respect to secrets.
pub(crate) const fn valid_word_count(words: usize) -> bool {
    matches!(words, 4 | 8 | 16)
}

/// Threefish-256 engine with a 32-byte block and key.
pub type Threefish256Engine = ThreefishEngine<4>;
/// Threefish-512 engine with a 64-byte block and key.
pub type Threefish512Engine = ThreefishEngine<8>;
/// Threefish-1024 engine with a 128-byte block and key.
pub type Threefish1024Engine = ThreefishEngine<16>;
