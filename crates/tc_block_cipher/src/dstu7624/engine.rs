//! DSTU 7624 block-cipher engine.

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

use super::{
    BlockCipherError, Dstu7624Config, Dstu7624Params, ValidDstu7624Config, cipher,
};

macro_rules! impl_configuration {
    ($block:literal, $key:literal, $rounds:literal, $round_keys:literal) => {
        impl ValidDstu7624Config<$block> for Dstu7624Config<$block, $key> {
            const ROUNDS: usize = $rounds;

            type Schedule = [[u64; $block]; $round_keys];

            fn new_schedule() -> Self::Schedule {
                [[0_u64; $block]; $round_keys]
            }

            fn schedule(schedule: &Self::Schedule) -> &[[u64; $block]] {
                schedule
            }

            fn schedule_mut(schedule: &mut Self::Schedule) -> &mut [[u64; $block]] {
                schedule
            }
        }
    };
}

// 標準只定義金鑰等於或兩倍於分組的五種組合，rounds 由金鑰寬度決定。
impl_configuration!(2, 2, 10, 11); // Kalyna-128/128
impl_configuration!(2, 4, 14, 15); // Kalyna-128/256
impl_configuration!(4, 4, 14, 15); // Kalyna-256/256
impl_configuration!(4, 8, 18, 19); // Kalyna-256/512
impl_configuration!(8, 8, 18, 19); // Kalyna-512/512

/// Portable DSTU 7624 (Kalyna) block cipher with compile-time widths.
///
/// Both const parameters count 64-bit words: `BLOCK_WORDS` is 2, 4, or 8 for a
/// 128-, 256-, or 512-bit block, and `KEY_WORDS` is the same or twice that. Only
/// the five combinations the standard defines are implemented, so an unsupported
/// pairing is a compile error rather than a runtime one.
pub struct Dstu7624Engine<const BLOCK_WORDS: usize, const KEY_WORDS: usize>
where
    Dstu7624Config<BLOCK_WORDS, KEY_WORDS>: ValidDstu7624Config<BLOCK_WORDS>,
{
    cipher: cipher::Dstu7624Cipher<BLOCK_WORDS, KEY_WORDS>,
    for_encryption: bool,
    initialised: bool,
}

impl<const BLOCK_WORDS: usize, const KEY_WORDS: usize> Dstu7624Engine<BLOCK_WORDS, KEY_WORDS>
where
    Dstu7624Config<BLOCK_WORDS, KEY_WORDS>: ValidDstu7624Config<BLOCK_WORDS>,
{
    /// Creates an uninitialised engine for the selected block/key combination.
    pub fn new() -> Self {
        Self {
            cipher: cipher::Dstu7624Cipher::new(),
            for_encryption: false,
            initialised: false,
        }
    }
}

impl<const BLOCK_WORDS: usize, const KEY_WORDS: usize> Default
    for Dstu7624Engine<BLOCK_WORDS, KEY_WORDS>
where
    Dstu7624Config<BLOCK_WORDS, KEY_WORDS>: ValidDstu7624Config<BLOCK_WORDS>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const BLOCK_WORDS: usize, const KEY_WORDS: usize> BlockCipher
    for Dstu7624Engine<BLOCK_WORDS, KEY_WORDS>
where
    Dstu7624Config<BLOCK_WORDS, KEY_WORDS>: ValidDstu7624Config<BLOCK_WORDS>,
{
    type Error = BlockCipherError;

    fn algorithm_name(&self) -> &str {
        "DSTU7624"
    }

    fn block_size(&self) -> usize {
        cipher::Dstu7624Cipher::<BLOCK_WORDS, KEY_WORDS>::block_bytes()
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockCipherError::NotInitialised);
        }
        let block_bytes = self.block_size();
        if input.len() < block_bytes || output.len() < block_bytes {
            return Err(BlockCipherError::BufferTooShort);
        }

        if self.for_encryption {
            self.cipher.encrypt_block(input, output);
        } else {
            self.cipher.decrypt_block(input, output);
        }
        Ok(block_bytes)
    }
}

impl<const BLOCK_WORDS: usize, const KEY_WORDS: usize> BlockCipherInit
    for Dstu7624Engine<BLOCK_WORDS, KEY_WORDS>
where
    Dstu7624Config<BLOCK_WORDS, KEY_WORDS>: ValidDstu7624Config<BLOCK_WORDS>,
{
    type Params<'a> = Dstu7624Params<KEY_WORDS>;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        // 金鑰與分組的搭配已由型別保證，故此處無需再驗。
        self.cipher.set_key(params.key_words());
        self.for_encryption = direction == CipherDirection::Encrypt;
        self.initialised = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_and_pre_init_errors() {
        let mut engine = Dstu7624Engine::<4, 4>::new();
        assert_eq!(engine.algorithm_name(), "DSTU7624");
        assert_eq!(engine.block_size(), 32);
        assert_eq!(
            engine.process_block(&[0u8; 32], &mut [0u8; 32]),
            Err(BlockCipherError::NotInitialised)
        );
    }

    #[test]
    fn rejects_short_buffers() {
        let mut engine = Dstu7624Engine::<2, 2>::new();
        engine
            .init(
                CipherDirection::Encrypt,
                &Dstu7624Params::<2>::new(&[0u8; 16]).unwrap(),
            )
            .unwrap();
        assert_eq!(
            engine.process_block(&[0u8; 8], &mut [0u8; 16]),
            Err(BlockCipherError::BufferTooShort)
        );
    }

    #[test]
    fn each_valid_combination_reports_its_block_size() {
        assert_eq!(Dstu7624Engine::<2, 2>::new().block_size(), 16);
        assert_eq!(Dstu7624Engine::<2, 4>::new().block_size(), 16);
        assert_eq!(Dstu7624Engine::<4, 4>::new().block_size(), 32);
        assert_eq!(Dstu7624Engine::<4, 8>::new().block_size(), 32);
        assert_eq!(Dstu7624Engine::<8, 8>::new().block_size(), 64);
    }
}
