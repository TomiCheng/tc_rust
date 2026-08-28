//! TEA block-cipher engine.

use tc_crypto_core::BlockCipher;

use super::{TEA_BLOCK_BYTES, TeaError, TeaParams};

/// The golden-ratio round constant.
const DELTA: u32 = 0x9E37_79B9;
/// The starting sum for decryption (`DELTA * 32`).
const D_SUM: u32 = 0xC6EF_3720;
/// Number of rounds.
const ROUNDS: usize = 32;

/// TEA with a 128-bit key and 64-bit block.
pub struct TeaEngine {
    /// 四個 32 位子鑰 `[a, b, c, d]`;init 前為 `None` = 未初始化。
    key: Option<[u32; 4]>,
    for_encryption: bool,
}

impl TeaEngine {
    /// Creates an uninitialised engine.
    pub fn new() -> Self {
        Self {
            key: None,
            for_encryption: false,
        }
    }

    fn encrypt_block(k: &[u32; 4], input: &[u8], output: &mut [u8]) {
        let [a, b, c, d] = *k;
        let mut v0 = read_word(input, 0);
        let mut v1 = read_word(input, 4);
        let mut sum = 0u32;
        for _ in 0..ROUNDS {
            sum = sum.wrapping_add(DELTA);
            v0 = v0.wrapping_add(feistel(v1, sum, a, b));
            v1 = v1.wrapping_add(feistel(v0, sum, c, d));
        }
        write_word(output, 0, v0);
        write_word(output, 4, v1);
    }

    fn decrypt_block(k: &[u32; 4], input: &[u8], output: &mut [u8]) {
        let [a, b, c, d] = *k;
        let mut v0 = read_word(input, 0);
        let mut v1 = read_word(input, 4);
        let mut sum = D_SUM;
        for _ in 0..ROUNDS {
            v1 = v1.wrapping_sub(feistel(v0, sum, c, d));
            v0 = v0.wrapping_sub(feistel(v1, sum, a, b));
            sum = sum.wrapping_sub(DELTA);
        }
        write_word(output, 0, v0);
        write_word(output, 4, v1);
    }
}

impl Default for TeaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockCipher for TeaEngine {
    type Params<'a> = TeaParams;
    type Error = TeaError;

    fn algorithm_name(&self) -> &str {
        "TEA"
    }

    fn block_size(&self) -> usize {
        TEA_BLOCK_BYTES
    }

    fn init(&mut self, for_encryption: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        let key = params.key();
        self.key = Some([
            read_word(key, 0),
            read_word(key, 4),
            read_word(key, 8),
            read_word(key, 12),
        ]);
        self.for_encryption = for_encryption;
        Ok(())
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let key = self.key.as_ref().ok_or(TeaError::NotInitialised)?;
        if input.len() < TEA_BLOCK_BYTES || output.len() < TEA_BLOCK_BYTES {
            return Err(TeaError::BufferTooShort);
        }
        if self.for_encryption {
            TeaEngine::encrypt_block(key, input, output);
        } else {
            TeaEngine::decrypt_block(key, input, output);
        }
        Ok(TEA_BLOCK_BYTES)
    }
}

/// One half of the TEA round: `((x << 4) + k0) ^ (x + sum) ^ ((x >> 5) + k1)`.
fn feistel(x: u32, sum: u32, k0: u32, k1: u32) -> u32 {
    ((x << 4).wrapping_add(k0)) ^ x.wrapping_add(sum) ^ ((x >> 5).wrapping_add(k1))
}

/// Reads a big-endian 32-bit word at byte offset `off`.
fn read_word(input: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(input[off..off + 4].try_into().unwrap())
}

/// Writes a big-endian 32-bit word at byte offset `off`.
fn write_word(output: &mut [u8], off: usize, value: u32) {
    output[off..off + 4].copy_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_and_pre_init_errors() {
        let mut engine = TeaEngine::new();
        assert_eq!(engine.algorithm_name(), "TEA");
        assert_eq!(engine.block_size(), 8);
        assert_eq!(
            engine.process_block(&[0u8; 8], &mut [0u8; 8]),
            Err(TeaError::NotInitialised)
        );
    }

    #[test]
    fn short_buffers_are_rejected() {
        let params = TeaParams::new(&[0u8; 16]).unwrap();
        let mut engine = TeaEngine::new();
        engine.init(true, &params).unwrap();
        assert_eq!(
            engine.process_block(&[0u8; 7], &mut [0u8; 8]),
            Err(TeaError::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&[0u8; 8], &mut [0u8; 7]),
            Err(TeaError::BufferTooShort)
        );
    }
}
