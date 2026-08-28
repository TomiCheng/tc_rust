//! XTEA block-cipher engine and key schedule.

use tc_crypto_core::BlockCipher;

use super::{XTEA_BLOCK_BYTES, XteaError, XteaParams};

/// The golden-ratio round constant.
const DELTA: u32 = 0x9E37_79B9;
/// Number of rounds.
const ROUNDS: usize = 32;

/// The precomputed round-key schedule.
struct Schedule {
    sum0: [u32; ROUNDS],
    sum1: [u32; ROUNDS],
}

/// XTEA with a 128-bit key and 64-bit block.
pub struct XteaEngine {
    /// 預算的 sum0/sum1 排程;init 前為 `None` = 未初始化。
    schedule: Option<Schedule>,
    for_encryption: bool,
}

impl XteaEngine {
    /// Creates an uninitialised engine.
    pub fn new() -> Self {
        Self {
            schedule: None,
            for_encryption: false,
        }
    }

    fn encrypt_block(s: &Schedule, input: &[u8], output: &mut [u8]) {
        let mut v0 = read_word(input, 0);
        let mut v1 = read_word(input, 4);
        for i in 0..ROUNDS {
            v0 = v0.wrapping_add(mix(v1) ^ s.sum0[i]);
            v1 = v1.wrapping_add(mix(v0) ^ s.sum1[i]);
        }
        write_word(output, 0, v0);
        write_word(output, 4, v1);
    }

    fn decrypt_block(s: &Schedule, input: &[u8], output: &mut [u8]) {
        let mut v0 = read_word(input, 0);
        let mut v1 = read_word(input, 4);
        for i in (0..ROUNDS).rev() {
            v1 = v1.wrapping_sub(mix(v0) ^ s.sum1[i]);
            v0 = v0.wrapping_sub(mix(v1) ^ s.sum0[i]);
        }
        write_word(output, 0, v0);
        write_word(output, 4, v1);
    }
}

impl Default for XteaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockCipher for XteaEngine {
    type Params<'a> = XteaParams;
    type Error = XteaError;

    fn algorithm_name(&self) -> &str {
        "XTEA"
    }

    fn block_size(&self) -> usize {
        XTEA_BLOCK_BYTES
    }

    fn init(&mut self, for_encryption: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        self.schedule = Some(build_schedule(params.key()));
        self.for_encryption = for_encryption;
        Ok(())
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let s = self.schedule.as_ref().ok_or(XteaError::NotInitialised)?;
        if input.len() < XTEA_BLOCK_BYTES || output.len() < XTEA_BLOCK_BYTES {
            return Err(XteaError::BufferTooShort);
        }
        if self.for_encryption {
            XteaEngine::encrypt_block(s, input, output);
        } else {
            XteaEngine::decrypt_block(s, input, output);
        }
        Ok(XTEA_BLOCK_BYTES)
    }
}

/// The round mixing function `(x << 4 ^ x >> 5) + x`.
fn mix(x: u32) -> u32 {
    ((x << 4) ^ (x >> 5)).wrapping_add(x)
}

/// Precomputes the `sum0`/`sum1` round keys from the four key words.
fn build_schedule(key: &[u8; 16]) -> Schedule {
    let s = [
        read_word(key, 0),
        read_word(key, 4),
        read_word(key, 8),
        read_word(key, 12),
    ];
    let mut sum0 = [0u32; ROUNDS];
    let mut sum1 = [0u32; ROUNDS];
    let mut j = 0u32;
    for i in 0..ROUNDS {
        sum0[i] = j.wrapping_add(s[(j & 3) as usize]);
        j = j.wrapping_add(DELTA);
        sum1[i] = j.wrapping_add(s[((j >> 11) & 3) as usize]);
    }
    Schedule { sum0, sum1 }
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
        let mut engine = XteaEngine::new();
        assert_eq!(engine.algorithm_name(), "XTEA");
        assert_eq!(engine.block_size(), 8);
        assert_eq!(
            engine.process_block(&[0u8; 8], &mut [0u8; 8]),
            Err(XteaError::NotInitialised)
        );
    }

    #[test]
    fn short_buffers_are_rejected() {
        let params = XteaParams::new(&[0u8; 16]).unwrap();
        let mut engine = XteaEngine::new();
        engine.init(true, &params).unwrap();
        assert_eq!(
            engine.process_block(&[0u8; 7], &mut [0u8; 8]),
            Err(XteaError::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&[0u8; 8], &mut [0u8; 7]),
            Err(XteaError::BufferTooShort)
        );
    }
}
