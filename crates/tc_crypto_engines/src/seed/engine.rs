//! SEED block-cipher engine, key schedule, and round function.

use tc_crypto_core::BlockCipher;

use super::tables::{KC, SS0, SS1, SS2, SS3};
use super::{SEED_BLOCK_BYTES, SeedError, SeedParams};

/// SEED with a 128-bit key and 128-bit block.
pub struct SeedEngine {
    /// 32 個工作金鑰字;init 前為 `None` = 未初始化。
    wkey: Option<[u32; 32]>,
    for_encryption: bool,
}

impl SeedEngine {
    /// Creates an uninitialised engine.
    pub fn new() -> Self {
        Self {
            wkey: None,
            for_encryption: false,
        }
    }
}

impl Default for SeedEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockCipher for SeedEngine {
    type Params<'a> = SeedParams;
    type Error = SeedError;

    fn algorithm_name(&self) -> &str {
        "SEED"
    }

    fn block_size(&self) -> usize {
        SEED_BLOCK_BYTES
    }

    fn init(&mut self, for_encryption: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        self.wkey = Some(create_working_key(params.key()));
        self.for_encryption = for_encryption;
        Ok(())
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let wk = self.wkey.as_ref().ok_or(SeedError::NotInitialised)?;
        if input.len() < SEED_BLOCK_BYTES || output.len() < SEED_BLOCK_BYTES {
            return Err(SeedError::BufferTooShort);
        }

        let mut l = u64::from_be_bytes(input[0..8].try_into().unwrap());
        let mut r = u64::from_be_bytes(input[8..16].try_into().unwrap());

        if self.for_encryption {
            for i in (0..32).step_by(4) {
                l ^= f(wk[i], wk[i + 1], r);
                r ^= f(wk[i + 2], wk[i + 3], l);
            }
        } else {
            for i in (0..=28).rev().step_by(4) {
                l ^= f(wk[i + 2], wk[i + 3], r);
                r ^= f(wk[i], wk[i + 1], l);
            }
        }

        // 輸出兩半互換:r 在前、l 在後。
        output[0..8].copy_from_slice(&r.to_be_bytes());
        output[8..16].copy_from_slice(&l.to_be_bytes());
        Ok(SEED_BLOCK_BYTES)
    }
}

/// The G function: combine the four S-box lookups of `x`'s bytes.
fn g(x: u32) -> u32 {
    SS0[(x & 0xff) as usize]
        ^ SS1[((x >> 8) & 0xff) as usize]
        ^ SS2[((x >> 16) & 0xff) as usize]
        ^ SS3[((x >> 24) & 0xff) as usize]
}

/// The round function `F` over a 64-bit half `r` and two subkey words.
fn f(ki0: u32, ki1: u32, r: u64) -> u64 {
    let r0 = ki0 ^ (r >> 32) as u32;
    let r1 = ki1 ^ r as u32;

    let t0 = g(r0 ^ r1);
    let t1 = g(r0.wrapping_add(t0));
    let rd1 = g(t1.wrapping_add(t0));
    let rd0 = rd1.wrapping_add(t1);

    (u64::from(rd0) << 32) | u64::from(rd1)
}

/// Expands the 128-bit key into 32 working-key words.
fn create_working_key(key: &[u8; 16]) -> [u32; 32] {
    let mut key0 = u32::from_be_bytes(key[0..4].try_into().unwrap());
    let mut key1 = u32::from_be_bytes(key[4..8].try_into().unwrap());
    let mut key2 = u32::from_be_bytes(key[8..12].try_into().unwrap());
    let mut key3 = u32::from_be_bytes(key[12..16].try_into().unwrap());

    let mut wk = [0u32; 32];
    for i in (0..16).step_by(2) {
        let kc_i = KC[i];
        wk[2 * i] = g(key0.wrapping_add(key2).wrapping_sub(kc_i));
        wk[2 * i + 1] = g(key1.wrapping_sub(key3).wrapping_add(kc_i));
        // 偶數步:{key0, key1} 右旋一個位元組。
        let keyt = key0 >> 8 | key1 << 24;
        key1 = key1 >> 8 | key0 << 24;
        key0 = keyt;

        let kc_i = KC[i + 1];
        wk[2 * i + 2] = g(key0.wrapping_add(key2).wrapping_sub(kc_i));
        wk[2 * i + 3] = g(key1.wrapping_sub(key3).wrapping_add(kc_i));
        // 奇數步:{key2, key3} 左旋一個位元組。
        let keyt = key2 << 8 | key3 >> 24;
        key3 = key3 << 8 | key2 >> 24;
        key2 = keyt;
    }
    wk
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_and_pre_init_errors() {
        let mut engine = SeedEngine::new();
        assert_eq!(engine.algorithm_name(), "SEED");
        assert_eq!(engine.block_size(), 16);
        assert_eq!(
            engine.process_block(&[0u8; 16], &mut [0u8; 16]),
            Err(SeedError::NotInitialised)
        );
    }

    #[test]
    fn short_buffers_are_rejected() {
        let params = SeedParams::new(&[0u8; 16]).unwrap();
        let mut engine = SeedEngine::new();
        engine.init(true, &params).unwrap();
        assert_eq!(
            engine.process_block(&[0u8; 15], &mut [0u8; 16]),
            Err(SeedError::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&[0u8; 16], &mut [0u8; 15]),
            Err(SeedError::BufferTooShort)
        );
    }
}
