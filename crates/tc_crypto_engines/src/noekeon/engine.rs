//! Noekeon block-cipher engine and round functions.

use tc_crypto_core::BlockCipher;

use super::{NOEKEON_BLOCK_BYTES, BlockCipherError, NoekeonParams};

/// Number of rounds (also the block and key size in bytes).
const SIZE: usize = 16;

/// Round constants, indexed `0..=SIZE` (encryption ascends, decryption descends).
const ROUND_CONSTANTS: [u8; SIZE + 1] = [
    0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
    0xd4,
];

/// Noekeon with a 128-bit key and 128-bit block, in direct-key mode.
pub struct NoekeonEngine {
    /// 工作金鑰:加密為原始金鑰字;解密時 init 先做一次零金鑰 `theta`。
    k: [u32; 4],
    for_encryption: bool,
    initialised: bool,
}

impl NoekeonEngine {
    /// Creates an uninitialised engine.
    pub fn new() -> Self {
        Self {
            k: [0; 4],
            for_encryption: false,
            initialised: false,
        }
    }

    fn encrypt_block(&self, input: &[u8], output: &mut [u8]) {
        let mut a = read_words(input);
        for (round, &rc) in ROUND_CONSTANTS.iter().enumerate() {
            a[0] ^= u32::from(rc);
            theta(&mut a, &self.k);
            if round == SIZE {
                break;
            }
            pi1(&mut a);
            gamma(&mut a);
            pi2(&mut a);
        }
        write_words(&a, output);
    }

    fn decrypt_block(&self, input: &[u8], output: &mut [u8]) {
        let mut a = read_words(input);
        for (round, &rc) in ROUND_CONSTANTS.iter().enumerate().rev() {
            theta(&mut a, &self.k);
            a[0] ^= u32::from(rc);
            if round == 0 {
                break;
            }
            pi1(&mut a);
            gamma(&mut a);
            pi2(&mut a);
        }
        write_words(&a, output);
    }
}

impl Default for NoekeonEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockCipher for NoekeonEngine {
    type Params<'a> = NoekeonParams;
    type Error = BlockCipherError;

    fn algorithm_name(&self) -> &str {
        "Noekeon"
    }

    fn block_size(&self) -> usize {
        NOEKEON_BLOCK_BYTES
    }

    fn init(&mut self, for_encryption: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        self.k = read_words(params.key());
        // 解密工作金鑰 = 對金鑰施以零金鑰 theta(bc 的 `theta(k, {0,0,0,0})`)。
        if !for_encryption {
            theta(&mut self.k, &[0; 4]);
        }
        self.for_encryption = for_encryption;
        self.initialised = true;
        Ok(())
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockCipherError::NotInitialised);
        }
        if input.len() < NOEKEON_BLOCK_BYTES || output.len() < NOEKEON_BLOCK_BYTES {
            return Err(BlockCipherError::BufferTooShort);
        }
        if self.for_encryption {
            self.encrypt_block(input, output);
        } else {
            self.decrypt_block(input, output);
        }
        Ok(NOEKEON_BLOCK_BYTES)
    }
}

/// Reads four big-endian 32-bit words from a 16-byte block.
fn read_words(input: &[u8]) -> [u32; 4] {
    let mut a = [0u32; 4];
    for (word, chunk) in a.iter_mut().zip(input.chunks_exact(4)) {
        *word = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    a
}

/// Writes four 32-bit words as big-endian bytes into a 16-byte block.
fn write_words(a: &[u32; 4], output: &mut [u8]) {
    for (word, chunk) in a.iter().zip(output.chunks_exact_mut(4)) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
}

/// The linear diffusion layer, mixing in the working key `k`.
fn theta(a: &mut [u32; 4], k: &[u32; 4]) {
    let mut t02 = a[0] ^ a[2];
    t02 ^= t02.rotate_left(8) ^ t02.rotate_left(24);

    a[0] ^= k[0];
    a[1] ^= k[1];
    a[2] ^= k[2];
    a[3] ^= k[3];

    let mut t13 = a[1] ^ a[3];
    t13 ^= t13.rotate_left(8) ^ t13.rotate_left(24);

    a[0] ^= t13;
    a[1] ^= t02;
    a[2] ^= t13;
    a[3] ^= t02;
}

/// The first bit-shuffle layer.
fn pi1(a: &mut [u32; 4]) {
    a[1] = a[1].rotate_left(1);
    a[2] = a[2].rotate_left(5);
    a[3] = a[3].rotate_left(2);
}

/// The second bit-shuffle layer (inverse rotations of [`pi1`]).
fn pi2(a: &mut [u32; 4]) {
    a[1] = a[1].rotate_left(31);
    a[2] = a[2].rotate_left(27);
    a[3] = a[3].rotate_left(30);
}

/// The nonlinear layer (an involution).
fn gamma(a: &mut [u32; 4]) {
    let t = a[3];
    a[1] ^= a[3] | a[2];
    a[3] = a[0] ^ (a[2] & !a[1]);

    a[2] = t ^ !a[1] ^ a[2] ^ a[3];

    a[1] ^= a[3] | a[2];
    a[0] = t ^ (a[2] & a[1]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_and_pre_init_errors() {
        let mut engine = NoekeonEngine::new();
        assert_eq!(engine.algorithm_name(), "Noekeon");
        assert_eq!(engine.block_size(), 16);
        assert_eq!(
            engine.process_block(&[0u8; 16], &mut [0u8; 16]),
            Err(BlockCipherError::NotInitialised)
        );
    }

    #[test]
    fn short_buffers_are_rejected() {
        let params = NoekeonParams::new(&[0u8; 16]).unwrap();
        let mut engine = NoekeonEngine::new();
        engine.init(true, &params).unwrap();
        assert_eq!(
            engine.process_block(&[0u8; 15], &mut [0u8; 16]),
            Err(BlockCipherError::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&[0u8; 16], &mut [0u8; 15]),
            Err(BlockCipherError::BufferTooShort)
        );
    }

    #[test]
    fn gamma_is_an_involution() {
        let mut a = [0x0123_4567u32, 0x89AB_CDEF, 0xFEDC_BA98, 0x7654_3210];
        let original = a;
        gamma(&mut a);
        gamma(&mut a);
        assert_eq!(a, original);
    }
}
