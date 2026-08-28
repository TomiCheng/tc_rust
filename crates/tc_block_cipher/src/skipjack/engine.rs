//! SKIPJACK block-cipher engine, key schedule, and G/H permutations.

use tc_crypto_core::BlockCipher;

use super::{SKIPJACK_BLOCK_BYTES, BlockCipherError, SkipjackParams};

/// The SKIPJACK F-table (byte substitution).
#[rustfmt::skip]
const FTABLE: [u8; 256] = [
    0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
    0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
    0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
    0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
    0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
    0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
    0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
    0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d,
    0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
    0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
    0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
    0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
    0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
    0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
    0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
    0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46,
];

/// The 32-step expanded key: each byte of the 10-byte key cycled into four rows.
struct Subkeys {
    k0: [u8; 32],
    k1: [u8; 32],
    k2: [u8; 32],
    k3: [u8; 32],
}

/// SKIPJACK with an 80-bit key and 64-bit block.
pub struct SkipjackEngine {
    /// 展開金鑰;init 前為 `None` = 未初始化。
    keys: Option<Subkeys>,
    for_encryption: bool,
}

impl SkipjackEngine {
    /// Creates an uninitialised engine.
    pub fn new() -> Self {
        Self {
            keys: None,
            for_encryption: false,
        }
    }

    fn encrypt_block(key: &Subkeys, input: &[u8], output: &mut [u8]) {
        let mut w1 = read_word(input, 0);
        let mut w2 = read_word(input, 2);
        let mut w3 = read_word(input, 4);
        let mut w4 = read_word(input, 6);

        let mut k = 0i32;
        for _ in 0..2 {
            for _ in 0..8 {
                let tmp = w4;
                w4 = w3;
                w3 = w2;
                w2 = g(key, k as usize, w1);
                w1 = w2 ^ tmp ^ (k + 1) as u16;
                k += 1;
            }
            for _ in 0..8 {
                let tmp = w4;
                w4 = w3;
                w3 = w1 ^ w2 ^ (k + 1) as u16;
                w2 = g(key, k as usize, w1);
                w1 = tmp;
                k += 1;
            }
        }

        write_word(output, 0, w1);
        write_word(output, 2, w2);
        write_word(output, 4, w3);
        write_word(output, 6, w4);
    }

    fn decrypt_block(key: &Subkeys, input: &[u8], output: &mut [u8]) {
        let mut w2 = read_word(input, 0);
        let mut w1 = read_word(input, 2);
        let mut w4 = read_word(input, 4);
        let mut w3 = read_word(input, 6);

        let mut k = 31i32;
        for _ in 0..2 {
            for _ in 0..8 {
                let tmp = w4;
                w4 = w3;
                w3 = w2;
                w2 = h(key, k as usize, w1);
                w1 = w2 ^ tmp ^ (k + 1) as u16;
                k -= 1;
            }
            for _ in 0..8 {
                let tmp = w4;
                w4 = w3;
                w3 = w1 ^ w2 ^ (k + 1) as u16;
                w2 = h(key, k as usize, w1);
                w1 = tmp;
                k -= 1;
            }
        }

        write_word(output, 0, w2);
        write_word(output, 2, w1);
        write_word(output, 4, w4);
        write_word(output, 6, w3);
    }
}

impl Default for SkipjackEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockCipher for SkipjackEngine {
    type Params<'a> = SkipjackParams;
    type Error = BlockCipherError;

    fn algorithm_name(&self) -> &str {
        "SKIPJACK"
    }

    fn block_size(&self) -> usize {
        SKIPJACK_BLOCK_BYTES
    }

    fn init(&mut self, for_encryption: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        self.keys = Some(expand_key(params.key()));
        self.for_encryption = for_encryption;
        Ok(())
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let key = self.keys.as_ref().ok_or(BlockCipherError::NotInitialised)?;
        if input.len() < SKIPJACK_BLOCK_BYTES || output.len() < SKIPJACK_BLOCK_BYTES {
            return Err(BlockCipherError::BufferTooShort);
        }
        if self.for_encryption {
            SkipjackEngine::encrypt_block(key, input, output);
        } else {
            SkipjackEngine::decrypt_block(key, input, output);
        }
        Ok(SKIPJACK_BLOCK_BYTES)
    }
}

/// The keyed `G` permutation (four F-table rounds over the two bytes of `w`).
fn g(key: &Subkeys, k: usize, w: u16) -> u16 {
    let g1 = (w >> 8) as u8;
    let g2 = w as u8;
    let g3 = FTABLE[(g2 ^ key.k0[k]) as usize] ^ g1;
    let g4 = FTABLE[(g3 ^ key.k1[k]) as usize] ^ g2;
    let g5 = FTABLE[(g4 ^ key.k2[k]) as usize] ^ g3;
    let g6 = FTABLE[(g5 ^ key.k3[k]) as usize] ^ g4;
    (u16::from(g5) << 8) | u16::from(g6)
}

/// The inverse permutation `H` of [`g`].
fn h(key: &Subkeys, k: usize, w: u16) -> u16 {
    let h1 = w as u8;
    let h2 = (w >> 8) as u8;
    let h3 = FTABLE[(h2 ^ key.k3[k]) as usize] ^ h1;
    let h4 = FTABLE[(h3 ^ key.k2[k]) as usize] ^ h2;
    let h5 = FTABLE[(h4 ^ key.k1[k]) as usize] ^ h3;
    let h6 = FTABLE[(h5 ^ key.k0[k]) as usize] ^ h4;
    (u16::from(h6) << 8) | u16::from(h5)
}

/// Expands the 10-byte key into the four 32-step rows (cycling the key bytes).
fn expand_key(key: &[u8; 10]) -> Subkeys {
    let mut k = Subkeys {
        k0: [0; 32],
        k1: [0; 32],
        k2: [0; 32],
        k3: [0; 32],
    };
    for i in 0..32 {
        k.k0[i] = key[(i * 4) % 10];
        k.k1[i] = key[(i * 4 + 1) % 10];
        k.k2[i] = key[(i * 4 + 2) % 10];
        k.k3[i] = key[(i * 4 + 3) % 10];
    }
    k
}

/// Reads a big-endian 16-bit word at byte offset `off`.
fn read_word(input: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([input[off], input[off + 1]])
}

/// Writes a big-endian 16-bit word at byte offset `off`.
fn write_word(output: &mut [u8], off: usize, value: u16) {
    output[off..off + 2].copy_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_and_pre_init_errors() {
        let mut engine = SkipjackEngine::new();
        assert_eq!(engine.algorithm_name(), "SKIPJACK");
        assert_eq!(engine.block_size(), 8);
        assert_eq!(
            engine.process_block(&[0u8; 8], &mut [0u8; 8]),
            Err(BlockCipherError::NotInitialised)
        );
    }

    #[test]
    fn short_buffers_are_rejected() {
        let params = SkipjackParams::new(&[0u8; 10]).unwrap();
        let mut engine = SkipjackEngine::new();
        engine.init(true, &params).unwrap();
        assert_eq!(
            engine.process_block(&[0u8; 7], &mut [0u8; 8]),
            Err(BlockCipherError::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&[0u8; 8], &mut [0u8; 7]),
            Err(BlockCipherError::BufferTooShort)
        );
    }
}
