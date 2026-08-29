//! RC6 block-cipher engine, key schedule, and round functions.

use alloc::vec;

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

use super::{BlockCipherError, RC6_BLOCK_BYTES, RC6_ROUNDS, Rc6Params};

/// Magic constant `Odd((e - 2) * 2^32)`.
const P32: u32 = 0xb7e1_5163;
/// Magic constant `Odd((phi - 1) * 2^32)`.
const Q32: u32 = 0x9e37_79b9;
/// Number of subkey words: `2 * rounds + 4`.
const SUBKEY_WORDS: usize = 2 * RC6_ROUNDS + 4;

/// RC6-32/20 with a variable-length key and 128-bit block.
pub struct Rc6Engine {
    /// 展開金鑰排程 S(44 字);init 前為 `None` = 未初始化。
    s: Option<[u32; SUBKEY_WORDS]>,
    for_encryption: bool,
}

impl Rc6Engine {
    /// Creates an uninitialised engine.
    pub fn new() -> Self {
        Self {
            s: None,
            for_encryption: false,
        }
    }

    fn encrypt_block(s: &[u32; SUBKEY_WORDS], input: &[u8], output: &mut [u8]) {
        let mut a = read_word(input, 0);
        let mut b = read_word(input, 1);
        let mut c = read_word(input, 2);
        let mut d = read_word(input, 3);

        // 前置白化。
        b = b.wrapping_add(s[0]);
        d = d.wrapping_add(s[1]);

        for i in 1..=RC6_ROUNDS {
            let t = f(b).rotate_left(5);
            let u = f(d).rotate_left(5);
            a = (a ^ t).rotate_left(u).wrapping_add(s[2 * i]);
            c = (c ^ u).rotate_left(t).wrapping_add(s[2 * i + 1]);
            // (A, B, C, D) <- (B, C, D, A)
            (a, b, c, d) = (b, c, d, a);
        }

        // 後置白化。
        a = a.wrapping_add(s[2 * RC6_ROUNDS + 2]);
        c = c.wrapping_add(s[2 * RC6_ROUNDS + 3]);

        write_word(output, 0, a);
        write_word(output, 1, b);
        write_word(output, 2, c);
        write_word(output, 3, d);
    }

    fn decrypt_block(s: &[u32; SUBKEY_WORDS], input: &[u8], output: &mut [u8]) {
        let mut a = read_word(input, 0);
        let mut b = read_word(input, 1);
        let mut c = read_word(input, 2);
        let mut d = read_word(input, 3);

        c = c.wrapping_sub(s[2 * RC6_ROUNDS + 3]);
        a = a.wrapping_sub(s[2 * RC6_ROUNDS + 2]);

        for i in (1..=RC6_ROUNDS).rev() {
            // (A, B, C, D) <- (D, A, B, C)
            (a, b, c, d) = (d, a, b, c);
            let t = f(b).rotate_left(5);
            let u = f(d).rotate_left(5);
            c = c.wrapping_sub(s[2 * i + 1]).rotate_right(t) ^ u;
            a = a.wrapping_sub(s[2 * i]).rotate_right(u) ^ t;
        }

        d = d.wrapping_sub(s[1]);
        b = b.wrapping_sub(s[0]);

        write_word(output, 0, a);
        write_word(output, 1, b);
        write_word(output, 2, c);
        write_word(output, 3, d);
    }
}

impl Default for Rc6Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockCipher for Rc6Engine {
    type Error = BlockCipherError;

    fn algorithm_name(&self) -> &str {
        "RC6"
    }

    fn block_size(&self) -> usize {
        RC6_BLOCK_BYTES
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let s = self.s.as_ref().ok_or(BlockCipherError::NotInitialised)?;
        if input.len() < RC6_BLOCK_BYTES || output.len() < RC6_BLOCK_BYTES {
            return Err(BlockCipherError::BufferTooShort);
        }
        if self.for_encryption {
            Rc6Engine::encrypt_block(s, input, output);
        } else {
            Rc6Engine::decrypt_block(s, input, output);
        }
        Ok(RC6_BLOCK_BYTES)
    }
}

impl BlockCipherInit for Rc6Engine {
    type Params<'a> = Rc6Params;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.s = Some(setup(params.key()));
        self.for_encryption = direction == CipherDirection::Encrypt;
        Ok(())
    }
}

/// The quadratic mixing function `f(x) = x * (2x + 1)`.
fn f(x: u32) -> u32 {
    x.wrapping_mul(x.wrapping_mul(2).wrapping_add(1))
}

/// Reads little-endian word `index` (each 4 bytes) from a 16-byte block.
fn read_word(input: &[u8], index: usize) -> u32 {
    let off = index * 4;
    u32::from_le_bytes(input[off..off + 4].try_into().unwrap())
}

/// Writes `value` as little-endian word `index` into a 16-byte block.
fn write_word(output: &mut [u8], index: usize, value: u32) {
    let off = index * 4;
    output[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

/// Expands the key into the 44-word RC6 schedule S (RC5's three-phase schedule).
fn setup(key: &[u8]) -> [u32; SUBKEY_WORDS] {
    // Phase 1:以小端序將金鑰填入 c 個字(零填補),至少一個字。
    let c = key.len().div_ceil(4).max(1);
    let mut l = vec![0u32; c];
    for (j, word) in l.iter_mut().enumerate() {
        let start = j * 4;
        let end = (start + 4).min(key.len());
        let mut chunk = [0u8; 4];
        if start < end {
            chunk[..end - start].copy_from_slice(&key[start..end]);
        }
        *word = u32::from_le_bytes(chunk);
    }

    // Phase 2:以 P、Q 的等差級數初始化 S。
    let mut s = [0u32; SUBKEY_WORDS];
    s[0] = P32;
    for i in 1..SUBKEY_WORDS {
        s[i] = s[i - 1].wrapping_add(Q32);
    }

    // Phase 3:以三輪混合將金鑰揉入 S 與 L。
    let iter = 3 * SUBKEY_WORDS.max(c);
    let (mut a, mut b) = (0u32, 0u32);
    let (mut ii, mut jj) = (0usize, 0usize);
    for _ in 0..iter {
        a = s[ii].wrapping_add(a).wrapping_add(b).rotate_left(3);
        s[ii] = a;
        let ab = a.wrapping_add(b);
        b = l[jj].wrapping_add(a).wrapping_add(b).rotate_left(ab);
        l[jj] = b;
        ii = (ii + 1) % SUBKEY_WORDS;
        jj = (jj + 1) % c;
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_and_pre_init_errors() {
        let mut engine = Rc6Engine::new();
        assert_eq!(engine.algorithm_name(), "RC6");
        assert_eq!(engine.block_size(), 16);
        assert_eq!(
            engine.process_block(&[0u8; 16], &mut [0u8; 16]),
            Err(BlockCipherError::NotInitialised)
        );
    }

    #[test]
    fn short_buffers_are_rejected() {
        let params = Rc6Params::new(&[0u8; 16]).unwrap();
        let mut engine = Rc6Engine::new();
        engine.init(CipherDirection::Encrypt, &params).unwrap();
        assert_eq!(
            engine.process_block(&[0u8; 15], &mut [0u8; 16]),
            Err(BlockCipherError::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&[0u8; 16], &mut [0u8; 15]),
            Err(BlockCipherError::BufferTooShort)
        );
    }
}
