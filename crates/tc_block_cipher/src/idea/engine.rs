//! IDEA block-cipher engine and key schedule.

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

use super::{BlockCipherError, IDEA_BLOCK_BYTES, IDEA_KEY_BYTES, IdeaParams};

/// Modular multiplication base, `2^16 + 1` (see [`mul`]).
const BASE: i32 = 0x1_0001;
/// 16-bit mask; IDEA operates on sixteen-bit words throughout.
const MASK: i32 = 0xFFFF;
/// Number of sixteen-bit subkey words (eight rounds of six, plus four for the
/// output transform).
const SUBKEY_WORDS: usize = 52;

/// IDEA with a 128-bit key and 64-bit block.
///
/// The working key is the direction-specific subkey schedule, so
/// [`init`](BlockCipherInit::init) is what actually selects encryption or decryption;
/// [`process_block`](BlockCipher::process_block) then runs the single shared round
/// function.
pub struct IdeaEngine {
    working_key: [u16; SUBKEY_WORDS],
    initialised: bool,
}

impl IdeaEngine {
    /// Creates an uninitialised engine.
    pub fn new() -> Self {
        Self {
            working_key: [0; SUBKEY_WORDS],
            initialised: false,
        }
    }

    /// Transforms one 64-bit block using the current working key.
    fn idea_func(&self, input: &[u8], output: &mut [u8]) {
        let wk = &self.working_key;
        let mut x0 = u16::from_be_bytes([input[0], input[1]]) as i32;
        let mut x1 = u16::from_be_bytes([input[2], input[3]]) as i32;
        let mut x2 = u16::from_be_bytes([input[4], input[5]]) as i32;
        let mut x3 = u16::from_be_bytes([input[6], input[7]]) as i32;

        let mut k = 0;
        for _ in 0..8 {
            x0 = mul(x0, wk[k] as i32);
            k += 1;
            x1 = (x1 + wk[k] as i32) & MASK;
            k += 1;
            x2 = (x2 + wk[k] as i32) & MASK;
            k += 1;
            x3 = mul(x3, wk[k] as i32);
            k += 1;

            let t0 = x1;
            let t1 = x2;
            x2 ^= x0;
            x1 ^= x3;
            x2 = mul(x2, wk[k] as i32);
            k += 1;
            x1 = (x1 + x2) & MASK;
            x1 = mul(x1, wk[k] as i32);
            k += 1;
            x2 = (x2 + x1) & MASK;
            x0 ^= x1;
            x3 ^= x2;
            x1 ^= t1;
            x2 ^= t0;
        }

        let o0 = mul(x0, wk[k] as i32) as u16;
        k += 1;
        let o1 = ((x2 + wk[k] as i32) & MASK) as u16; // NB: x2 before x1
        k += 1;
        let o2 = ((x1 + wk[k] as i32) & MASK) as u16;
        k += 1;
        let o3 = mul(x3, wk[k] as i32) as u16;

        output[0..2].copy_from_slice(&o0.to_be_bytes());
        output[2..4].copy_from_slice(&o1.to_be_bytes());
        output[4..6].copy_from_slice(&o2.to_be_bytes());
        output[6..8].copy_from_slice(&o3.to_be_bytes());
    }
}

impl Default for IdeaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockCipher for IdeaEngine {
    type Error = BlockCipherError;

    fn algorithm_name(&self) -> &str {
        "IDEA"
    }

    fn block_size(&self) -> usize {
        IDEA_BLOCK_BYTES
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockCipherError::NotInitialised);
        }
        if input.len() < IDEA_BLOCK_BYTES || output.len() < IDEA_BLOCK_BYTES {
            return Err(BlockCipherError::BufferTooShort);
        }
        self.idea_func(input, output);
        Ok(IDEA_BLOCK_BYTES)
    }
}

impl BlockCipherInit for IdeaEngine {
    type Params<'a> = IdeaParams;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.working_key =
            generate_working_key(direction == CipherDirection::Encrypt, params.key());
        self.initialised = true;
        Ok(())
    }
}

/// `x * y` modulo `2^16 + 1`, treating a zero operand as `2^16` (IDEA's
/// multiplication in the group of nonzero residues mod 65537).
fn mul(x: i32, y: i32) -> i32 {
    if x == 0 {
        (BASE - y) & MASK
    } else if y == 0 {
        (BASE - x) & MASK
    } else {
        // 65535 * 65535 fits in u32, so the full product is exact here.
        let p = (x as u32).wrapping_mul(y as u32);
        let low = (p & 0xFFFF) as i32;
        let high = (p >> 16) as i32;
        (low - high + i32::from(low < high)) & MASK
    }
}

/// Multiplicative inverse modulo `2^16 + 1` via the extended Euclidean algorithm;
/// zero and one are self-inverse.
fn mul_inv(x: i32) -> i32 {
    if x < 2 {
        return x;
    }

    let mut x = x;
    let mut t0: i32 = 1;
    let mut t1 = BASE / x;
    let mut y = BASE % x;
    while y != 1 {
        let q = x / y;
        x %= y;
        // Bouncy Castle relies on 32-bit wraparound before masking to 16 bits.
        t0 = t0.wrapping_add(t1.wrapping_mul(q)) & MASK;
        if x == 1 {
            return t0;
        }
        let q = y / x;
        y %= x;
        t1 = t1.wrapping_add(t0.wrapping_mul(q)) & MASK;
    }
    (1 - t1) & MASK
}

/// Additive inverse modulo `2^16`.
fn add_inv(x: i32) -> i32 {
    (0 - x) & MASK
}

/// Expands the 128-bit user key into the 52-word encryption subkey by taking the
/// first eight words verbatim, then rotating the previous block left by 25 bits.
fn expand_key(key: &[u8; IDEA_KEY_BYTES]) -> [u16; SUBKEY_WORDS] {
    let mut k = [0u16; SUBKEY_WORDS];
    for i in 0..8 {
        k[i] = u16::from_be_bytes([key[i * 2], key[i * 2 + 1]]);
    }
    for i in 8..SUBKEY_WORDS {
        // 值皆落在 16 位元內,u16 運算等同 bc 的 `& Mask`。
        k[i] = if i & 7 < 6 {
            (k[i - 7] & 127) << 9 | k[i - 6] >> 7
        } else if i & 7 == 6 {
            (k[i - 7] & 127) << 9 | k[i - 14] >> 7
        } else {
            (k[i - 15] & 127) << 9 | k[i - 14] >> 7
        };
    }
    k
}

/// Inverts the encryption subkey into the decryption subkey using the
/// multiplicative and additive inverses, working from the back of the schedule.
fn invert_key(in_key: &[u16; SUBKEY_WORDS]) -> [u16; SUBKEY_WORDS] {
    let mut key = [0u16; SUBKEY_WORDS];
    let mut i = 0; // 讀取游標
    let mut p = SUBKEY_WORDS; // 寫入游標(自尾端往前)

    let mut store = |p: &mut usize, value: i32| {
        *p -= 1;
        key[*p] = value as u16;
    };

    let mut t1 = mul_inv(in_key[i] as i32);
    i += 1;
    let mut t2 = add_inv(in_key[i] as i32);
    i += 1;
    let mut t3 = add_inv(in_key[i] as i32);
    i += 1;
    let mut t4 = mul_inv(in_key[i] as i32);
    i += 1;
    store(&mut p, t4);
    store(&mut p, t3);
    store(&mut p, t2);
    store(&mut p, t1);

    for _round in 1..8 {
        t1 = in_key[i] as i32;
        i += 1;
        t2 = in_key[i] as i32;
        i += 1;
        store(&mut p, t2);
        store(&mut p, t1);

        t1 = mul_inv(in_key[i] as i32);
        i += 1;
        t2 = add_inv(in_key[i] as i32);
        i += 1;
        t3 = add_inv(in_key[i] as i32);
        i += 1;
        t4 = mul_inv(in_key[i] as i32);
        i += 1;
        store(&mut p, t4);
        store(&mut p, t2); // NB: order
        store(&mut p, t3);
        store(&mut p, t1);
    }

    t1 = in_key[i] as i32;
    i += 1;
    t2 = in_key[i] as i32;
    i += 1;
    store(&mut p, t2);
    store(&mut p, t1);

    t1 = mul_inv(in_key[i] as i32);
    i += 1;
    t2 = add_inv(in_key[i] as i32);
    i += 1;
    t3 = add_inv(in_key[i] as i32);
    i += 1;
    t4 = mul_inv(in_key[i] as i32); // 最後一項不遞增
    store(&mut p, t4);
    store(&mut p, t3);
    store(&mut p, t2);
    store(&mut p, t1);

    debug_assert_eq!(p, 0);
    key
}

fn generate_working_key(for_encryption: bool, key: &[u8; IDEA_KEY_BYTES]) -> [u16; SUBKEY_WORDS] {
    let expanded = expand_key(key);
    if for_encryption {
        expanded
    } else {
        invert_key(&expanded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_and_pre_init_errors() {
        let mut engine = IdeaEngine::new();
        assert_eq!(engine.algorithm_name(), "IDEA");
        assert_eq!(engine.block_size(), 8);
        assert_eq!(
            engine.process_block(&[0u8; 8], &mut [0u8; 8]),
            Err(BlockCipherError::NotInitialised)
        );
    }

    #[test]
    fn short_buffers_are_rejected() {
        let params = IdeaParams::new(&[0u8; IDEA_KEY_BYTES]).unwrap();
        let mut engine = IdeaEngine::new();
        engine.init(CipherDirection::Encrypt, &params).unwrap();
        assert_eq!(
            engine.process_block(&[0u8; 7], &mut [0u8; 8]),
            Err(BlockCipherError::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&[0u8; 8], &mut [0u8; 7]),
            Err(BlockCipherError::BufferTooShort)
        );
    }

    #[test]
    fn mul_zero_operand_is_two_to_the_sixteen() {
        // 0 代表 2^16;2^16 * 1 = 2^16 ≡ 2^16 (mod 65537),仍以 0 表示。
        assert_eq!(mul(0, 1), 0);
        // 2^16 * 2^16 = 2^32 ≡ 1 (mod 65537)。
        assert_eq!(mul(0, 0), 1);
    }

    #[test]
    fn mul_inv_round_trips() {
        for x in [2i32, 3, 7, 12345, 65535] {
            assert_eq!(mul(x, mul_inv(x)), 1);
        }
        assert_eq!(mul_inv(0), 0);
        assert_eq!(mul_inv(1), 1);
    }
}
