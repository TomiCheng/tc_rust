//! RC5 engine, generic over word size.
//!
//! RC5-32 and RC5-64 are the same algorithm over 32- or 64-bit words. The shared
//! logic lives in [`setup`], [`encrypt_block`], and [`decrypt_block`], generic
//! over the [`Rc5Word`] trait; [`Rc532Engine`] and [`Rc564Engine`] are the two
//! concrete word sizes Bouncy Castle ships.

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

use super::{BlockCipherError, RC5_DEFAULT_ROUNDS, RC5_MAX_KEY_BYTES, RC5_MAX_ROUNDS, Rc5Params};

/// Words needed to hold the longest permitted key, so L can live inline.
/// The 32-bit variant needs the most: 255 bytes over four-byte words.
const MAX_KEY_WORDS: usize = RC5_MAX_KEY_BYTES.div_ceil(4);

/// A word size RC5 can operate over (Bouncy Castle ships `u32` and `u64`).
///
/// The `P`/`Q` magic constants and the little-endian word I/O are all that
/// distinguish the two variants; the round structure is identical.
pub trait Rc5Word: Copy + Eq {
    /// Algorithm name reported by the engine.
    const NAME: &'static str;
    /// Word size in bytes; the block is two words.
    const BYTES: usize;
    /// Additive constant `Odd((e - 2) * 2^w)`.
    const P: Self;
    /// Additive constant `Odd((phi - 1) * 2^w)`.
    const Q: Self;
    /// The zero word.
    const ZERO: Self;

    fn wrapping_add(self, rhs: Self) -> Self;
    fn wrapping_sub(self, rhs: Self) -> Self;
    fn xor(self, rhs: Self) -> Self;
    /// Rotate left by `n` (only the low `log2(bits)` bits of `n` matter).
    fn rotl(self, n: u32) -> Self;
    /// Rotate right by `n`.
    fn rotr(self, n: u32) -> Self;
    /// The rotation distance carried by this word (its low 32 bits).
    fn rotation(self) -> u32;
    /// Reads one little-endian word from the front of `bytes`.
    fn read_le(bytes: &[u8]) -> Self;
    /// Writes this word as little-endian bytes into the front of `out`.
    fn write_le(self, out: &mut [u8]);
}

impl Rc5Word for u32 {
    const NAME: &'static str = "RC5-32";
    const BYTES: usize = 4;
    const P: Self = 0xb7e1_5163;
    const Q: Self = 0x9e37_79b9;
    const ZERO: Self = 0;

    fn wrapping_add(self, rhs: Self) -> Self {
        u32::wrapping_add(self, rhs)
    }
    fn wrapping_sub(self, rhs: Self) -> Self {
        u32::wrapping_sub(self, rhs)
    }
    fn xor(self, rhs: Self) -> Self {
        self ^ rhs
    }
    fn rotl(self, n: u32) -> Self {
        self.rotate_left(n)
    }
    fn rotr(self, n: u32) -> Self {
        self.rotate_right(n)
    }
    fn rotation(self) -> u32 {
        self
    }
    fn read_le(bytes: &[u8]) -> Self {
        u32::from_le_bytes(bytes[..4].try_into().unwrap())
    }
    fn write_le(self, out: &mut [u8]) {
        out[..4].copy_from_slice(&self.to_le_bytes());
    }
}

impl Rc5Word for u64 {
    const NAME: &'static str = "RC5-64";
    const BYTES: usize = 8;
    const P: Self = 0xb7e1_5162_8aed_2a6b;
    const Q: Self = 0x9e37_79b9_7f4a_7c15;
    const ZERO: Self = 0;

    fn wrapping_add(self, rhs: Self) -> Self {
        u64::wrapping_add(self, rhs)
    }
    fn wrapping_sub(self, rhs: Self) -> Self {
        u64::wrapping_sub(self, rhs)
    }
    fn xor(self, rhs: Self) -> Self {
        self ^ rhs
    }
    fn rotl(self, n: u32) -> Self {
        self.rotate_left(n)
    }
    fn rotr(self, n: u32) -> Self {
        self.rotate_right(n)
    }
    fn rotation(self) -> u32 {
        self as u32
    }
    fn read_le(bytes: &[u8]) -> Self {
        u64::from_le_bytes(bytes[..8].try_into().unwrap())
    }
    fn write_le(self, out: &mut [u8]) {
        out[..8].copy_from_slice(&self.to_le_bytes());
    }
}

/// RC5 over word type `W` with a compile-time round count; use the
/// [`Rc532Engine`] / [`Rc564Engine`] aliases.
///
/// The expanded key schedule S holds `2 * (ROUNDS + 1)` words. Stable Rust
/// cannot compute that length from `ROUNDS` inside an array type, so it is held
/// as the first pair plus one pair per round — which is also exactly how the
/// round loop consumes it.
pub struct Rc5Engine<W: Rc5Word, const ROUNDS: usize = RC5_DEFAULT_ROUNDS> {
    /// `S[0]` and `S[1]`, applied before the first round.
    first: [W; 2],
    /// `S[2i]` and `S[2i+1]` for each round `i`.
    rest: [[W; 2]; ROUNDS],
    initialised: bool,
    for_encryption: bool,
}

/// RC5 with 32-bit words and a 64-bit block (`RC5-32`).
pub type Rc532Engine<const ROUNDS: usize = RC5_DEFAULT_ROUNDS> = Rc5Engine<u32, ROUNDS>;
/// RC5 with 64-bit words and a 128-bit block (`RC5-64`).
pub type Rc564Engine<const ROUNDS: usize = RC5_DEFAULT_ROUNDS> = Rc5Engine<u64, ROUNDS>;

impl<W: Rc5Word, const ROUNDS: usize> Rc5Engine<W, ROUNDS> {
    /// RFC 2040 caps the round count; the check is now a compile-time one.
    const VALID_ROUNDS: () = assert!(
        ROUNDS <= RC5_MAX_ROUNDS,
        "RC5 ROUNDS must not exceed 255"
    );

    /// Words in the expanded key schedule.
    const SCHEDULE_WORDS: usize = 2 * (ROUNDS + 1);

    /// Creates an uninitialised engine.
    pub fn new() -> Self {
        let () = Self::VALID_ROUNDS;
        Self {
            first: [W::ZERO; 2],
            rest: [[W::ZERO; 2]; ROUNDS],
            initialised: false,
            for_encryption: false,
        }
    }

    /// Reads schedule word `index`, which the key expansion walks cyclically.
    fn schedule_get(&self, index: usize) -> W {
        if index < 2 {
            self.first[index]
        } else {
            self.rest[(index - 2) / 2][(index - 2) % 2]
        }
    }

    /// Writes schedule word `index`.
    fn schedule_set(&mut self, index: usize, value: W) {
        if index < 2 {
            self.first[index] = value;
        } else {
            self.rest[(index - 2) / 2][(index - 2) % 2] = value;
        }
    }

    /// Expands the key into S (RFC 2040's three-phase schedule).
    fn setup(&mut self, key: &[u8]) {
        // Phase 1:以小端序將金鑰填入 c 個字(零填補),至少一個字。金鑰上限
        // 255 bytes，故 L 最多 64 個字，就地存放。
        let c = key.len().div_ceil(W::BYTES).max(1);
        let mut l_buffer = [W::ZERO; MAX_KEY_WORDS];
        let l = &mut l_buffer[..c];
        for (j, word) in l.iter_mut().enumerate() {
            let start = j * W::BYTES;
            let end = (start + W::BYTES).min(key.len());
            let mut chunk = [0u8; 8];
            if start < end {
                chunk[..end - start].copy_from_slice(&key[start..end]);
            }
            *word = W::read_le(&chunk);
        }

        // Phase 2:以 P、Q 的等差級數初始化 S。
        let t = Self::SCHEDULE_WORDS;
        self.schedule_set(0, W::P);
        for i in 1..t {
            let previous = self.schedule_get(i - 1);
            self.schedule_set(i, previous.wrapping_add(W::Q));
        }

        // Phase 3:以三輪混合將金鑰揉入 S 與 L。
        let iter = 3 * t.max(c);
        let (mut a, mut b) = (W::ZERO, W::ZERO);
        let (mut ii, mut jj) = (0usize, 0usize);
        for _ in 0..iter {
            a = self.schedule_get(ii).wrapping_add(a).wrapping_add(b).rotl(3);
            self.schedule_set(ii, a);
            let ab = a.wrapping_add(b);
            b = l[jj].wrapping_add(a).wrapping_add(b).rotl(ab.rotation());
            l[jj] = b;
            ii = (ii + 1) % t;
            jj = (jj + 1) % c;
        }
    }

    fn encrypt_block(&self, input: &[u8], output: &mut [u8]) {
        let bytes = W::BYTES;
        let mut a = W::read_le(input).wrapping_add(self.first[0]);
        let mut b = W::read_le(&input[bytes..]).wrapping_add(self.first[1]);
        for pair in &self.rest {
            a = a.xor(b).rotl(b.rotation()).wrapping_add(pair[0]);
            b = b.xor(a).rotl(a.rotation()).wrapping_add(pair[1]);
        }
        a.write_le(output);
        b.write_le(&mut output[bytes..]);
    }

    fn decrypt_block(&self, input: &[u8], output: &mut [u8]) {
        let bytes = W::BYTES;
        let mut a = W::read_le(input);
        let mut b = W::read_le(&input[bytes..]);
        for pair in self.rest.iter().rev() {
            b = b.wrapping_sub(pair[1]).rotr(a.rotation()).xor(a);
            a = a.wrapping_sub(pair[0]).rotr(b.rotation()).xor(b);
        }
        a.wrapping_sub(self.first[0]).write_le(output);
        b.wrapping_sub(self.first[1]).write_le(&mut output[bytes..]);
    }
}

impl<W: Rc5Word, const ROUNDS: usize> Default for Rc5Engine<W, ROUNDS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<W: Rc5Word, const ROUNDS: usize> BlockCipher for Rc5Engine<W, ROUNDS> {
    type Error = BlockCipherError;

    fn algorithm_name(&self) -> &str {
        W::NAME
    }

    fn block_size(&self) -> usize {
        2 * W::BYTES
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockCipherError::NotInitialised);
        }
        let block = 2 * W::BYTES;
        if input.len() < block || output.len() < block {
            return Err(BlockCipherError::BufferTooShort);
        }
        if self.for_encryption {
            self.encrypt_block(input, output);
        } else {
            self.decrypt_block(input, output);
        }
        Ok(block)
    }
}

impl<W: Rc5Word, const ROUNDS: usize> BlockCipherInit for Rc5Engine<W, ROUNDS> {
    type Params<'a> = Rc5Params;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.setup(params.key());
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
        let mut engine: Rc532Engine = Rc532Engine::new();
        assert_eq!(engine.algorithm_name(), "RC5-32");
        assert_eq!(engine.block_size(), 8);
        assert_eq!(
            engine.process_block(&[0u8; 8], &mut [0u8; 8]),
            Err(BlockCipherError::NotInitialised)
        );

        let engine: Rc564Engine = Rc564Engine::new();
        assert_eq!(engine.algorithm_name(), "RC5-64");
        assert_eq!(engine.block_size(), 16);
    }

    #[test]
    fn short_buffers_are_rejected() {
        let params = Rc5Params::new(&[0u8; 8]).unwrap();
        let mut engine: Rc532Engine = Rc532Engine::new();
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
}
