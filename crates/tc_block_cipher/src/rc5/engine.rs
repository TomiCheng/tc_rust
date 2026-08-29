//! RC5 engine, generic over word size.
//!
//! RC5-32 and RC5-64 are the same algorithm over 32- or 64-bit words. The shared
//! logic lives in [`setup`], [`encrypt_block`], and [`decrypt_block`], generic
//! over the [`Rc5Word`] trait; [`Rc532Engine`] and [`Rc564Engine`] are the two
//! concrete word sizes Bouncy Castle ships.

use alloc::vec;
use alloc::vec::Vec;

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

use super::{BlockCipherError, Rc5Params};

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

/// RC5 over word type `W`; use the [`Rc532Engine`] / [`Rc564Engine`] aliases.
pub struct Rc5Engine<W: Rc5Word> {
    /// 展開金鑰排程 S(長度 2*(rounds+1));init 前為 `None` = 未初始化。
    s: Option<Vec<W>>,
    rounds: usize,
    for_encryption: bool,
}

/// RC5 with 32-bit words and a 64-bit block (`RC5-32`).
pub type Rc532Engine = Rc5Engine<u32>;
/// RC5 with 64-bit words and a 128-bit block (`RC5-64`).
pub type Rc564Engine = Rc5Engine<u64>;

impl<W: Rc5Word> Rc5Engine<W> {
    /// Creates an uninitialised engine.
    pub fn new() -> Self {
        Self {
            s: None,
            rounds: 0,
            for_encryption: false,
        }
    }
}

impl<W: Rc5Word> Default for Rc5Engine<W> {
    fn default() -> Self {
        Self::new()
    }
}

impl<W: Rc5Word> BlockCipher for Rc5Engine<W> {
    type Error = BlockCipherError;

    fn algorithm_name(&self) -> &str {
        W::NAME
    }

    fn block_size(&self) -> usize {
        2 * W::BYTES
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let s = self.s.as_deref().ok_or(BlockCipherError::NotInitialised)?;
        let block = 2 * W::BYTES;
        if input.len() < block || output.len() < block {
            return Err(BlockCipherError::BufferTooShort);
        }
        if self.for_encryption {
            encrypt_block::<W>(s, self.rounds, input, output);
        } else {
            decrypt_block::<W>(s, self.rounds, input, output);
        }
        Ok(block)
    }
}

impl<W: Rc5Word> BlockCipherInit for Rc5Engine<W> {
    type Params<'a> = Rc5Params;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.rounds = params.rounds();
        self.s = Some(setup::<W>(params.key(), params.rounds()));
        self.for_encryption = direction == CipherDirection::Encrypt;
        Ok(())
    }
}

/// Expands the key into the `2 * (rounds + 1)`-word schedule S (RFC 2040).
fn setup<W: Rc5Word>(key: &[u8], rounds: usize) -> Vec<W> {
    // Phase 1:以小端序將金鑰填入 c 個字(零填補),至少一個字。
    let c = key.len().div_ceil(W::BYTES).max(1);
    let mut l = vec![W::ZERO; c];
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
    let t = 2 * (rounds + 1);
    let mut s = vec![W::ZERO; t];
    s[0] = W::P;
    for i in 1..t {
        s[i] = s[i - 1].wrapping_add(W::Q);
    }

    // Phase 3:以三輪混合將金鑰揉入 S 與 L。
    let iter = 3 * t.max(c);
    let (mut a, mut b) = (W::ZERO, W::ZERO);
    let (mut ii, mut jj) = (0usize, 0usize);
    for _ in 0..iter {
        a = s[ii].wrapping_add(a).wrapping_add(b).rotl(3);
        s[ii] = a;
        let ab = a.wrapping_add(b);
        b = l[jj].wrapping_add(a).wrapping_add(b).rotl(ab.rotation());
        l[jj] = b;
        ii = (ii + 1) % t;
        jj = (jj + 1) % c;
    }
    s
}

fn encrypt_block<W: Rc5Word>(s: &[W], rounds: usize, input: &[u8], output: &mut [u8]) {
    let bytes = W::BYTES;
    let mut a = W::read_le(input).wrapping_add(s[0]);
    let mut b = W::read_le(&input[bytes..]).wrapping_add(s[1]);
    for i in 1..=rounds {
        a = a.xor(b).rotl(b.rotation()).wrapping_add(s[2 * i]);
        b = b.xor(a).rotl(a.rotation()).wrapping_add(s[2 * i + 1]);
    }
    a.write_le(output);
    b.write_le(&mut output[bytes..]);
}

fn decrypt_block<W: Rc5Word>(s: &[W], rounds: usize, input: &[u8], output: &mut [u8]) {
    let bytes = W::BYTES;
    let mut a = W::read_le(input);
    let mut b = W::read_le(&input[bytes..]);
    for i in (1..=rounds).rev() {
        b = b.wrapping_sub(s[2 * i + 1]).rotr(a.rotation()).xor(a);
        a = a.wrapping_sub(s[2 * i]).rotr(b.rotation()).xor(b);
    }
    a.wrapping_sub(s[0]).write_le(output);
    b.wrapping_sub(s[1]).write_le(&mut output[bytes..]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_and_pre_init_errors() {
        let mut engine = Rc532Engine::new();
        assert_eq!(engine.algorithm_name(), "RC5-32");
        assert_eq!(engine.block_size(), 8);
        assert_eq!(
            engine.process_block(&[0u8; 8], &mut [0u8; 8]),
            Err(BlockCipherError::NotInitialised)
        );

        let engine = Rc564Engine::new();
        assert_eq!(engine.algorithm_name(), "RC5-64");
        assert_eq!(engine.block_size(), 16);
    }

    #[test]
    fn short_buffers_are_rejected() {
        let params = Rc5Params::new(&[0u8; 8]).unwrap();
        let mut engine = Rc532Engine::new();
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
